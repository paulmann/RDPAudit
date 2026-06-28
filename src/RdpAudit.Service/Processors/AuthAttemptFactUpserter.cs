// File:    src/RdpAudit.Service/Processors/AuthAttemptFactUpserter.cs
// Module:  RdpAudit.Service.Processors
// Purpose: Translates the v3 authentication-outcome events into AuthAttemptFact rows — the
//          atomic source of truth per Detect_Attack_Strategy_v3.md §8.1. Only authoritative
//          outcome-bearing events create rows; RdpCoreTS / TCP / WTS / LSM events MUST NOT.
//          Outcome authority hierarchy (v3 §6.3 rule 3):
//          4624/4625 > 4776/4771 > (1149 + LSM 21) > LSM alone > RdpCoreTS/TCP (never).
//          A 4625 with no IpAddress is still persisted (NeedsCorrelation=true) so the failure
//          counter is preserved even when NLA strips the address.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using Microsoft.EntityFrameworkCore;
using RdpAudit.Core.Data;
using RdpAudit.Core.Events;
using RdpAudit.Core.Models;
using RdpAudit.Core.Util;

namespace RdpAudit.Service.Processors;

/// <summary>Translates outcome-bearing Windows events into <see cref="AuthAttemptFact"/> rows.</summary>
public sealed class AuthAttemptFactUpserter
{
	private const string SecurityChannel = "Security";

	private readonly RdpTransportIpCache _transportIpCache;

	public AuthAttemptFactUpserter(RdpTransportIpCache transportIpCache)
	{
		_transportIpCache = transportIpCache;
	}

	/// <summary>
	/// Apply a batch of normalized events to <paramref name="db"/>, creating one
	/// <see cref="AuthAttemptFact"/> per authoritative outcome event. Returns the number of
	/// failed/succeeded rows created so callers can update telemetry. Caller commits the
	/// surrounding transaction.
	/// </summary>
	public Task<AuthAttemptFactBatchResult> ApplyAsync(
		AuditDbContext db,
		IReadOnlyList<RawEvent> entities,
		CancellationToken ct)
	{
		ArgumentNullException.ThrowIfNull(db);
		ArgumentNullException.ThrowIfNull(entities);
		_ = ct;

		int failedCount = 0;
		int succeededCount = 0;
		DateTime lastUtc = default;
		DateTime nowUtc = DateTime.UtcNow;
		List<AuthAttemptFact> created = new();

		// First pass: seed the transport-IP cache from RdpCoreTS 131/140 and TS-RCM 261 so a 4625
		// in the same batch can find its IP candidate even if both events arrived in the same batch.
		foreach (RawEvent e in entities)
		{
			if (IsTransportIpSource(e))
			{
				_transportIpCache.Record(e.SourceIp, e.TimeUtc, e.EventId);
			}
		}

		foreach (RawEvent e in entities)
		{
			AuthAttemptFact? fact = TryBuildFact(e);
			if (fact is null)
			{
				continue;
			}

			fact.IngestedUtc = nowUtc;
			fact.EvidenceRawEventId = e.Id;
			db.AuthAttemptFacts.Add(fact);
			created.Add(fact);

			switch (fact.Outcome)
			{
				case AuthAttemptOutcome.Failed:
				case AuthAttemptOutcome.Denied:
					failedCount++;
					break;
				case AuthAttemptOutcome.Succeeded:
					succeededCount++;
					break;
			}

			if (e.TimeUtc > lastUtc)
			{
				lastUtc = e.TimeUtc;
			}
		}

		_transportIpCache.Sweep(nowUtc);
		return Task.FromResult(new AuthAttemptFactBatchResult(failedCount, succeededCount, lastUtc, created));
	}

	/// <summary>Build an <see cref="AuthAttemptFact"/> from a single normalized event, or null when
	/// the event is not an authoritative outcome carrier.</summary>
	internal AuthAttemptFact? TryBuildFact(RawEvent e)
	{
		if (!IsAuthoritativeAuthEvent(e))
		{
			return null;
		}

		AuthAttemptOutcome outcome = ClassifyOutcome(e);
		if (outcome == AuthAttemptOutcome.Unknown)
		{
			return null;
		}

		// v1.2.1: re-run normalisation defensively. RawEvent.SourceIp is normally already
		// canonical (PerEventIpResolver runs IpNormalizer), but the AuthAttemptFact rows are
		// the single source of truth that the Attack-Statistics / RDP-Clients aggregates
		// derive from — if a punctuation-wrapped value ever slips through (legacy rows,
		// SessionCorrelationCache seed paths, tests that pre-date the normalizer), we MUST
		// reject it here rather than persist it into the aggregate join key.
		string? ip = IpNormalizer.Normalize(e.SourceIp);
		bool ipFromCorrelation = e.SourceIpDerived;
		string enrichmentSource = e.SourceIpDerived ? "LogonIdChain" : "DirectXml";
		string enrichmentConfidence = e.SourceIpDerived ? "Medium" : (ip is not null ? "High" : "None");
		bool needsCorrelation = false;

		// v3 §6.3 rule 5 — NLA-stripped 4625: try recovery from RdpCoreTS 131/140 cache.
		if (string.IsNullOrWhiteSpace(ip) && (e.EventId == 4625 || e.EventId == 4624) && IsSecurity(e.Channel))
		{
			TransportIpLookup lookup = _transportIpCache.FindCandidate(e.TimeUtc);
			if (lookup.Confidence == TransportIpConfidence.UniqueHighConfidence)
			{
				ip = lookup.Ip;
				ipFromCorrelation = true;
				enrichmentSource = lookup.EvidenceEventId == 131
					? "RdpCoreTs131"
					: lookup.EvidenceEventId == 140 ? "RdpCoreTs140" : "TsRcm261";
				enrichmentConfidence = "High";
			}
			else if (lookup.Confidence == TransportIpConfidence.AmbiguousMediumConfidence)
			{
				ip = lookup.Ip;
				ipFromCorrelation = true;
				enrichmentSource = "RdpCoreTsAmbiguous";
				enrichmentConfidence = "Medium";
				needsCorrelation = true;
			}
			else
			{
				// No transport-IP found; persist the failure regardless so attack counters move.
				needsCorrelation = true;
			}
		}

		string? subStatus = e.EventId == 4625 ? ExtractSubStatus(e) : null;
		string? subStatusMeaning = SubStatusCatalog.Translate(subStatus);
		string? normalizedUser = NormalizeUserName(e.UserName);

		return new AuthAttemptFact
		{
			TimeUtc = e.TimeUtc,
			SourceIp = ip,
			SourcePort = ExtractSourcePort(e),
			TargetUser = e.UserName,
			TargetDomain = e.Domain,
			NormalizedUserName = normalizedUser,
			WorkstationName = ExtractWorkstation(e),
			AuthPackage = e.AuthPackage,
			LogonType = e.LogonType,
			LogonId = e.LogonId,
			Outcome = outcome,
			Status = e.Status,
			SubStatus = subStatus,
			SubStatusMeaning = subStatusMeaning,
			EvidenceChannel = e.Channel,
			EvidenceEventId = e.EventId,
			IpFromCorrelation = ipFromCorrelation,
			EnrichmentSource = enrichmentSource,
			EnrichmentConfidence = enrichmentConfidence,
			NeedsCorrelation = needsCorrelation,
		};
	}

	/// <summary>Outcome authority hierarchy enforcement (v3 §6.3 rule 3).</summary>
	internal static AuthAttemptOutcome ClassifyOutcome(RawEvent e)
	{
		if (!IsSecurity(e.Channel))
		{
			return AuthAttemptOutcome.Unknown;
		}

		return e.EventId switch
		{
			// LSA: most authoritative.
			4624 => AuthAttemptOutcome.Succeeded,
			4625 => AuthAttemptOutcome.Failed,
			// Explicit credential use: success when the OS records the row (no failure variant).
			4648 => AuthAttemptOutcome.Succeeded,
			// Kerberos pre-auth failed (4771) — failure with IpAddress.
			4771 => AuthAttemptOutcome.Failed,
			// NTLM credential validation — Status field encodes success vs failure.
			4776 => IsZeroStatus(e.Status) ? AuthAttemptOutcome.Succeeded : AuthAttemptOutcome.Failed,
			// Kerberos TGT / service ticket — successes.
			4768 => AuthAttemptOutcome.Succeeded,
			4769 => AuthAttemptOutcome.Succeeded,
			// RDP access denied — authorization failure, distinct from credential failure.
			4825 => AuthAttemptOutcome.Denied,
			_ => AuthAttemptOutcome.Unknown,
		};
	}

	internal static bool IsAuthoritativeAuthEvent(RawEvent e)
	{
		if (!IsSecurity(e.Channel))
		{
			return false;
		}

		return e.EventId is 4624 or 4625 or 4648 or 4768 or 4769 or 4771 or 4776 or 4825;
	}

	internal static bool IsTransportIpSource(RawEvent e)
	{
		const string RdpCoreTs = "Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational";
		const string TsRcm = "Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational";

		if (string.IsNullOrWhiteSpace(e.SourceIp))
		{
			return false;
		}

		if (string.Equals(e.Channel, RdpCoreTs, StringComparison.OrdinalIgnoreCase))
		{
			return e.EventId == 131 || e.EventId == 140;
		}

		if (string.Equals(e.Channel, TsRcm, StringComparison.OrdinalIgnoreCase))
		{
			return e.EventId == 261;
		}

		return false;
	}

	internal static string? NormalizeUserName(string? userName)
	{
		if (string.IsNullOrWhiteSpace(userName))
		{
			return null;
		}

		string trimmed = userName.Trim();
		int slash = trimmed.IndexOf('\\', StringComparison.Ordinal);
		string bareUser = slash >= 0 ? trimmed[(slash + 1)..] : trimmed;
		int at = bareUser.IndexOf('@', StringComparison.Ordinal);
		if (at > 0)
		{
			bareUser = bareUser[..at];
		}

		return bareUser.ToLowerInvariant();
	}

	private static bool IsSecurity(string? channel)
	{
		return !string.IsNullOrWhiteSpace(channel)
			&& channel.Equals(SecurityChannel, StringComparison.OrdinalIgnoreCase);
	}

	private static bool IsZeroStatus(string? status)
	{
		// NtStatusFormatter handles hex (0x0 / 0x00000000), signed decimal (0 / -0), and unsigned
		// decimal (0). Blank / null is treated as "no failure indicator" — equivalent to a zero
		// status — so 4776 events without an explicit Status field are classified as Succeeded
		// (matches Windows semantics: present-but-zero == success).
		return NtStatusFormatter.IsZero(status);
	}

	/// <summary>Extract the SubStatus field from the normalized Details JSON if EventNormalizer
	/// captured it there. EventNormalizer surfaces every EventData/Data child into the JSON map
	/// and canonicalizes NTSTATUS-bearing fields to <c>0xXXXXXXXX</c>; we re-canonicalize here as
	/// a defensive belt-and-braces against pre-Stage-3 rows whose Details still carry the raw
	/// signed-decimal form Windows wrote.</summary>
	private static string? ExtractSubStatus(RawEvent e)
	{
		string? raw = ExtractDetailsField(e.Details, "SubStatus");
		return raw is null ? null : NtStatusFormatter.Canonicalize(raw);
	}

	private static int? ExtractSourcePort(RawEvent e)
	{
		string? raw = ExtractDetailsField(e.Details, "IpPort");
		if (raw is null)
		{
			return null;
		}

		return int.TryParse(raw, System.Globalization.CultureInfo.InvariantCulture, out int port)
			? port
			: null;
	}

	private static string? ExtractWorkstation(RawEvent e)
	{
		return ExtractDetailsField(e.Details, "WorkstationName")
			?? ExtractDetailsField(e.Details, "Workstation");
	}

	private static string? ExtractDetailsField(string? detailsJson, string key)
	{
		if (string.IsNullOrWhiteSpace(detailsJson))
		{
			return null;
		}

		try
		{
			using System.Text.Json.JsonDocument doc = System.Text.Json.JsonDocument.Parse(detailsJson);
			if (doc.RootElement.ValueKind != System.Text.Json.JsonValueKind.Object)
			{
				return null;
			}

			foreach (System.Text.Json.JsonProperty prop in doc.RootElement.EnumerateObject())
			{
				if (string.Equals(prop.Name, key, StringComparison.OrdinalIgnoreCase)
					&& prop.Value.ValueKind == System.Text.Json.JsonValueKind.String)
				{
					string? value = prop.Value.GetString();
					return string.IsNullOrWhiteSpace(value) ? null : value;
				}
			}
		}
		catch (System.Text.Json.JsonException)
		{
			// Malformed details JSON should not stall the pipeline.
		}

		return null;
	}
}

/// <summary>Summary of a single <see cref="AuthAttemptFactUpserter.ApplyAsync"/> batch.</summary>
/// <param name="FailedCreated">Number of failed/denied facts created.</param>
/// <param name="SucceededCreated">Number of succeeded facts created.</param>
/// <param name="LastFactUtc">Timestamp of the most recent created fact, or <c>default</c> when none.</param>
/// <param name="Facts">The created entities (for downstream visibility / tests).</param>
public sealed record AuthAttemptFactBatchResult(
	int FailedCreated,
	int SucceededCreated,
	DateTime LastFactUtc,
	IReadOnlyList<AuthAttemptFact> Facts);
