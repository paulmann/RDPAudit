/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 2.1.2
// File   : AuthAttemptFactUpserter.cs
// Project: RdpAudit.Service (RdpAudit.Service.Processors)
// Purpose: Translates v3 authentication-outcome events into AuthAttemptFact rows — the atomic
//          source of truth per Detect_Attack_Strategy_v3.md §8.1. Only authoritative
//          outcome-bearing Security events create rows; RdpCoreTS / TCP / WTS / LSM events
//          MUST NOT. Outcome authority hierarchy (v3 §6.3 rule 3):
//          4624/4625 > 4776/4771 > (1149 + LSM 21) > LSM alone > RdpCoreTS/TCP (never).
//          A 4625 with no IpAddress is still persisted (NeedsCorrelation=true) so the failure
//          counter is preserved even when NLA strips the address.
//          v2.1.0: honors CancellationToken in the batch loop and adds DEBUG-mode structured
//          tracing for every rejected event and every transport-IP correlation outcome.
//          v2.1.2: logger/options restored as OPTIONAL constructor parameters. Existing unit
//          tests (AuthAttemptFactUpserterTests.cs, Security4625RealHostIngestionTests.cs)
//          construct this type directly as `new AuthAttemptFactUpserter(transportIpCache)` with
//          no logger/options — making them mandatory broke 8+ call sites with CS7036. Production
//          DI still resolves and injects real ILogger/IOptionsMonitor instances; tests get a
//          fully functional upserter with diagnostics silently disabled (DebugEnabled=false).
// Depends: AuditDbContext, RawEvent, AuthAttemptFact, RdpTransportIpCache,
//          ILogger<AuthAttemptFactUpserter>?, IOptionsMonitor<RdpAuditOptions>?
// Extends: Add a new case to IsAuthoritativeAuthEvent + ClassifyOutcome when a new Security
//          event id becomes an authoritative outcome carrier; keep both switches in sync.

using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using RdpAudit.Core.Config;
using RdpAudit.Core.Data;
using RdpAudit.Core.Events;
using RdpAudit.Core.Models;
using RdpAudit.Core.Util;

namespace RdpAudit.Service.Processors;

/// <summary>Translates outcome-bearing Windows Security events into <see cref="AuthAttemptFact"/>
/// rows — the single atomic source of truth consumed by Attack Statistics and RDP Activity
/// aggregates.</summary>
public sealed class AuthAttemptFactUpserter
{
	// ── Fields & DI ──────────────────────────────────────────────────────────────

	private const string SecurityChannel = "Security";

	private readonly RdpTransportIpCache _transportIpCache;
	private readonly ILogger<AuthAttemptFactUpserter>? _logger;
	private readonly IOptionsMonitor<RdpAuditOptions>? _options;

	// ── Construction ─────────────────────────────────────────────────────────────

	/// <summary>
	/// <paramref name="logger"/> and <paramref name="options"/> are optional: production DI
	/// always supplies real instances, enabling DEBUG-mode structured tracing; unit tests may
	/// construct this type with only <paramref name="transportIpCache"/>, in which case all
	/// diagnostic logging is a no-op via the null-conditional operator.
	/// </summary>
	public AuthAttemptFactUpserter(
		RdpTransportIpCache transportIpCache,
		ILogger<AuthAttemptFactUpserter>? logger = null,
		IOptionsMonitor<RdpAuditOptions>? options = null)
	{
		ArgumentNullException.ThrowIfNull(transportIpCache);

		_transportIpCache = transportIpCache;
		_logger = logger;
		_options = options;
	}

	private bool DebugEnabled => _options?.CurrentValue.Diagnostics.DebugMode == true;

	// ── Public API ───────────────────────────────────────────────────────────────

	/// <summary>
	/// Apply a batch of normalized events to <see cref="AuditDbContext.AuthAttemptFacts"/>,
	/// creating one row per authoritative outcome event. Returns the number of failed/succeeded
	/// rows created so callers can update telemetry. Caller commits the surrounding transaction.
	/// </summary>
	public Task<AuthAttemptFactBatchResult> ApplyAsync(
		AuditDbContext db,
		IReadOnlyList<RawEvent> entities,
		CancellationToken ct)
	{
		ArgumentNullException.ThrowIfNull(db);
		ArgumentNullException.ThrowIfNull(entities);

		bool debugEnabled = DebugEnabled;

		if (entities.Count == 0)
		{
			return Task.FromResult(new AuthAttemptFactBatchResult(0, 0, default, Array.Empty<AuthAttemptFact>()));
		}

		int failedCount = 0;
		int succeededCount = 0;
		int notAuthoritative = 0;
		int unknownOutcome = 0;
		int needsCorrelationCount = 0;
		DateTime lastUtc = default;
		DateTime nowUtc = DateTime.UtcNow;
		List<AuthAttemptFact> created = new();

		// First pass: seed the transport-IP cache from RdpCoreTS 131/140 and TS-RCM 261 so a
		// 4625 in the same batch can find its IP candidate even if both events arrived together.
		foreach (RawEvent e in entities)
		{
			ct.ThrowIfCancellationRequested();

			if (IsTransportIpSource(e))
			{
				_transportIpCache.Record(e.SourceIp!, e.TimeUtc, e.EventId);

				if (debugEnabled)
				{
					_logger?.LogDebug(
						"AuthAttemptFactUpserter TRANSPORT-IP SEED: EventId={EventId} Channel={Channel} Ip={Ip} TimeUtc={TimeUtc}",
						e.EventId, e.Channel, e.SourceIp, e.TimeUtc);
				}
			}
		}

		foreach (RawEvent e in entities)
		{
			ct.ThrowIfCancellationRequested();

			if (!IsAuthoritativeAuthEvent(e))
			{
				notAuthoritative++;

				if (debugEnabled && IsSecurity(e.Channel))
				{
					// Only trace Security-channel misses; TS-RCM/TS-LSM/RdpCoreTS events are
					// expected to never produce an AuthAttemptFact and would flood the log.
					_logger?.LogDebug(
						"AuthAttemptFactUpserter DROP: EventId={EventId} Channel={Channel} is on the Security channel but is not in the authoritative outcome carrier list (4624/4625/4648/4768/4769/4771/4776/4825). No AuthAttemptFact row created.",
						e.EventId, e.Channel);
				}

				continue;
			}

			AuthAttemptFact? fact = TryBuildFact(e, debugEnabled);
			if (fact is null)
			{
				unknownOutcome++;

				if (debugEnabled)
				{
					_logger?.LogDebug(
						"AuthAttemptFactUpserter DROP: EventId={EventId} Channel={Channel} is authoritative but ClassifyOutcome returned Unknown — check that ClassifyOutcome and IsAuthoritativeAuthEvent stay in sync.",
						e.EventId, e.Channel);
				}

				continue;
			}

			fact.IngestedUtc = nowUtc;
			fact.EvidenceRawEventId = e.Id;
			db.AuthAttemptFacts.Add(fact);
			created.Add(fact);

			if (fact.NeedsCorrelation)
			{
				needsCorrelationCount++;
			}

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

		if (debugEnabled)
		{
			_logger?.LogDebug(
				"AuthAttemptFactUpserter.ApplyAsync BATCH SUMMARY: total={Total} createdFacts={Created} (failed={Failed}, succeeded={Succeeded}) notAuthoritative={NotAuthoritative} unknownOutcome={UnknownOutcome} needsCorrelation={NeedsCorrelation}",
				entities.Count, created.Count, failedCount, succeededCount, notAuthoritative, unknownOutcome, needsCorrelationCount);
		}

		return Task.FromResult(new AuthAttemptFactBatchResult(failedCount, succeededCount, lastUtc, created));
	}

	// ── Core Logic ───────────────────────────────────────────────────────────────

	/// <summary>Build an <see cref="AuthAttemptFact"/> from a single normalized event, or null
	/// when the event is not an authoritative outcome carrier.</summary>
	internal AuthAttemptFact? TryBuildFact(RawEvent e) => TryBuildFact(e, DebugEnabled);

	private AuthAttemptFact? TryBuildFact(RawEvent e, bool debugEnabled)
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
		// canonical (PerEventIpResolver runs IpNormalizer), but AuthAttemptFact rows are the
		// single source of truth that Attack-Statistics / RDP-Clients aggregates derive from —
		// reject a punctuation-wrapped value here rather than persist it into the join key.
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
					: lookup.EvidenceEventId == 140
						? "RdpCoreTs140"
						: "TsRcm261";
				enrichmentConfidence = "High";

				if (debugEnabled)
				{
					_logger?.LogDebug(
						"AuthAttemptFactUpserter TRANSPORT-IP MATCH: EventId={EventId} at {TimeUtc} resolved to Ip={Ip} via {Source} (UniqueHighConfidence)",
						e.EventId, e.TimeUtc, ip, enrichmentSource);
				}
			}
			else if (lookup.Confidence == TransportIpConfidence.AmbiguousMediumConfidence)
			{
				ip = lookup.Ip;
				ipFromCorrelation = true;
				enrichmentSource = "RdpCoreTsAmbiguous";
				enrichmentConfidence = "Medium";
				needsCorrelation = true;

				if (debugEnabled)
				{
					_logger?.LogDebug(
						"AuthAttemptFactUpserter TRANSPORT-IP AMBIGUOUS: EventId={EventId} at {TimeUtc} matched Ip={Ip} with AmbiguousMediumConfidence — multiple transport candidates in window, flagged NeedsCorrelation=true",
						e.EventId, e.TimeUtc, ip);
				}
			}
			else
			{
				// No transport-IP found; persist the failure regardless so attack counters move.
				needsCorrelation = true;

				if (debugEnabled)
				{
					_logger?.LogDebug(
						"AuthAttemptFactUpserter TRANSPORT-IP MISS: EventId={EventId} at {TimeUtc} has no direct IP and RdpTransportIpCache found no candidate within the correlation window. Fact will be persisted with SourceIp=null and NeedsCorrelation=true — verify TS-RCM 261 / RdpCoreTS 131 watchers are armed and forwarding events for this time window.",
						e.EventId, e.TimeUtc);
				}
			}
		}

		string? subStatus = e.EventId == 4625 ? ExtractSubStatus(e) : null;
		string? subStatusMeaning = SubStatusCatalog.Translate(subStatus);
		string? normalizedUser = NormalizeUserName(e.UserName);

		AuthAttemptFact fact = new()
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

		if (debugEnabled)
		{
			_logger?.LogDebug(
				"AuthAttemptFactUpserter BUILD: EventId={EventId} Outcome={Outcome} Ip={Ip} IpFromCorrelation={IpFromCorrelation} EnrichmentSource={EnrichmentSource} EnrichmentConfidence={EnrichmentConfidence} NeedsCorrelation={NeedsCorrelation} User={User}",
				e.EventId, outcome, ip, ipFromCorrelation, enrichmentSource, enrichmentConfidence, needsCorrelation, normalizedUser);
		}

		return fact;
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
			4624 => AuthAttemptOutcome.Succeeded,
			4625 => AuthAttemptOutcome.Failed,
			4648 => AuthAttemptOutcome.Succeeded,
			4771 => AuthAttemptOutcome.Failed,
			4776 => IsZeroStatus(e.Status) ? AuthAttemptOutcome.Succeeded : AuthAttemptOutcome.Failed,
			4768 => AuthAttemptOutcome.Succeeded,
			4769 => AuthAttemptOutcome.Succeeded,
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
		=> !string.IsNullOrWhiteSpace(channel)
			&& channel.Equals(SecurityChannel, StringComparison.OrdinalIgnoreCase);

	private static bool IsZeroStatus(string? status)
	{
		// Blank/null is treated as "no failure indicator" — equivalent to a zero status — so
		// 4776 events without an explicit Status field are classified as Succeeded (matches
		// Windows semantics: present-but-zero == success).
		return NtStatusFormatter.IsZero(status);
	}

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

/// <summary>Summary of a single batch.</summary>
/// <param name="FailedCreated">Number of failed/denied facts created.</param>
/// <param name="SucceededCreated">Number of succeeded facts created.</param>
/// <param name="LastFactUtc">Timestamp of the most recent created fact, or default when none.</param>
/// <param name="Facts">The created entities (for downstream visibility / tests).</param>
public sealed record AuthAttemptFactBatchResult(
	int FailedCreated,
	int SucceededCreated,
	DateTime LastFactUtc,
	IReadOnlyList<AuthAttemptFact> Facts);
