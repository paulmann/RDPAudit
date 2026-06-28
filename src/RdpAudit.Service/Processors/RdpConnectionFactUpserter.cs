// File:    src/RdpAudit.Service/Processors/RdpConnectionFactUpserter.cs
// Module:  RdpAudit.Service.Processors
// Purpose: Batched merge layer that turns normalised RawEvent rows into idempotent upserts against
//          the RdpConnectionFacts table. One logical upsert per unique connection key per batch.
//          Direct-IP observations are authoritative — they may create new facts and update IP.
//          Derived-IP observations may refresh LastSeenUtc and lifecycle timestamps on an existing
//          fact but are never allowed to create a new fact (avoids cache-misdirected spam).
//          Hostnames never reach the table: the caller is expected to feed only validated IPs.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System.Globalization;
using System.Net;
using Microsoft.EntityFrameworkCore;
using RdpAudit.Core.Data;
using RdpAudit.Core.Models;

namespace RdpAudit.Service.Processors;

/// <summary>Batched merge layer for <see cref="RdpConnectionFact"/> rows.</summary>
public sealed class RdpConnectionFactUpserter
{
	/// <summary>Hard cap on the number of comma-separated event ids retained in
	/// <see cref="RdpConnectionFact.ObservedEventIds"/>. Older ids fall off the front when the
	/// column would otherwise exceed its 256-char budget.</summary>
	internal const int MaxObservedEventIds = 32;

	/// <summary>Maximum width of <see cref="RdpConnectionFact.ObservedEventIds"/> on disk.</summary>
	internal const int ObservedEventIdsMaxLength = 256;

	/// <summary>Maximum number of unique usernames retained in
	/// <see cref="RdpConnectionFact.UserNamesAttempted"/>.</summary>
	internal const int MaxAttemptedUserNames = 32;

	/// <summary>Maximum width of <see cref="RdpConnectionFact.UserNamesAttempted"/>.</summary>
	internal const int UserNamesAttemptedMaxLength = 1024;

	internal const string TsLsmChannel = "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational";
	internal const string TsRcmChannel = "Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational";
	internal const string SecurityChannel = "Security";

	/// <summary>
	/// Sentinel IP used to preserve forensic evidence of a failed logon (Security 4625) when the
	/// payload carried no parseable IP and session correlation could not supply one either. The
	/// row is keyed by the attempted username and grouped under <c>"0.0.0.0"</c> in the
	/// connection-facts table. Consumers must treat this as "unresolved attacker IP" — it is NOT
	/// real traffic from 0.0.0.0. See <see cref="BuildCandidate"/> for the routing rule.
	/// </summary>
	internal const string UnresolvedIpSentinel = "0.0.0.0";

	/// <summary>
	/// Apply a batch of normalised <see cref="RawEvent"/> rows to <paramref name="db"/>. Reads only
	/// the matching existing fact rows (single round-trip), then either updates them in place or
	/// queues a new entity. Caller must commit the surrounding transaction.
	/// </summary>
	public async Task ApplyAsync(
		AuditDbContext db,
		IReadOnlyList<RawEvent> entities,
		CancellationToken ct)
	{
		if (entities.Count == 0)
		{
			return;
		}

		// 1) Build per-event candidates and group by strongest available key. Order each group by
		//    time so lifecycle timestamps are applied in chronological order.
		List<Candidate> candidates = new(entities.Count);
		foreach (RawEvent e in entities)
		{
			Candidate? c = BuildCandidate(e);
			if (c is not null)
			{
				candidates.Add(c.Value);
			}
		}

		if (candidates.Count == 0)
		{
			return;
		}

		Dictionary<string, List<Candidate>> grouped = new(StringComparer.Ordinal);
		foreach (Candidate c in candidates)
		{
			if (!grouped.TryGetValue(c.Key, out List<Candidate>? list))
			{
				list = new List<Candidate>();
				grouped[c.Key] = list;
			}

			list.Add(c);
		}

		foreach (List<Candidate> list in grouped.Values)
		{
			list.Sort(static (a, b) => a.TimeUtc.CompareTo(b.TimeUtc));
		}

		// 2) Fetch existing facts that may match any candidate. Selective on indexed keys.
		HashSet<string> logonIds = new(StringComparer.OrdinalIgnoreCase);
		HashSet<(int Wts, string User)> wtsUserPairs = new();
		foreach (Candidate c in candidates)
		{
			if (!string.IsNullOrWhiteSpace(c.LogonId))
			{
				logonIds.Add(NormalizeLogonId(c.LogonId!));
			}
			else if (c.WtsSessionId is int wts && !string.IsNullOrWhiteSpace(c.UserName))
			{
				wtsUserPairs.Add((wts, c.UserName!.Trim()));
			}
		}

		List<RdpConnectionFact> matches = new();
		if (logonIds.Count > 0)
		{
			List<RdpConnectionFact> rows = await db.RdpConnectionFacts
				.Where(r => r.LogonId != null && logonIds.Contains(r.LogonId))
				.ToListAsync(ct).ConfigureAwait(false);
			matches.AddRange(rows);
		}

		if (wtsUserPairs.Count > 0)
		{
			HashSet<int> wtsIds = new();
			HashSet<string> usernames = new(StringComparer.OrdinalIgnoreCase);
			foreach ((int w, string u) in wtsUserPairs)
			{
				wtsIds.Add(w);
				usernames.Add(u);
			}

			List<RdpConnectionFact> rows = await db.RdpConnectionFacts
				.Where(r => r.WtsSessionId != null
					&& wtsIds.Contains(r.WtsSessionId.Value)
					&& r.UserName != null
					&& usernames.Contains(r.UserName))
				.ToListAsync(ct).ConfigureAwait(false);
			matches.AddRange(rows);
		}

		Dictionary<string, RdpConnectionFact> matchByKey = new(StringComparer.Ordinal);
		foreach (RdpConnectionFact row in matches)
		{
			string? key = BuildKeyFromRow(row);
			if (key is not null && !matchByKey.ContainsKey(key))
			{
				matchByKey[key] = row;
			}
		}

		// 3) Merge per-key candidate chains.
		foreach ((string key, List<Candidate> chain) in grouped)
		{
			RdpConnectionFact? existing = matchByKey.TryGetValue(key, out RdpConnectionFact? found) ? found : null;
			foreach (Candidate c in chain)
			{
				existing = Merge(db, existing, c, key);
			}

			if (existing is not null)
			{
				matchByKey[key] = existing;
			}
		}
	}

	/// <summary>Build a candidate from a single normalised event. Returns null when the event has
	/// no useful key/IP combination for the connection-facts table.</summary>
	internal static Candidate? BuildCandidate(RawEvent e)
	{
		string channel = e.Channel ?? string.Empty;
		EventKind kind = ClassifyEvent(channel, e.EventId, e.LogonType);
		if (kind == EventKind.Unrelated)
		{
			return null;
		}

		bool hasValidIp = !string.IsNullOrWhiteSpace(e.SourceIp) && IsValidIp(e.SourceIp);
		string? logonId = string.IsNullOrWhiteSpace(e.LogonId) ? null : e.LogonId.Trim();
		int? wts = e.SessionId;
		string? user = string.IsNullOrWhiteSpace(e.UserName) ? null : e.UserName.Trim();

		// Sentinel routing: a failed-logon (Security 4625) whose source IP was never parseable
		// AND could not be supplied by session correlation must still be preserved as failed
		// evidence. We route it to the username-keyed sentinel fact row (Ip="0.0.0.0") so the
		// Attack Statistics aggregations see the failure without falsely attributing it to a
		// real address. This treatment is invoked only when SourceIpUnresolved is set by the
		// normalizer and there is an attempted username to anchor the row.
		bool unresolvedSentinel = false;
		string? resolvedIp = hasValidIp ? e.SourceIp!.Trim() : null;
		if (kind == EventKind.FailedLogon
			&& !hasValidIp
			&& e.SourceIpUnresolved
			&& !string.IsNullOrWhiteSpace(user))
		{
			resolvedIp = UnresolvedIpSentinel;
			unresolvedSentinel = true;
		}

		string? key = BuildKey(logonId, wts, user);
		if (key is null)
		{
			return null;
		}

		// For 4625 (failed logon) — record IP-only without WTS context if needed: keyless rows
		// would otherwise pollute the table, so we still require a UserName at minimum (the user
		// the attacker was attempting). 4625 has both UserName and IP, so the key falls through
		// to the U: form.
		return new Candidate(
			Key: key,
			LogonId: logonId,
			WtsSessionId: wts,
			UserName: user,
			Domain: string.IsNullOrWhiteSpace(e.Domain) ? null : e.Domain!.Trim(),
			Ip: resolvedIp,
			IpIsDerived: e.SourceIpDerived,
			IsUnresolvedSentinel: unresolvedSentinel,
			TimeUtc: e.TimeUtc,
			EventId: e.EventId,
			Kind: kind);
	}

	internal static EventKind ClassifyEvent(string channel, int eventId, int? logonType)
	{
		if (IsTsLsm(channel))
		{
			return eventId switch
			{
				21 => EventKind.SessionLogon,           // session logon w/ IP
				22 => EventKind.ShellStart,             // shell start
				23 => EventKind.LogOff,                 // session logoff
				24 => EventKind.Disconnect,             // session disconnected
				25 => EventKind.Reconnect,              // session reconnected
				_ => EventKind.Unrelated,
			};
		}

		if (IsTsRcm(channel))
		{
			return eventId switch
			{
				1149 => EventKind.AuthenticatedConnection, // RD Gateway / NLA auth
				261 => EventKind.PreAuthListener,         // TS-RCM listener accepted a TCP connection pre-auth
				_ => EventKind.Unrelated,
			};
		}

		if (IsSecurity(channel))
		{
			switch (eventId)
			{
				case 4624:
					// Only count remote/RDP-relevant logon types as connection-fact successes.
					// 2=Interactive, 3=Network, 7=Unlock, 10=RemoteInteractive, 11=CachedInteractive.
					// For the RDP-connection-fact lens we accept 2/3/7/10/11 as relevant.
					if (logonType is 2 or 3 or 7 or 10 or 11)
					{
						return EventKind.SuccessfulLogon;
					}

					return EventKind.Unrelated;
				case 4625:
					return EventKind.FailedLogon;
				case 4634:
				case 4647:
					return EventKind.LogOff;
				case 4648:
					return EventKind.ExplicitCreds;
				case 4778:
					return EventKind.Reconnect;
				case 4779:
					return EventKind.Disconnect;
				default:
					return EventKind.Unrelated;
			}
		}

		return EventKind.Unrelated;
	}

	private RdpConnectionFact? Merge(AuditDbContext db, RdpConnectionFact? existing, Candidate c, string key)
	{
		if (existing is null)
		{
			// Direct IP observations may create new facts. Derived-IP and no-IP events should NOT
			// create new rows on their own — otherwise a stale cache could mislead the historical
			// view. They can still update existing facts when one materialises. The unresolved-IP
			// sentinel is an explicit exception: a failed logon with no resolvable IP must still
			// produce a fact row (under "0.0.0.0", keyed by username) so the failure count is
			// preserved for forensic review.
			if (c.Ip is null || (c.IpIsDerived && !c.IsUnresolvedSentinel))
			{
				return null;
			}

			RdpConnectionFact row = new()
			{
				Ip = c.Ip,
				UserName = c.UserName,
				Domain = c.Domain,
				WtsSessionId = c.WtsSessionId,
				LogonId = c.LogonId is null ? null : NormalizeLogonId(c.LogonId),
				FirstSeenUtc = c.TimeUtc,
				LastSeenUtc = c.TimeUtc,
				ObservedEventIds = AppendEventId(null, c.EventId),
				UserNamesAttempted = AppendUserName(null, c.UserName),
				FailedLogons = c.Kind == EventKind.FailedLogon ? 1 : 0,
				SuccessfulLogons = IsSuccessKind(c.Kind) ? 1 : 0,
				IsActive = IsConnectingKind(c.Kind),
			};

			ApplyLifecycle(row, c);
			db.RdpConnectionFacts.Add(row);
			return row;
		}

		// Refresh windowing.
		if (c.TimeUtc > existing.LastSeenUtc)
		{
			existing.LastSeenUtc = c.TimeUtc;
		}

		if (c.TimeUtc < existing.FirstSeenUtc)
		{
			existing.FirstSeenUtc = c.TimeUtc;
		}

		// Update IP only for direct, non-sentinel observations. Never let an unresolved-IP
		// sentinel overwrite a real IP that was already recorded.
		if (c.Ip is not null && !c.IpIsDerived && !c.IsUnresolvedSentinel)
		{
			existing.Ip = c.Ip;
		}

		// Fill in missing scalar fields conservatively.
		if (string.IsNullOrWhiteSpace(existing.Domain) && !string.IsNullOrWhiteSpace(c.Domain))
		{
			existing.Domain = c.Domain;
		}

		if (string.IsNullOrWhiteSpace(existing.UserName) && !string.IsNullOrWhiteSpace(c.UserName))
		{
			existing.UserName = c.UserName;
		}

		if (existing.LogonId is null && c.LogonId is not null)
		{
			existing.LogonId = NormalizeLogonId(c.LogonId);
		}

		if (existing.WtsSessionId is null && c.WtsSessionId is not null)
		{
			existing.WtsSessionId = c.WtsSessionId;
		}

		existing.ObservedEventIds = AppendEventId(existing.ObservedEventIds, c.EventId);
		existing.UserNamesAttempted = AppendUserName(existing.UserNamesAttempted, c.UserName);

		switch (c.Kind)
		{
			case EventKind.FailedLogon:
				existing.FailedLogons++;
				break;
			case EventKind.SuccessfulLogon:
			case EventKind.AuthenticatedConnection:
			case EventKind.SessionLogon:
				// NLA hosts almost never emit Security 4624 for the RDP logon flow, so TS-RCM 1149
				// (AuthenticatedConnection) and TS-LSM 21 (SessionLogon) are the only authoritative
				// proof of a successful RDP session. Count them as successes so the "Attack
				// Statistics" / "RDP Clients" facts stop reporting zero on real workloads.
				existing.SuccessfulLogons++;
				break;
		}

		ApplyLifecycle(existing, c);
		existing.IsActive = ComputeIsActive(existing);
		return existing;
	}

	private static bool IsSuccessKind(EventKind kind) => kind switch
	{
		EventKind.SuccessfulLogon => true,
		EventKind.AuthenticatedConnection => true,
		EventKind.SessionLogon => true,
		_ => false,
	};

	private static void ApplyLifecycle(RdpConnectionFact row, Candidate c)
	{
		switch (c.Kind)
		{
			case EventKind.AuthenticatedConnection:
				if (row.AuthenticatedUtc is null || row.AuthenticatedUtc < c.TimeUtc)
				{
					row.AuthenticatedUtc = c.TimeUtc;
				}

				if (row.ConnectedUtc is null)
				{
					row.ConnectedUtc = c.TimeUtc;
				}

				break;
			case EventKind.SessionLogon:
			case EventKind.ShellStart:
				if (row.ConnectedUtc is null || row.ConnectedUtc > c.TimeUtc)
				{
					row.ConnectedUtc = c.TimeUtc;
				}

				break;
			case EventKind.SuccessfulLogon:
				if (row.AuthenticatedUtc is null || row.AuthenticatedUtc < c.TimeUtc)
				{
					row.AuthenticatedUtc = c.TimeUtc;
				}

				if (row.ConnectedUtc is null)
				{
					row.ConnectedUtc = c.TimeUtc;
				}

				break;
			case EventKind.Disconnect:
				if (row.DisconnectedUtc is null || row.DisconnectedUtc < c.TimeUtc)
				{
					row.DisconnectedUtc = c.TimeUtc;
				}

				break;
			case EventKind.Reconnect:
				if (row.ReconnectedUtc is null || row.ReconnectedUtc < c.TimeUtc)
				{
					row.ReconnectedUtc = c.TimeUtc;
				}

				break;
			case EventKind.LogOff:
				if (row.LoggedOffUtc is null || row.LoggedOffUtc < c.TimeUtc)
				{
					row.LoggedOffUtc = c.TimeUtc;
				}

				break;
		}

		row.IsActive = ComputeIsActive(row);
	}

	private static bool ComputeIsActive(RdpConnectionFact row)
	{
		DateTime? connectMarker = LatestOf(row.ConnectedUtc, row.ReconnectedUtc, row.AuthenticatedUtc);
		DateTime? endMarker = LatestOf(row.DisconnectedUtc, row.LoggedOffUtc);

		if (connectMarker is null)
		{
			return false;
		}

		if (endMarker is null)
		{
			return true;
		}

		return connectMarker > endMarker;
	}

	private static DateTime? LatestOf(params DateTime?[] values)
	{
		DateTime? best = null;
		foreach (DateTime? v in values)
		{
			if (v is null)
			{
				continue;
			}

			if (best is null || v > best)
			{
				best = v;
			}
		}

		return best;
	}

	private static bool IsConnectingKind(EventKind kind) => kind switch
	{
		EventKind.AuthenticatedConnection => true,
		EventKind.SessionLogon => true,
		EventKind.ShellStart => true,
		EventKind.SuccessfulLogon => true,
		EventKind.Reconnect => true,
		_ => false,
	};

	internal static string? BuildKey(string? logonId, int? wtsSessionId, string? userName)
	{
		if (!string.IsNullOrWhiteSpace(logonId))
		{
			return "L:" + NormalizeLogonId(logonId);
		}

		if (wtsSessionId is int sid && !string.IsNullOrWhiteSpace(userName))
		{
			return string.Create(
				CultureInfo.InvariantCulture,
				$"S:{sid}|{userName!.Trim()}");
		}

		if (!string.IsNullOrWhiteSpace(userName))
		{
			return "U:" + userName!.Trim();
		}

		return null;
	}

	internal static string? BuildKeyFromRow(RdpConnectionFact row)
	{
		return BuildKey(row.LogonId, row.WtsSessionId, row.UserName);
	}

	internal static string NormalizeLogonId(string logonId)
	{
		string trimmed = logonId.Trim();
		return trimmed.StartsWith("0x", StringComparison.OrdinalIgnoreCase)
			? trimmed.ToLowerInvariant()
			: trimmed;
	}

	internal static bool IsValidIp(string? candidate)
	{
		if (string.IsNullOrWhiteSpace(candidate))
		{
			return false;
		}

		return IPAddress.TryParse(candidate, out _);
	}

	internal static string AppendEventId(string? current, int eventId)
	{
		if (eventId <= 0)
		{
			return current ?? string.Empty;
		}

		string token = eventId.ToString(CultureInfo.InvariantCulture);
		if (string.IsNullOrEmpty(current))
		{
			return token;
		}

		string[] parts = current.Split(',', StringSplitOptions.RemoveEmptyEntries);
		List<string> kept = new(parts.Length + 1);
		foreach (string part in parts)
		{
			if (!string.Equals(part, token, StringComparison.Ordinal))
			{
				kept.Add(part);
			}
		}

		kept.Add(token);
		while (kept.Count > MaxObservedEventIds)
		{
			kept.RemoveAt(0);
		}

		string joined = string.Join(',', kept);
		while (joined.Length > ObservedEventIdsMaxLength && kept.Count > 1)
		{
			kept.RemoveAt(0);
			joined = string.Join(',', kept);
		}

		return joined;
	}

	internal static string? AppendUserName(string? current, string? userName)
	{
		if (string.IsNullOrWhiteSpace(userName))
		{
			return current;
		}

		string token = userName.Trim();
		if (string.IsNullOrEmpty(current))
		{
			return token.Length <= UserNamesAttemptedMaxLength ? token : token[..UserNamesAttemptedMaxLength];
		}

		string[] parts = current.Split(',', StringSplitOptions.RemoveEmptyEntries);
		List<string> kept = new(parts.Length + 1);
		foreach (string part in parts)
		{
			if (!string.Equals(part, token, StringComparison.OrdinalIgnoreCase))
			{
				kept.Add(part);
			}
		}

		kept.Add(token);
		while (kept.Count > MaxAttemptedUserNames)
		{
			kept.RemoveAt(0);
		}

		string joined = string.Join(',', kept);
		while (joined.Length > UserNamesAttemptedMaxLength && kept.Count > 1)
		{
			kept.RemoveAt(0);
			joined = string.Join(',', kept);
		}

		return joined;
	}

	private static bool IsTsLsm(string channel) => channel.Equals(TsLsmChannel, StringComparison.OrdinalIgnoreCase);

	private static bool IsTsRcm(string channel) => channel.Equals(TsRcmChannel, StringComparison.OrdinalIgnoreCase);

	private static bool IsSecurity(string channel) => channel.Equals(SecurityChannel, StringComparison.OrdinalIgnoreCase);

	/// <summary>Internal classification of an event's lifecycle role for the connection fact.</summary>
	internal enum EventKind
	{
		Unrelated,
		AuthenticatedConnection,
		SessionLogon,
		ShellStart,
		SuccessfulLogon,
		FailedLogon,
		Disconnect,
		Reconnect,
		LogOff,
		/// <summary>
		/// Pre-authentication listener observation (TS-RCM 261). Updates LastSeen/ObservedEventIds
		/// only — does not move any lifecycle timestamp or increment success/failure counters.
		/// </summary>
		PreAuthListener,
		/// <summary>
		/// Explicit-credentials use (Security 4648). Appends the attempted username and updates
		/// LastSeen/ObservedEventIds. NOT counted as a successful logon by itself.
		/// </summary>
		ExplicitCreds,
	}

	/// <summary>Per-event candidate the upserter consumes. Carries only the fields needed to
	/// merge a single observation into the fact table.</summary>
	internal readonly record struct Candidate(
		string Key,
		string? LogonId,
		int? WtsSessionId,
		string? UserName,
		string? Domain,
		string? Ip,
		bool IpIsDerived,
		bool IsUnresolvedSentinel,
		DateTime TimeUtc,
		int EventId,
		EventKind Kind);
}
