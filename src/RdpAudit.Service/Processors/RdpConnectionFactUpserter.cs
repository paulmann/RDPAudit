/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 2.1.2
// File   : RdpConnectionFactUpserter.cs
// Project: RdpAudit.Service (RdpAudit.Service.Processors)
// Purpose: Batched merge layer that turns normalised RawEvent rows into idempotent upserts
//          against RdpConnectionFacts.
//          v2.1.0: strong-key events (LogonId, or WtsSessionId+UserName) now always create a
//          fact row even without a direct IP yet — the previous rule required a direct/sentinel
//          IP to seed ANY new row, silently discarding identity-first events and leaving RDP
//          Activity empty even with a healthy Live Events feed. IP is backfilled by a later
//          observation in the same logon chain instead.
//          v2.1.0: added DEBUG-mode structured tracing at every rejection/merge decision point.
//          v2.1.1: fixed CS8601 — RdpConnectionFact.Ip is a non-nullable string whose "no IP
//          yet" sentinel is string.Empty (never null); all IP presence checks use
//          string.IsNullOrEmpty(...) instead of null comparisons, and assignments use
//          `?? string.Empty` / a guarded `!`.
//          v2.1.2: logger/options restored as OPTIONAL constructor parameters. Existing unit
//          tests (RdpConnectionFactUpserterTests.cs, EventNormalizerStageIpDTests.cs) construct
//          this type as `new RdpConnectionFactUpserter()` with no arguments — making the
//          diagnostics dependencies mandatory broke 20+ call sites with CS7036. Production DI
//          still resolves and injects real ILogger/IOptionsMonitor instances; tests get a fully
//          functional upserter with diagnostics silently disabled (DebugEnabled=false).
// Depends: AuditDbContext, RawEvent, RdpConnectionFact, ILogger<RdpConnectionFactUpserter>?,
//          IOptionsMonitor<RdpAuditOptions>?
// Extends: Add a new EventKind branch + ClassifyEvent case when a new channel/event needs to
//          participate in connection-fact lifecycle tracking; update KeyStrength rules if a new
//          identity field becomes available.

using System.Globalization;
using System.Net;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using RdpAudit.Core.Config;
using RdpAudit.Core.Data;
using RdpAudit.Core.Models;

namespace RdpAudit.Service.Processors;

/// <summary>
/// Batched merge layer that folds a batch of normalised <see cref="RawEvent"/> rows into
/// idempotent upserts against <see cref="RdpConnectionFact"/>. A candidate with a strong
/// identity key (LogonId, or WtsSessionId+UserName) is always materialised into a fact row —
/// IP presence only controls whether the IP column is populated immediately or backfilled by a
/// later observation in the same logon chain. A weak key (username-only) still requires a
/// direct or sentinel IP to avoid seeding unanchored noise rows. Note:
/// <see cref="RdpConnectionFact.Ip"/> is a non-nullable string whose "no IP yet" sentinel value
/// is <see cref="string.Empty"/> — never null.
/// </summary>
public sealed class RdpConnectionFactUpserter
{
	// ── Fields & DI ──────────────────────────────────────────────────────────────

	internal const int MaxObservedEventIds = 32;
	internal const int ObservedEventIdsMaxLength = 256;
	internal const int MaxAttemptedUserNames = 32;
	internal const int UserNamesAttemptedMaxLength = 1024;

	internal const string TsLsmChannel = "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational";
	internal const string TsRcmChannel = "Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational";
	internal const string SecurityChannel = "Security";

	/// <summary>
	/// Sentinel IP used to preserve forensic evidence of a failed logon (Security 4625) when the
	/// payload carried no parseable IP and session correlation could not supply one either.
	/// </summary>
	internal const string UnresolvedIpSentinel = "0.0.0.0";

	private readonly ILogger<RdpConnectionFactUpserter>? _logger;
	private readonly IOptionsMonitor<RdpAuditOptions>? _options;

	// ── Construction ─────────────────────────────────────────────────────────────

	/// <summary>
	/// <paramref name="logger"/> and <paramref name="options"/> are optional: production DI
	/// always supplies real instances, enabling DEBUG-mode structured tracing; unit tests may
	/// construct this type with the parameterless form, in which case all diagnostic logging is
	/// a no-op via the null-conditional operator.
	/// </summary>
	public RdpConnectionFactUpserter(
		ILogger<RdpConnectionFactUpserter>? logger = null,
		IOptionsMonitor<RdpAuditOptions>? options = null)
	{
		_logger = logger;
		_options = options;
	}

	private bool DebugEnabled => _options?.CurrentValue.Diagnostics.DebugMode == true;

	// ── Public API ───────────────────────────────────────────────────────────────

	public async Task ApplyAsync(AuditDbContext db, IReadOnlyList<RawEvent> entities, CancellationToken ct)
	{
		ArgumentNullException.ThrowIfNull(db);
		ArgumentNullException.ThrowIfNull(entities);

		if (entities.Count == 0)
		{
			return;
		}

		bool debugEnabled = DebugEnabled;

		List<Candidate> candidates = new(entities.Count);
		int rejected = 0;

		foreach (RawEvent e in entities)
		{
			ct.ThrowIfCancellationRequested();

			Candidate? c = BuildCandidate(e);
			if (c is null)
			{
				rejected++;
				if (debugEnabled)
				{
					LogRejectedCandidate(e);
				}

				continue;
			}

			candidates.Add(c.Value);
		}

		if (debugEnabled)
		{
			_logger?.LogDebug(
				"RdpConnectionFactUpserter.ApplyAsync: {Total} events in batch, {Candidates} produced a candidate, {Rejected} were rejected before keying",
				entities.Count, candidates.Count, rejected);
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

		ct.ThrowIfCancellationRequested();

		List<RdpConnectionFact> matches = new();

		if (logonIds.Count > 0)
		{
			List<RdpConnectionFact> rows = await db.RdpConnectionFacts
				.Where(r => r.LogonId != null && logonIds.Contains(r.LogonId))
				.ToListAsync(ct)
				.ConfigureAwait(false);
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
				.Where(r =>
					r.WtsSessionId != null &&
					wtsIds.Contains(r.WtsSessionId.Value) &&
					r.UserName != null &&
					usernames.Contains(r.UserName))
				.ToListAsync(ct)
				.ConfigureAwait(false);
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

		int created = 0;
		int updated = 0;
		int droppedOnMerge = 0;

		foreach ((string key, List<Candidate> chain) in grouped)
		{
			RdpConnectionFact? existing = matchByKey.TryGetValue(key, out RdpConnectionFact? found)
				? found
				: null;

			bool existedBeforeChain = existing is not null;

			foreach (Candidate c in chain)
			{
				bool wasNull = existing is null;
				existing = Merge(db, existing, c, key, debugEnabled);

				if (existing is null)
				{
					droppedOnMerge++;
				}
				else if (wasNull)
				{
					created++;
				}
			}

			if (existing is not null)
			{
				matchByKey[key] = existing;
				if (existedBeforeChain)
				{
					updated++;
				}
			}
		}

		if (debugEnabled)
		{
			_logger?.LogDebug(
				"RdpConnectionFactUpserter.ApplyAsync: {Groups} identity groups processed — {Created} new facts created, {Updated} existing facts touched, {DroppedOnMerge} candidate applications skipped by Merge",
				grouped.Count, created, updated, droppedOnMerge);
		}
	}

	// ── Core Logic ───────────────────────────────────────────────────────────────

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

		bool unresolvedSentinel = false;
		string? resolvedIp = hasValidIp ? e.SourceIp!.Trim() : null;

		if (kind == EventKind.FailedLogon && !hasValidIp && e.SourceIpUnresolved && !string.IsNullOrWhiteSpace(user))
		{
			resolvedIp = UnresolvedIpSentinel;
			unresolvedSentinel = true;
		}

		string? key = BuildKey(logonId, wts, user);
		if (key is null)
		{
			return null;
		}

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
				21 => EventKind.SessionLogon,
				22 => EventKind.ShellStart,
				23 => EventKind.LogOff,
				24 => EventKind.Disconnect,
				25 => EventKind.Reconnect,
				_ => EventKind.Unrelated,
			};
		}

		if (IsTsRcm(channel))
		{
			return eventId switch
			{
				1149 => EventKind.AuthenticatedConnection,
				261 => EventKind.PreAuthListener,
				_ => EventKind.Unrelated,
			};
		}

		if (IsSecurity(channel))
		{
			switch (eventId)
			{
				case 4624:
					return logonType is 2 or 3 or 7 or 10 or 11
						? EventKind.SuccessfulLogon
						: EventKind.Unrelated;
				case 4625:
					return EventKind.FailedLogon;
				case 4634:
				case 4647:
					return EventKind.LogOff;
				case 4648:
					return EventKind.ExplicitCreds;
				case 4672:
					// Special Logon — deliberately excluded: fires for SYSTEM/service logons
					// unrelated to an RDP session and would pollute Activity with non-RDP rows.
					return EventKind.Unrelated;
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

	private RdpConnectionFact? Merge(
		AuditDbContext db,
		RdpConnectionFact? existing,
		Candidate c,
		string key,
		bool debugEnabled)
	{
		bool candidateHasIp = !string.IsNullOrEmpty(c.Ip);

		if (existing is null)
		{
			KeyStrength strength = ClassifyKeyStrength(key);
			bool hasAnchorIp = candidateHasIp && (!c.IpIsDerived || c.IsUnresolvedSentinel);

			bool canCreate = strength == KeyStrength.Strong || hasAnchorIp;

			if (!canCreate)
			{
				if (debugEnabled)
				{
					_logger?.LogDebug(
						"RdpConnectionFactUpserter Merge DROP: Key={Key} EventId={EventId} Kind={Kind} KeyStrength={Strength} — cannot seed a new fact: weak key requires a direct/sentinel IP but Ip={Ip} IpIsDerived={IpIsDerived}",
						key, c.EventId, c.Kind, strength, c.Ip, c.IpIsDerived);
				}

				return null;
			}

			RdpConnectionFact row = new()
			{
				Ip = c.Ip ?? string.Empty,
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

			if (debugEnabled)
			{
				_logger?.LogDebug(
					"RdpConnectionFactUpserter Merge CREATE: Key={Key} EventId={EventId} Kind={Kind} Ip={Ip} IpIsDerived={IpIsDerived} LogonId={LogonId} WtsSessionId={WtsSessionId} UserName={UserName}",
					key, c.EventId, c.Kind, row.Ip, c.IpIsDerived, c.LogonId, c.WtsSessionId, c.UserName);
			}

			return row;
		}

		if (c.TimeUtc > existing.LastSeenUtc)
		{
			existing.LastSeenUtc = c.TimeUtc;
		}

		if (c.TimeUtc < existing.FirstSeenUtc)
		{
			existing.FirstSeenUtc = c.TimeUtc;
		}

		bool existingHasIp = !string.IsNullOrEmpty(existing.Ip);

		if (candidateHasIp && !c.IpIsDerived && !c.IsUnresolvedSentinel)
		{
			existing.Ip = c.Ip!;
		}
		else if (!existingHasIp && candidateHasIp)
		{
			existing.Ip = c.Ip!;
		}

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
				existing.SuccessfulLogons++;
				break;
		}

		ApplyLifecycle(existing, c);
		existing.IsActive = ComputeIsActive(existing);

		if (debugEnabled)
		{
			_logger?.LogDebug(
				"RdpConnectionFactUpserter Merge UPDATE: Key={Key} EventId={EventId} Kind={Kind} Ip={Ip} IsActive={IsActive} SuccessfulLogons={SuccessfulLogons} FailedLogons={FailedLogons}",
				key, c.EventId, c.Kind, existing.Ip, existing.IsActive, existing.SuccessfulLogons, existing.FailedLogons);
		}

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

				row.ConnectedUtc ??= c.TimeUtc;
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

				row.ConnectedUtc ??= c.TimeUtc;
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
			return string.Create(CultureInfo.InvariantCulture, $"S:{sid}|{userName!.Trim()}");
		}

		if (!string.IsNullOrWhiteSpace(userName))
		{
			return "U:" + userName!.Trim();
		}

		return null;
	}

	internal static string? BuildKeyFromRow(RdpConnectionFact row)
		=> BuildKey(row.LogonId, row.WtsSessionId, row.UserName);

	private static KeyStrength ClassifyKeyStrength(string key)
		=> key.StartsWith("L:", StringComparison.Ordinal) || key.StartsWith("S:", StringComparison.Ordinal)
			? KeyStrength.Strong
			: KeyStrength.Weak;

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

	// ── Error Handling & Retry ───────────────────────────────────────────────────

	private void LogRejectedCandidate(RawEvent e)
	{
		EventKind kind = ClassifyEvent(e.Channel ?? string.Empty, e.EventId, e.LogonType);

		if (kind == EventKind.Unrelated)
		{
			_logger?.LogDebug(
				"RdpConnectionFactUpserter BuildCandidate DROP: EventId={EventId} Channel={Channel} LogonType={LogonType} classified as Unrelated — no fact row will ever be produced for this event shape.",
				e.EventId, e.Channel, e.LogonType);
			return;
		}

		_logger?.LogDebug(
			"RdpConnectionFactUpserter BuildCandidate DROP: EventId={EventId} Channel={Channel} Kind={Kind} has no usable key — LogonId={LogonId} SessionId={SessionId} UserName={UserName}. " +
			"A key requires LogonId, OR (SessionId AND UserName), OR UserName alone.",
			e.EventId, e.Channel, kind, e.LogonId, e.SessionId, e.UserName);
	}

	// ── Disposal & Pool Returns ──────────────────────────────────────────────────
	// (No unmanaged resources or pooled objects owned by this class.)

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
		PreAuthListener,
		ExplicitCreds,
	}

	private enum KeyStrength
	{
		Weak,
		Strong,
	}

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
