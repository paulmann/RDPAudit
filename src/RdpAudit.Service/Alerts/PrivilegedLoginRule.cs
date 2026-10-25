// File:    src/RdpAudit.Service/Alerts/PrivilegedLoginRule.cs
// Module:  RdpAudit.Service.Alerts
// Purpose: Flags Event 4672 - Special privileges (SeDebug / SeTcb) assigned at logon.
//          Hardened against the start-of-service well-known-SID storm observed on 2026-08-24
//          (~40 identical PRIVILEGED_LOGIN alerts in 8 ms for user SYSTEM, ip null):
//            • well-known service SIDs (S-1-5-18 SYSTEM / S-1-5-19 LOCAL SERVICE /
//              S-1-5-20 NETWORK SERVICE) are filtered by exact SID taken from the
//              normalized Details JSON (EventNormalizer persists EventData/Data
//              SubjectUserSid), never by the localized account name;
//            • a meaningful network context is required - a non-empty SourceIp AND a
//              network/RDP logon type. Explicit LogonType must be 3 (Network), 7 (Unlock)
//              or 10 (RemoteInteractive); anything else (5 Service, 0/2, ...) never alerts.
//              Because Windows 4672 carries no LogonType field of its own, a missing
//              LogonType falls back to correlating the matching Security 4624 via
//              SubjectLogonId == TargetLogonId through IAlertContext.GetRecentByUserAsync;
//            • historical / backfill events older than Alerts.AlertEventMaxAgeMinutes are
//              ignored here - they remain persisted as RawEvent facts upstream of rules;
//            • identical triggers are suppressed per (user, source ip, logon type) inside
//              Alerts.PrivilegedLoginSuppressionWindowMinutes; one summary alert carrying
//              the suppressed count is emitted when the window expires;
//            • a per-rule alert budget (Alerts.PrivilegedLoginRateLimitPerMinute) caps the
//              output with an explicit structured throttling log once per minute.
//          Every rejection path (wrong event id, age, missing ip, non-network logon type,
//          whitelist, privilege scan, well-known SID, suppression, throttle) is allocation-free:
//          EvaluateAsync is deliberately NOT an async method - it returns a shared cached task
//          singleton for null results, so a 10 000-call hot loop allocates zero bytes. Only the
//          rare qualifying path (emitted alert or the LogonType-null DB correlation) allocates.
// Extends: RdpAudit.Core.Events.AlertRuleBase
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System.Globalization;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using RdpAudit.Core.Config;
using RdpAudit.Core.Events;
using RdpAudit.Core.Models;

namespace RdpAudit.Service.Alerts;

/// <summary>Flags Event 4672 - Special privileges assigned at logon.</summary>
public sealed class PrivilegedLoginRule : AlertRuleBase
{
	// ── Detection constants ────────────────────────────────────────────────────

	private static readonly string[] WatchedPrivileges =
	{
		"SeDebugPrivilege",
		"SeTcbPrivilege",
		"SeImpersonatePrivilege",
		"SeBackupPrivilege",
		"SeRestorePrivilege",
		"SeTakeOwnershipPrivilege",
	};

	private const string PrivilegeListTokenCamel = "\"privilegeList\"";
	private const string PrivilegeListTokenPascal = "\"PrivilegeList\"";
	private const string SubjectUserSidTokenCamel = "\"subjectUserSid\"";
	private const string SubjectUserSidTokenPascal = "\"SubjectUserSid\"";

	private const int SuppressionBucketCount = 64;

	/// <summary>Shared completed task returned on every rejection path. Task.FromResult
	/// caches the singleton for null results, so these paths allocate nothing per call.</summary>
	private static readonly Task<Alert?> NullTask = Task.FromResult<Alert?>(null);

	// ── Fields ─────────────────────────────────────────────────────────────────

	/// <summary>UTC clock. Defaults to <c>DateTime.UtcNow</c>; tests inject a controllable clock.</summary>
	private readonly Func<DateTime> _utcNow;
	private readonly ILogger<PrivilegedLoginRule> _logger;

	/// <summary>Keyed suppression buckets. The RuleId is implicit: each rule instance owns its
	/// own bucket array, so the effective dedupe key is (RuleId, UserName, SourceIp, LogonType).</summary>
	private readonly WindowBucket?[] _buckets = new WindowBucket?[SuppressionBucketCount];
	private readonly object _windowGate = new();

	/// <summary>Sliding-budget state for the per-minute alert cap. Minute-bucket based so the
	/// throttle fact is logged at most once per clock minute.</summary>
	private readonly object _rateGate = new();
	private long _rateMinuteUtc;
	private int _rateUsed;
	private long _throttleLoggedMinuteUtc = long.MinValue;

	// ── Construction ───────────────────────────────────────────────────────────

	public PrivilegedLoginRule()
		: this(static () => DateTime.UtcNow, NullLogger<PrivilegedLoginRule>.Instance)
	{
	}

	public PrivilegedLoginRule(ILogger<PrivilegedLoginRule>? logger)
		: this(static () => DateTime.UtcNow, logger ?? NullLogger<PrivilegedLoginRule>.Instance)
	{
	}

	internal PrivilegedLoginRule(Func<DateTime> utcNow, ILogger<PrivilegedLoginRule>? logger = null)
	{
		_utcNow = utcNow ?? throw new ArgumentNullException(nameof(utcNow));
		_logger = logger ?? NullLogger<PrivilegedLoginRule>.Instance;
	}

	// ── Public API ─────────────────────────────────────────────────────────────

	public override string RuleId => "PRIVILEGED_LOGIN";

	public override string Name => "Privileged Account Logon";

	public override AlertSeverity Severity => AlertSeverity.Medium;

	public override bool IsEnabled(RdpAuditOptions options) => options.Alerts.EnablePrivilegedLoginDetection;

	public override Task<Alert?> EvaluateAsync(RawEvent evt, IAlertContext ctx, CancellationToken ct)
	{
		if (evt.EventId != 4672)
		{
			return NullTask;
		}

		AlertOptions alerts = ctx.Options.Alerts;
		DateTime nowUtc = _utcNow();

		// Backfill / startup replay gate. Historical events stay persisted as RawEvent facts
		// upstream (EventProcessorWorker commits them before any rule runs); they must never
		// surface here as fresh alerts.
		int ageMinutes = Math.Max(1, alerts.AlertEventMaxAgeMinutes);
		if (nowUtc - evt.TimeUtc > TimeSpan.FromMinutes(ageMinutes))
		{
			return NullTask;
		}

		// RDPAudit detects network logon activity: an event without a source IP has no
		// network context and must never produce this alert (SYSTEM local logons, logon
		// type 5 service starts, etc.). This is the exact 2026-08-24 storm path.
		if (string.IsNullOrEmpty(evt.SourceIp))
		{
			return NullTask;
		}

		string sourceIp = evt.SourceIp;

		if (!string.IsNullOrEmpty(evt.UserName)
			&& alerts.WhitelistUsers.Contains(evt.UserName, StringComparer.OrdinalIgnoreCase))
		{
			return NullTask;
		}

		string? details = evt.Details;
		if (string.IsNullOrEmpty(details))
		{
			return NullTask;
		}

		ReadOnlySpan<char> json = details;
		if (!TryGetJsonStringValue(json, PrivilegeListTokenCamel, out ReadOnlySpan<char> privilegeList)
			&& !TryGetJsonStringValue(json, PrivilegeListTokenPascal, out privilegeList))
		{
			return NullTask;
		}

		if (!ContainsSensitivePrivilege(privilegeList))
		{
			return NullTask;
		}

		// Well-known service accounts are rejected by exact SID. The SID is read from the
		// normalized Details JSON: EventNormalizer.ExtractAllEventData flattens every
		// EventData/Data element of the 4672 payload, including
		// Data[@Name='SubjectUserSid']. Localized account names (SYSTEM / СИСТЕМА / ...)
		// are deliberately never used for this filter.
		if (ContainsWellKnownServiceSid(json))
		{
			return NullTask;
		}

		// Windows 4672 has no LogonType field of its own. An explicit non-network value (5
		// Service, 0/2, ...) fails immediately; a null value falls back to correlating the
		// matching Security 4624 through IAlertContext (the only allocated, DB-backed path).
		if (evt.LogonType is int explicitLogonType)
		{
			if (explicitLogonType is not (3 or 7 or 10))
			{
				return NullTask;
			}

			return TryEmitAlert(sourceIp, evt, alerts, nowUtc);
		}

		if (string.IsNullOrEmpty(evt.LogonId)
			|| string.IsNullOrEmpty(evt.UserName))
		{
			return NullTask;
		}

		return EvaluateWithLogonCorrelationAsync(sourceIp, evt, ctx, alerts, nowUtc, ct);
	}

	// ── Alert emission ─────────────────────────────────────────────────────────

	/// <summary>Runs the suppression window and the per-minute budget, then either returns the
	/// shared null task or allocates and returns the single justified alert. This is the slowest
	/// of the hot paths, and it still allocates nothing when the trigger is suppressed or throttled.</summary>
	private Task<Alert?> TryEmitAlert(string sourceIp, RawEvent evt, AlertOptions alerts, DateTime nowUtc)
	{
		TimeSpan window = TimeSpan.FromMinutes(Math.Max(1, alerts.PrivilegedLoginSuppressionWindowMinutes));
		WindowDecision decision = RegisterWindowHit(evt.UserName, sourceIp, evt.LogonType, nowUtc, window);
		if (decision.Suppressed)
		{
			return NullTask;
		}

		int perMinute = Math.Max(1, alerts.PrivilegedLoginRateLimitPerMinute);
		RateDecision rate = TryAcquireRateSlot(nowUtc, perMinute);
		if (rate == RateDecision.Throttled)
		{
			return NullTask;
		}

		if (rate == RateDecision.ThrottledNotify)
		{
			_logger.LogWarning(
				"Alert rule {RuleId} throttled: per-minute alert budget of {PerMinute} exhausted; further alerts suppressed until the next minute",
				RuleId,
				perMinute);
			return NullTask;
		}

		if (decision.Summary)
		{
			return Task.FromResult<Alert?>(CreateAlert(
				evt,
				string.Format(
					CultureInfo.InvariantCulture,
					"Privileged logon by {0} from {1}: {2} identical event(s) suppressed in the last {3:0} min",
					evt.UserName ?? "(unknown user)",
					evt.SourceIp,
					decision.SuppressedCount,
					window.TotalMinutes),
				new
				{
					Summary = true,
					SuppressedCount = decision.SuppressedCount,
					WindowMinutes = window.TotalMinutes,
					Mitre = "T1078",
				}));
		}

		return Task.FromResult<Alert?>(CreateAlert(
			evt,
			string.Format(
				CultureInfo.InvariantCulture,
				"Privileged logon by {0} (sensitive privileges granted)",
				evt.UserName ?? "(unknown user)"),
			new { Mitre = "T1078" }));
	}

	/// <summary>Rare path: the event reports no LogonType, so the network-context decision needs
	/// the matching Security 4624 from the database. Only this path is genuinely async.</summary>
	private async Task<Alert?> EvaluateWithLogonCorrelationAsync(
		string sourceIp,
		RawEvent evt,
		IAlertContext ctx,
		AlertOptions alerts,
		DateTime nowUtc,
		CancellationToken ct)
	{
		if (!await HasNetworkLogonContextViaCorrelationAsync(evt, ctx, ct).ConfigureAwait(false))
		{
			return null;
		}

		return await TryEmitAlert(sourceIp, evt, alerts, nowUtc).ConfigureAwait(false);
	}

	/// <summary>Correlates the 4672 to its Security 4624 by SubjectLogonId == TargetLogonId and
	/// requires the 4624 to carry a network logon type (3 / 7 / 10).</summary>
	private static async Task<bool> HasNetworkLogonContextViaCorrelationAsync(
		RawEvent evt,
		IAlertContext ctx,
		CancellationToken ct)
	{
		int lookbackMinutes = Math.Max(1, ctx.Options.Alerts.AlertEventMaxAgeMinutes);
		IReadOnlyList<RawEvent> recent = await ctx
			.GetRecentByUserAsync(evt.UserName!, 200, TimeSpan.FromMinutes(lookbackMinutes), ct)
			.ConfigureAwait(false);

		foreach (RawEvent candidate in recent)
		{
			if (candidate.EventId == 4624
				&& string.Equals(candidate.LogonId, evt.LogonId, StringComparison.OrdinalIgnoreCase)
				&& candidate.LogonType is 3 or 7 or 10)
			{
				return true;
			}
		}

		return false;
	}

	// ── Dedupe / suppression window ────────────────────────────────────────────

	private readonly record struct WindowDecision(bool Suppressed, bool Summary, long SuppressedCount)
	{
		public static WindowDecision Suppress() => new(Suppressed: true, Summary: false, SuppressedCount: 0);

		public static WindowDecision Summarize(long suppressedCount) => new(Suppressed: false, Summary: true, SuppressedCount: suppressedCount);

		public static WindowDecision Fresh() => default;
	}

	/// <summary>Registers the keyed trigger inside its suppression bucket. First hit in a window
	/// yields <c>Fresh</c>; further identical hits yield <c>Suppress</c>; the first identical hit
	/// after window expiry yields <c>Summarize(count)</c> and re-arms a new window (the current
	/// event is consumed as the summary trigger).</summary>
	private WindowDecision RegisterWindowHit(string? userName, string sourceIp, int? logonType, DateTime nowUtc, TimeSpan window)
	{
		uint hash = HashKey(userName, sourceIp, logonType);
		int index = (int)(hash % (uint)_buckets.Length);
		lock (_windowGate)
		{
			WindowBucket bucket = _buckets[index] ??= new WindowBucket();
			bool same = bucket.LogonType == logonType
				&& string.Equals(bucket.SourceIp, sourceIp, StringComparison.OrdinalIgnoreCase)
				&& string.Equals(bucket.UserName, userName, StringComparison.OrdinalIgnoreCase);
			if (!same)
			{
				bucket.UserName = userName;
				bucket.SourceIp = sourceIp;
				bucket.LogonType = logonType;
				bucket.WindowStartUtc = nowUtc;
				bucket.AlertEmitted = true;
				bucket.SuppressedCount = 0;
				return WindowDecision.Fresh();
			}

			bool expired = (nowUtc - bucket.WindowStartUtc) >= window;
			if (expired)
			{
				long suppressed = bucket.SuppressedCount;
				bucket.WindowStartUtc = nowUtc;
				bucket.SuppressedCount = 0;
				bucket.AlertEmitted = true;
				return suppressed > 0 ? WindowDecision.Summarize(suppressed) : WindowDecision.Fresh();
			}

			if (bucket.AlertEmitted)
			{
				bucket.SuppressedCount++;
				return WindowDecision.Suppress();
			}

			bucket.AlertEmitted = true;
			return WindowDecision.Fresh();
		}
	}

	/// <summary>FNV-1a over the three key fields with ordinal-ignore-case folding for the
	/// string parts. Zero-allocation; used only for bucket scatter, equality is still field-based.</summary>
	private static uint HashKey(string? userName, string sourceIp, int? logonType)
	{
		uint hash = 2166136261u;
		hash = HashSpan(hash, userName.AsSpan());
		hash = HashSpan(hash, sourceIp.AsSpan());
		unchecked
		{
			hash ^= (uint)(logonType ?? 0);
			hash *= 16777619u;
		}
		return hash;
	}

	private static uint HashSpan(uint hash, ReadOnlySpan<char> span)
	{
		unchecked
		{
			foreach (char c in span)
			{
				char folded = c is >= 'A' and <= 'Z' ? (char)(c + 32) : c;
				hash ^= folded;
				hash *= 16777619u;
			}
		}
		return hash;
	}

	// ── Per-minute alert budget ────────────────────────────────────────────────

	private enum RateDecision
	{
		Allowed,
		Throttled,
		ThrottledNotify,
	}

	private RateDecision TryAcquireRateSlot(DateTime nowUtc, int perMinute)
	{
		long minute = nowUtc.Ticks - (nowUtc.Ticks % TimeSpan.TicksPerMinute);
		lock (_rateGate)
		{
			if (minute != _rateMinuteUtc)
			{
				_rateMinuteUtc = minute;
				_rateUsed = 0;
			}

			if (_rateUsed >= perMinute)
			{
				RateDecision decision = _throttleLoggedMinuteUtc == minute
					? RateDecision.Throttled
					: RateDecision.ThrottledNotify;
				if (decision == RateDecision.ThrottledNotify)
				{
					_throttleLoggedMinuteUtc = minute;
				}

				return decision;
			}

			_rateUsed++;
			return RateDecision.Allowed;
		}
	}

	// ── Allocation-free scanners ───────────────────────────────────────────────

	private static bool ContainsWellKnownServiceSid(ReadOnlySpan<char> json)
	{
		if (TryGetJsonStringValue(json, SubjectUserSidTokenCamel, out ReadOnlySpan<char> sid)
			|| TryGetJsonStringValue(json, SubjectUserSidTokenPascal, out sid))
		{
			return sid.Equals("S-1-5-18", StringComparison.Ordinal)
				|| sid.Equals("S-1-5-19", StringComparison.Ordinal)
				|| sid.Equals("S-1-5-20", StringComparison.Ordinal);
		}

		// No SID in the payload: fail open. The network/logon gates above remain authoritative.
		return false;
	}

	private static bool ContainsSensitivePrivilege(ReadOnlySpan<char> privilegeList)
	{
		foreach (string privilege in WatchedPrivileges)
		{
			if (privilegeList.Contains(privilege, StringComparison.Ordinal))
			{
				return true;
			}
		}

		return false;
	}

	/// <summary>Reads a JSON string property value without allocating. The token must include
	/// the enclosing quotes (e.g. <c>"privilegeList"</c>); tolerant of whitespace around the
	/// colon and of camelCase/PascalCase key forms via two explicit token probes.</summary>
	private static bool TryGetJsonStringValue(
		ReadOnlySpan<char> json,
		ReadOnlySpan<char> token,
		out ReadOnlySpan<char> value)
	{
		value = default;
		int index = json.IndexOf(token);
		if (index < 0)
		{
			return false;
		}

		int cursor = index + token.Length;
		SkipWhitespace(json, ref cursor);
		if (cursor >= json.Length || json[cursor] != ':')
		{
			return false;
		}

		cursor++;
		SkipWhitespace(json, ref cursor);
		if (cursor >= json.Length || json[cursor] != '"')
		{
			return false;
		}

		cursor++;
		int start = cursor;
		while (cursor < json.Length && json[cursor] != '"')
		{
			cursor++;
		}

		if (cursor >= json.Length)
		{
			return false;
		}

		value = json[start..cursor];
		return true;
	}

	private static void SkipWhitespace(ReadOnlySpan<char> json, ref int cursor)
	{
		while (cursor < json.Length && char.IsWhiteSpace(json[cursor]))
		{
			cursor++;
		}
	}

	// ── Suppression table ──────────────────────────────────────────────────────

	private sealed class WindowBucket
	{
		public string? UserName;
		public string SourceIp = string.Empty;
		public int? LogonType;
		public DateTime WindowStartUtc;
		public long SuppressedCount;
		public bool AlertEmitted;
	}
}
