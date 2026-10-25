// File:    src/RdpAudit.Core/Models/AttackStatsAggregator.cs
// Module:  RdpAudit.Core.Models
// Purpose: Pure (DB-agnostic) projection from raw logon-event samples and active-block lookups into
//          one AttackStat row per source IP. Lifted out of the worker so it can be unit tested
//          without an EF Core DbContext. The worker is responsible for streaming inputs out of the
//          database; this helper does the deterministic projection / scoring.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

namespace RdpAudit.Core.Models;

/// <summary>The auth outcome an <see cref="AttackEventSample"/> represents.</summary>
public enum AttackEventOutcome
{
	/// <summary>The sample is not a logon outcome event for an RDP host. It should be skipped —
	/// it must NOT increment Total / Successful / Failed.</summary>
	Unrelated = 0,

	/// <summary>The sample is a confirmed successful logon (Security 4624 with an RDP-relevant
	/// logon type, TS-RCM 1149 authenticated connection, TS-LSM 21 session logon, or TS-LSM 25
	/// reconnect).</summary>
	Successful = 1,

	/// <summary>The sample is a confirmed failed logon (Security 4625).</summary>
	Failed = 2,

	/// <summary>A real, successful logon that is NOT an RDP session: Security 4624 with the
	/// network logon type (3), which SMB, SSH, WinRM and the NLA stage of RDP all produce. It
	/// counts toward TotalActivity only — never toward Successful.</summary>
	Neutral = 3,
}

/// <summary>Pure projection helper for Attack Statistics aggregation.</summary>
/// <remarks>
/// The Service-side worker pulls bounded slices of <c>RawEvents</c> (logon successes / failures)
/// and a set of currently-blocked IPs from the database, then hands them to <see cref="Aggregate"/>
/// which produces one <see cref="AttackStat"/> per distinct source IP. All scoring goes through
/// <see cref="AttackThreatScoring"/> so the same number rendered in the Configurator UI is the
/// number the worker wrote.
/// </remarks>
public static class AttackStatsAggregator
{
	/// <summary>Security channel logon-success event id (Windows Security log).</summary>
	public const int EventIdLogonSuccess = 4624;

	/// <summary>Security channel logon-failure event id (Windows Security log).</summary>
	public const int EventIdLogonFailure = 4625;

	/// <summary>
	/// Canonical "RDP-relevant logon type" test for Security 4624 — the single source of truth for
	/// every layer that decides whether a 4624 counts as an authentication success.
	/// </summary>
	/// <remarks>
	/// Detect_Attack_Strategy_v3.md (§2, §6.4) treats a 4624 as a successful logon only for
	/// remote / interactive logon types. Batch (4) and Service (5) are local by definition: the
	/// Service Control Manager creates them and their <c>Source Network Address</c> is empty,
	/// loopback or a stripped sentinel, so they can never be an attacker's RDP success.
	/// NetworkCleartext (8) and NewCredentials (9) are not credential-validated logons either.
	/// A <c>null</c> / <c>0</c> type stays eligible because some channels omit the field entirely
	/// and a stripped payload must not be silently dropped.
	/// Allocation-free by construction (pattern match — no LINQ, no collection) because this
	/// predicate runs in the per-event ingest path (NFR-PERF-1).
	/// </remarks>
	public static bool IsRdpRelevantLogonType(int? logonType) =>
		logonType is null or 0 or 2 or 3 or 7 or 10 or 11;

	/// <summary>
	/// The same success-bearing logon-type codes as <see cref="IsRdpRelevantLogonType"/>, exposed as a
	/// collection so database queries can build an equivalent server-side <c>IN (...)</c> predicate —
	/// the SQLite provider cannot translate a method call, and re-listing the codes per query is how
	/// these counters drift apart again. Do not mutate. Kept in lock-step with the predicate by
	/// <c>AttackStatsAggregatorTests.RdpRelevantLogonTypeCodes_AgreeWithThePredicate</c>.
	/// </summary>
	public static readonly int[] RdpRelevantLogonTypeCodes = [0, 2, 3, 7, 10, 11];

	/// <summary>
	/// Canonical "this logon could have arrived over the network" test, used for <b>attribution</b>
	/// (transport-IP / session correlation) and for network-context alert rules — as opposed to
	/// <see cref="IsRdpRelevantLogonType"/>, which answers the classification question.
	/// </summary>
	/// <remarks>
	/// Only Network (3), Unlock / reconnect (7) and RemoteInteractive (10) can carry a remote source
	/// address. A console (2 / 11), batch (4) or service (5) logon reports an empty, loopback or
	/// <c>-</c> address, so correlating an IP onto it attaches the address of an unrelated concurrent
	/// RDP connection to a local logon — the false-attribution class this predicate exists to prevent.
	/// Detect_Attack_Strategy_v3.md §2 and docs/40-alert-rules.md use exactly this set.
	/// </remarks>
	public static bool IsRemoteCapableLogonType(int? logonType) => logonType is 3 or 7 or 10;

	/// <summary>
	/// True for *known* logon types that are local by construction and therefore can never carry a
	/// remote source address — console Interactive (2) / CachedInteractive (11) / CachedUnlock (13),
	/// Batch (4) and Service (5).
	/// </summary>
	/// <remarks>
	/// Used to suppress IP <b>attribution</b> for these logons: Windows reports an empty, loopback or
	/// stripped (<c>-</c>) source address for them, so a time-window correlation would attach the
	/// address of an unrelated concurrent RDP connection. Deliberately narrower than "not
	/// remote-capable": NetworkCleartext (8) and NewCredentials (9) may legitimately originate from a
	/// remote peer, and a <c>null</c> / <c>0</c> type means "field absent", which is exactly the
	/// stripped-payload case v3 §6.3 rule 5 exists to recover — so those must stay eligible.
	/// </remarks>
	public static bool IsLocalOnlyLogonType(int? logonType) => logonType is 2 or 4 or 5 or 11 or 13;

	/// <summary>
	/// True when an absent address for this evidence class means "expected but lost" rather than
	/// "this record type never carries one".
	/// </summary>
	/// <remarks>
	/// The unresolved-IP sentinel exists to keep real brute-force pressure visible when Windows strips
	/// the address from an event that normally has it. It was also catching classes that cannot carry
	/// an address at all — NTLM validation (4776), explicit-credential use (4648), Kerberos pre-auth
	/// (4768 / 4769 / 4771), console (2 / 11) and service (5) logons — so a real host rendered
	/// thousands of "(unresolved)" events that were never RDP attempts with a lost address. Measured
	/// on ILAB (192.168.3.100, 23.10.2026): of the 3 562 events under the sentinel, 4776 and 4624
	/// LogonType 5 accounted for almost all of them, while Security 4625 without an address — the
	/// only class where the address is genuinely expected — numbered 16 in the whole database.
	/// </remarks>
	/// <summary>
	/// Logon types that describe an actual RDP session for the "success" counter:
	/// RemoteInteractive (10) and Unlock / reconnect (7). Everything else is either local
	/// (2 / 4 / 5 / 11), a bare network logon (3 — SMB, SSH, WinRM, NLA stage) or unknown, and must
	/// not be presented as an RDP session success.
	/// </summary>
	/// <remarks>
	/// Measured on the fleet (23.10.2026): the grid credited an external address that made 8 failed
	/// attempts with **2 870 successful RDP logons**, almost all of them Security 4776 / 4648 records
	/// that the worker folded into a synthetic 4624. A successful NTLM validation or an
	/// explicit-credential use is not a session at all, and a console logon is not a remote one.
	/// </remarks>
	public static bool IsRdpSuccessLogonType(int? logonType) => logonType is 7 or 10;

	public static bool ExpectsSourceAddress(int evidenceEventId, int? logonType) => evidenceEventId switch
	{
		// Failed logon: an address-bearing class writes IpAddress, so a blank one there is genuine loss.
		// A batch (4), service (5) or console (2 / 11) failure is local by construction and carries no address;
		// filing it under the sentinel presented local account trouble as unresolved remote attack pressure
		// (measured on 192.168.1.100: 891 batch failures inflated that row).
		4625 => logonType is null or 0 || !IsLocalOnlyLogonType(logonType),
		// Success: only the types that can arrive over the network (plus an absent / unknown field).
		4624 => logonType is null or 0 || IsRemoteCapableLogonType(logonType),
		// RDP reconnect / disconnect and the "denied by user right" record carry the caller address.
		4778 or 4779 => true,
		4825 => true,
		// TS-RCM authentication attempt (Param3 is the source address).
		1149 => true,
		_ => false,
	};

	/// <summary>
	/// Sentinel IP used when Stage 1 flagged the event as <c>SourceIpUnresolved</c>. The address
	/// is reserved (IANA "this host on this network") and is unambiguous: real attacker traffic
	/// never legitimately carries 0.0.0.0 as source. Operators see this row rendered as
	/// <see cref="SentinelDisplayLabel"/> in the Attack Statistics tab.
	/// </summary>
	public const string SentinelUnresolvedIp = "0.0.0.0";

	/// <summary>Operator-facing label for the unresolved-IP sentinel row.</summary>
	public const string SentinelDisplayLabel = "(unresolved)";

	internal const string SecurityChannel = "Security";
	internal const string TsLsmChannel = "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational";
	internal const string TsRcmChannel = "Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational";

	/// <summary>Returns true when the supplied IP equals the unresolved-attacker sentinel.</summary>
	public static bool IsSentinelUnresolvedIp(string? ip) =>
		!string.IsNullOrEmpty(ip) && string.Equals(ip, SentinelUnresolvedIp, StringComparison.Ordinal);

	/// <summary>
	/// Classifies an event into <see cref="AttackEventOutcome"/>. Mapping mirrors the same set of
	/// events <see cref="RdpConnectionFact"/> upserts treat as authoritative for an RDP login outcome.
	/// </summary>
	/// <remarks>
	/// On many Windows SKUs, a successful RDP logon does not produce a usable Security 4624 (the
	/// IpAddress field is "-" or local), while the TerminalServices channels carry the IP and the
	/// authoritative successful-auth signal — TS-RCM 1149 / TS-LSM 21. Without this classifier the
	/// aggregator was scoring TS-RCM 1149 as a failure (because the old fallback counted any
	/// unknown event id toward _failed), which inverted the Attack Statistics tab. We now require
	/// an explicit positive classification before incrementing Failed.
	/// </remarks>
	public static AttackEventOutcome Classify(string? channel, int eventId, int? logonType)
	{
		string ch = channel ?? string.Empty;

		if (string.Equals(ch, SecurityChannel, StringComparison.OrdinalIgnoreCase) || ch.Length == 0)
		{
			switch (eventId)
			{
				case EventIdLogonSuccess:
					// "Successful" here means a REMOTE logon, not any logon Windows recorded: console (2),
					// cached-interactive (11), batch (4) and service (5) entries never describe an RDP
					// session. Counting them credited attacking addresses with hundreds of "successful
					// RDP logons" while no session ever existed.
					if (IsRdpSuccessLogonType(logonType))
					{
						return AttackEventOutcome.Successful;
					}

					// Network (3) is a successful logon that is not an RDP session: SMB, SSH, WinRM and
					// the NLA stage of an RDP connection all produce it. Keep it visible in Total, but
					// never present it as "RDP Session Success" — measured on the fleet, an address with
					// 14 657 failed RDP attempts showed 130 "successes", all of them 4624 LogonType 3
					// with zero RemoteInteractive logons behind them.
					return logonType is null or 0 or 3
						? AttackEventOutcome.Neutral
						: AttackEventOutcome.Unrelated;
				case EventIdLogonFailure:
					return AttackEventOutcome.Failed;
				default:
					return AttackEventOutcome.Unrelated;
			}
		}

		if (string.Equals(ch, TsRcmChannel, StringComparison.OrdinalIgnoreCase))
		{
			return eventId switch
			{
				1149 => AttackEventOutcome.Successful, // RD Gateway / NLA authenticated connection.
				_ => AttackEventOutcome.Unrelated,
			};
		}

		if (string.Equals(ch, TsLsmChannel, StringComparison.OrdinalIgnoreCase))
		{
			return eventId switch
			{
				21 => AttackEventOutcome.Successful, // session logon with IP
				25 => AttackEventOutcome.Successful, // session reconnected
				_ => AttackEventOutcome.Unrelated,
			};
		}

		return AttackEventOutcome.Unrelated;
	}

	/// <summary>
	/// Aggregates one row per distinct source IP from <paramref name="samples"/>, scoring each row
	/// against the active-block set in <paramref name="blockedIps"/>.
	/// </summary>
	/// <param name="samples">Bounded slice of logon-relevant raw events.</param>
	/// <param name="blockedIps">Set of source IPs that currently have an Active / Pending block.</param>
	/// <param name="nowUtc">"Now" reference (UTC) — used for the recentness component and LastUpdated.</param>
	/// <returns>One <see cref="AttackStat"/> per distinct, non-empty <c>SourceIp</c>.</returns>
	public static IReadOnlyList<AttackStat> Aggregate(
		IEnumerable<AttackEventSample> samples,
		ISet<string> blockedIps,
		DateTime nowUtc)
	{
		ArgumentNullException.ThrowIfNull(samples);
		ArgumentNullException.ThrowIfNull(blockedIps);

		Dictionary<string, Accumulator> byIp = new(StringComparer.OrdinalIgnoreCase);
		foreach (AttackEventSample sample in samples)
		{
			if (string.IsNullOrWhiteSpace(sample.SourceIp))
			{
				continue;
			}

			AttackEventOutcome outcome = Classify(sample.Channel, sample.EventId, sample.LogonType);
			if (outcome == AttackEventOutcome.Unrelated)
			{
				continue;
			}

			string ip = sample.SourceIp.Trim();
			if (!byIp.TryGetValue(ip, out Accumulator? acc))
			{
				acc = new Accumulator(ip);
				byIp[ip] = acc;
			}

			acc.Apply(sample, outcome);
		}

		List<AttackStat> result = new(byIp.Count);
		foreach (Accumulator acc in byIp.Values)
		{
			result.Add(acc.Build(blockedIps.Contains(acc.Ip), nowUtc));
		}

		// Deterministic ordering for byte-stable test assertions.
		result.Sort((a, b) =>
		{
			int byScore = b.ThreatScore.CompareTo(a.ThreatScore);
			if (byScore != 0)
			{
				return byScore;
			}
			return string.CompareOrdinal(a.Ip, b.Ip);
		});
		return result;
	}

	private sealed class Accumulator
	{
		public string Ip { get; }

		private long _total;
		private long _successful;
		private long _failed;
		private DateTime _firstSeenUtc = DateTime.MaxValue;
		private DateTime _lastSeenUtc = DateTime.MinValue;
		private int? _lastLoginType;
		private readonly List<string?> _attemptedLogins = new();

		public Accumulator(string ip)
		{
			Ip = ip;
		}

		public void Apply(AttackEventSample sample, AttackEventOutcome outcome)
		{
			_total++;
			switch (outcome)
			{
				case AttackEventOutcome.Successful:
					_successful++;
					break;
				case AttackEventOutcome.Failed:
					_failed++;
					break;
			}

			if (sample.TimeUtc < _firstSeenUtc)
			{
				_firstSeenUtc = sample.TimeUtc;
			}
			if (sample.TimeUtc > _lastSeenUtc)
			{
				_lastSeenUtc = sample.TimeUtc;
				if (sample.LogonType.HasValue)
				{
					_lastLoginType = sample.LogonType;
				}
			}

			_attemptedLogins.Add(sample.UserName);
		}

		public AttackStat Build(bool isBlocked, DateTime nowUtc)
		{
			DateTime first = _firstSeenUtc == DateTime.MaxValue ? nowUtc : _firstSeenUtc;
			DateTime last = _lastSeenUtc == DateTime.MinValue ? nowUtc : _lastSeenUtc;
			long durationSeconds = AttackStatProjection.ComputeDurationSeconds(first, last);
			IReadOnlyList<string> topLogins = AttackStatProjection.ComputeTopLogins(_attemptedLogins);

			double score = AttackThreatScoring.ComputeScore(
				_failed,
				_successful,
				durationSeconds,
				isBlocked,
				last,
				nowUtc);

			return new AttackStat
			{
				Ip = Ip,
				TotalAttempts = _total,
				Successful = _successful,
				Failed = _failed,
				FirstSeenUtc = first,
				LastSeenUtc = last,
				DurationSeconds = durationSeconds,
				Top10AttemptedLogins = AttackStatProjection.SerializeTopLogins(topLogins),
				LastLoginType = _lastLoginType,
				ThreatScore = score,
				IsBlocked = isBlocked,
				LastUpdatedUtc = nowUtc,
			};
		}
	}
}

/// <summary>Compact event sample fed to <see cref="AttackStatsAggregator.Aggregate"/>.</summary>
/// <param name="SourceIp">Trimmed source IP (any non-empty IPv4 / IPv6 textual form).</param>
/// <param name="EventId">Windows event id.</param>
/// <param name="TimeUtc">Event UTC timestamp.</param>
/// <param name="UserName">Optional attempted login name; null / blank entries are dropped.</param>
/// <param name="LogonType">Optional Windows logon type captured from the event.</param>
/// <param name="Channel">Originating Windows event channel — used by
/// <see cref="AttackStatsAggregator.Classify"/> to recognise TS-RCM 1149 / TS-LSM 21/25 as
/// successful authentications. Defaults to <c>"Security"</c> when omitted so legacy callers that
/// only pass Security-channel events keep their behaviour.</param>
public readonly record struct AttackEventSample(
	string? SourceIp,
	int EventId,
	DateTime TimeUtc,
	string? UserName,
	int? LogonType,
	string? Channel = AttackStatsAggregator.SecurityChannel);
