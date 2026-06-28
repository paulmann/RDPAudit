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
					// Only count remote/RDP-relevant logon types as connection successes —
					// 2 Interactive, 3 Network, 7 Unlock, 10 RemoteInteractive, 11 CachedInteractive.
					// LogonType 0 (or missing) is permitted because some channels omit the field but
					// still represent an RDP success when paired with a non-null source IP.
					if (logonType is null or 0 or 2 or 3 or 7 or 10 or 11)
					{
						return AttackEventOutcome.Successful;
					}

					return AttackEventOutcome.Unrelated;
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
