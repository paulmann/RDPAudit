// File:    tests/RdpAudit.Core.Tests/AttackStatsAggregatorTests.cs
// Module:  RdpAudit.Core.Tests
// Purpose: Covers the pure projection from sample raw logon events + active-block set into one
//          AttackStat row per source IP. The worker is a thin EF-Core adapter on top of this
//          helper, so locking the projection here is enough to keep aggregation deterministic.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using RdpAudit.Core.Models;
using Xunit;

namespace RdpAudit.Core.Tests;

public class AttackStatsAggregatorTests
{
	private static readonly DateTime Now = new(2026, 5, 19, 12, 0, 0, DateTimeKind.Utc);

	[Fact]
	public void NoSamples_ReturnsEmpty()
	{
		IReadOnlyList<AttackStat> rows = AttackStatsAggregator.Aggregate(
			Array.Empty<AttackEventSample>(),
			new HashSet<string>(StringComparer.OrdinalIgnoreCase),
			Now);
		Assert.Empty(rows);
	}

	[Fact]
	public void EmptyOrNullSourceIp_IsSkipped()
	{
		AttackEventSample[] samples =
		{
			new(null, AttackStatsAggregator.EventIdLogonFailure, Now, "x", null),
			new(string.Empty, AttackStatsAggregator.EventIdLogonFailure, Now, "y", null),
			new("   ", AttackStatsAggregator.EventIdLogonFailure, Now, "z", null),
		};
		IReadOnlyList<AttackStat> rows = AttackStatsAggregator.Aggregate(
			samples,
			new HashSet<string>(StringComparer.OrdinalIgnoreCase),
			Now);
		Assert.Empty(rows);
	}

	[Fact]
	public void GroupsByIp_CountsSuccessFailureSeparately()
	{
		AttackEventSample[] samples =
		{
			new("10.0.0.1", AttackStatsAggregator.EventIdLogonFailure, Now.AddSeconds(-30), "admin", 10),
			new("10.0.0.1", AttackStatsAggregator.EventIdLogonFailure, Now.AddSeconds(-20), "admin", 10),
			new("10.0.0.1", AttackStatsAggregator.EventIdLogonSuccess, Now, "admin", 3),
			new("10.0.0.2", AttackStatsAggregator.EventIdLogonFailure, Now.AddSeconds(-10), "root", 10),
		};
		IReadOnlyList<AttackStat> rows = AttackStatsAggregator.Aggregate(
			samples,
			new HashSet<string>(StringComparer.OrdinalIgnoreCase),
			Now);

		Assert.Equal(2, rows.Count);

		AttackStat one = rows.First(r => r.Ip == "10.0.0.1");
		Assert.Equal(3, one.TotalAttempts);
		Assert.Equal(1, one.Successful);
		Assert.Equal(2, one.Failed);
		Assert.Equal(3, one.LastLoginType); // logon type 3 captured on the most-recent attempt
		Assert.Equal(30, one.DurationSeconds);
		Assert.False(one.IsBlocked);

		AttackStat two = rows.First(r => r.Ip == "10.0.0.2");
		Assert.Equal(1, two.TotalAttempts);
		Assert.Equal(0, two.Successful);
		Assert.Equal(1, two.Failed);
	}

	[Fact]
	public void TopLogins_AreCappedAtTenAndDeterministic()
	{
		List<AttackEventSample> samples = new();
		// Twelve distinct logins with descending frequencies.
		for (int i = 0; i < 12; i++)
		{
			int freq = 12 - i;
			for (int j = 0; j < freq; j++)
			{
				samples.Add(new AttackEventSample(
					"203.0.113.5",
					AttackStatsAggregator.EventIdLogonFailure,
					Now.AddSeconds(-i),
					$"user{i:D2}",
					3));
			}
		}

		IReadOnlyList<AttackStat> rows = AttackStatsAggregator.Aggregate(
			samples,
			new HashSet<string>(StringComparer.OrdinalIgnoreCase),
			Now);
		AttackStat row = Assert.Single(rows);

		IReadOnlyList<string> top = AttackStatProjection.DeserializeTopLogins(row.Top10AttemptedLogins);
		Assert.Equal(AttackStatProjection.TopLoginsLimit, top.Count);
		Assert.Equal("user00", top[0]);
		Assert.Equal("user09", top[^1]);
	}

	[Fact]
	public void IsBlocked_IsPropagatedFromSet()
	{
		AttackEventSample[] samples =
		{
			new("198.51.100.7", AttackStatsAggregator.EventIdLogonFailure, Now, "admin", null),
		};
		HashSet<string> blocked = new(StringComparer.OrdinalIgnoreCase) { "198.51.100.7" };

		IReadOnlyList<AttackStat> rows = AttackStatsAggregator.Aggregate(samples, blocked, Now);
		AttackStat row = Assert.Single(rows);
		Assert.True(row.IsBlocked);
		// ActiveBlockBonus + failure pressure (1*0.5) + intensity (1/1*1000 saturated 20) + recentness (10) = 40.5
		// → Yellow.
		Assert.Equal(AttackThreatLevel.Yellow, AttackThreatScoring.ClassifyScore(row.ThreatScore));
	}

	[Fact]
	public void UnknownEventId_IsSkippedNotCountedAsFailed()
	{
		// Stage FIX-1: prior behaviour counted unknown event ids toward Failed; that inverted the
		// Attack Statistics tab because TS-RCM 1149 / TS-LSM 21 (successful auths) carry a source
		// IP and would land here. Unknown events must now be skipped entirely.
		AttackEventSample[] samples =
		{
			new("172.16.0.10", 9999, Now, "guest", null),
		};
		IReadOnlyList<AttackStat> rows = AttackStatsAggregator.Aggregate(
			samples,
			new HashSet<string>(StringComparer.OrdinalIgnoreCase),
			Now);
		Assert.Empty(rows);
	}

	[Fact]
	public void TsRcm1149_CountsAsSuccessfulNotFailed()
	{
		// Regression: TS-RCM 1149 represents a successful authenticated connection. Before the
		// fix this incremented Failed because the aggregator only recognised Security 4624.
		AttackEventSample[] samples =
		{
			new("10.20.30.40", 1149, Now, "alice", null,
				"Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational"),
		};
		IReadOnlyList<AttackStat> rows = AttackStatsAggregator.Aggregate(
			samples,
			new HashSet<string>(StringComparer.OrdinalIgnoreCase),
			Now);
		AttackStat row = Assert.Single(rows);
		Assert.Equal(1, row.TotalAttempts);
		Assert.Equal(1, row.Successful);
		Assert.Equal(0, row.Failed);
	}

	[Fact]
	public void TsLsm21_CountsAsSuccessfulNotFailed()
	{
		AttackEventSample[] samples =
		{
			new("10.20.30.41", 21, Now, "bob", 10,
				"Microsoft-Windows-TerminalServices-LocalSessionManager/Operational"),
		};
		IReadOnlyList<AttackStat> rows = AttackStatsAggregator.Aggregate(
			samples,
			new HashSet<string>(StringComparer.OrdinalIgnoreCase),
			Now);
		AttackStat row = Assert.Single(rows);
		Assert.Equal(1, row.Successful);
		Assert.Equal(0, row.Failed);
	}

	[Fact]
	public void Security_4624Success_And_4625Failure_AreCountedCorrectly()
	{
		// FIX-1 regression: a successful 4624 must increment Successful (not Failed); a 4625 must
		// increment Failed; both must end up on the same per-IP row.
		AttackEventSample[] samples =
		{
			new("203.0.113.10", AttackStatsAggregator.EventIdLogonSuccess, Now, "alice", 10, "Security"),
			new("203.0.113.10", AttackStatsAggregator.EventIdLogonFailure, Now.AddSeconds(-15), "alice", 3, "Security"),
		};
		IReadOnlyList<AttackStat> rows = AttackStatsAggregator.Aggregate(
			samples,
			new HashSet<string>(StringComparer.OrdinalIgnoreCase),
			Now);
		AttackStat row = Assert.Single(rows);
		Assert.Equal(2, row.TotalAttempts);
		Assert.Equal(1, row.Successful);
		Assert.Equal(1, row.Failed);
	}

	[Fact]
	public void Security_4624WithNonRdpLogonType_IsSkipped()
	{
		// LogonType 4 (Batch) / 5 (Service) are not RDP-relevant — they must not count toward
		// either Successful or Failed for the Attack Statistics view.
		AttackEventSample[] samples =
		{
			new("10.0.0.99", AttackStatsAggregator.EventIdLogonSuccess, Now, "svcacct", 5, "Security"),
		};
		IReadOnlyList<AttackStat> rows = AttackStatsAggregator.Aggregate(
			samples,
			new HashSet<string>(StringComparer.OrdinalIgnoreCase),
			Now);
		Assert.Empty(rows);
	}

	[Fact]
	public void SentinelUnresolvedIp_IsReservedConstantAndDetected()
	{
		// Stage 2 contract: the unresolved-IP sentinel is "0.0.0.0" and the helper recognises it.
		Assert.Equal("0.0.0.0", AttackStatsAggregator.SentinelUnresolvedIp);
		Assert.True(AttackStatsAggregator.IsSentinelUnresolvedIp("0.0.0.0"));
		Assert.False(AttackStatsAggregator.IsSentinelUnresolvedIp("203.0.113.10"));
		Assert.False(AttackStatsAggregator.IsSentinelUnresolvedIp(null));
		Assert.False(AttackStatsAggregator.IsSentinelUnresolvedIp(string.Empty));
	}

	[Fact]
	public void SentinelUnresolvedIp_AggregatesUnderItsOwnRow()
	{
		// Stage 2: when the caller substitutes the sentinel IP for unresolved 4625 rows, the
		// aggregator treats it as just another distinct IP — counters land on a single row,
		// successful Security 4624 with a real IP stays on its own row.
		AttackEventSample[] samples =
		{
			new(AttackStatsAggregator.SentinelUnresolvedIp,
				AttackStatsAggregator.EventIdLogonFailure, Now.AddSeconds(-30), "administrator", null, "Security"),
			new(AttackStatsAggregator.SentinelUnresolvedIp,
				AttackStatsAggregator.EventIdLogonFailure, Now.AddSeconds(-10), "guest", null, "Security"),
			new("203.0.113.50",
				AttackStatsAggregator.EventIdLogonSuccess, Now, "alice", 10, "Security"),
		};
		IReadOnlyList<AttackStat> rows = AttackStatsAggregator.Aggregate(
			samples,
			new HashSet<string>(StringComparer.OrdinalIgnoreCase),
			Now);

		AttackStat sentinel = Assert.Single(rows, r => r.Ip == AttackStatsAggregator.SentinelUnresolvedIp);
		Assert.Equal(2, sentinel.Failed);
		Assert.Equal(0, sentinel.Successful);
		Assert.Equal(2, sentinel.TotalAttempts);

		AttackStat real = Assert.Single(rows, r => r.Ip == "203.0.113.50");
		Assert.Equal(1, real.Successful);
		Assert.Equal(0, real.Failed);
	}

	[Fact]
	public void TsRcm261_RemainsUnrelated_ObservationOnly()
	{
		// Stage 6 / Stage 2 cross-check: TS-RCM 261 (listener received a connection) is observation-
		// only and must never count toward Successful or Failed. The classifier returns Unrelated.
		AttackEventSample[] samples =
		{
			new("198.51.100.250", 261, Now, null, null,
				"Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational"),
		};
		IReadOnlyList<AttackStat> rows = AttackStatsAggregator.Aggregate(
			samples,
			new HashSet<string>(StringComparer.OrdinalIgnoreCase),
			Now);
		Assert.Empty(rows);
	}

	[Fact]
	public void Result_IsOrderedByThreatScoreThenIpDeterministically()
	{
		AttackEventSample[] samples =
		{
			new("10.0.0.1", AttackStatsAggregator.EventIdLogonFailure, Now, "x", null),
			new("10.0.0.2", AttackStatsAggregator.EventIdLogonFailure, Now, "x", null),
			new("10.0.0.2", AttackStatsAggregator.EventIdLogonFailure, Now.AddSeconds(-30), "x", null),
		};
		IReadOnlyList<AttackStat> rows = AttackStatsAggregator.Aggregate(
			samples,
			new HashSet<string>(StringComparer.OrdinalIgnoreCase),
			Now);

		Assert.Equal(2, rows.Count);
		// 10.0.0.2 has more failures so its score should be >= 10.0.0.1's; ordering descending by score.
		Assert.True(rows[0].ThreatScore >= rows[1].ThreatScore);
	}
}
