// File:    tests/RdpAudit.Core.Tests/AttackStatsFilterTests.cs
// Module:  RdpAudit.Core.Tests
// Purpose: Covers the pure Attack Statistics filter predicate used by the Configurator tab to
//          pre-filter cached rows while the operator types. Mirrors the server-side
//          AttackStatsRequest semantics so the UI and the IPC handler agree on edge cases.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using RdpAudit.Core.Ipc.Contracts;
using RdpAudit.Core.Models;
using RdpAudit.Core.Util;
using Xunit;

namespace RdpAudit.Core.Tests;

public class AttackStatsFilterTests
{
	private static AttackStatEntryDto Sample(
		string ip = "203.0.113.5",
		double score = 25,
		bool isBlocked = false,
		DateTime? lastSeenUtc = null)
	{
		return new AttackStatEntryDto
		{
			Ip = ip,
			ThreatScore = score,
			ThreatLevel = AttackThreatScoring.ClassifyScore(score),
			IsBlocked = isBlocked,
			LastSeenUtc = lastSeenUtc ?? new DateTime(2026, 5, 19, 12, 0, 0, DateTimeKind.Utc),
		};
	}

	[Fact]
	public void EmptyFilter_MatchesAnyEntry()
	{
		AttackStatsFilter f = new();
		Assert.True(f.IsEmpty);
		Assert.True(f.Matches(Sample()));
	}

	[Fact]
	public void NullEntry_NeverMatches()
	{
		AttackStatsFilter f = new();
		Assert.False(f.Matches(null));
	}

	[Fact]
	public void IpQuery_IsCaseInsensitiveSubstring()
	{
		AttackStatsFilter f = new() { IpQuery = "113" };
		Assert.True(f.Matches(Sample(ip: "203.0.113.5")));
		Assert.False(f.Matches(Sample(ip: "10.0.0.1")));
	}

	[Fact]
	public void MinThreatScore_IsInclusive()
	{
		AttackStatsFilter f = new() { MinThreatScore = 50 };
		Assert.True(f.Matches(Sample(score: 50)));
		Assert.True(f.Matches(Sample(score: 80)));
		Assert.False(f.Matches(Sample(score: 49.9)));
	}

	[Fact]
	public void OnlyBlocked_ExcludesUnblockedRows()
	{
		AttackStatsFilter f = new() { OnlyBlocked = true };
		Assert.True(f.Matches(Sample(isBlocked: true)));
		Assert.False(f.Matches(Sample(isBlocked: false)));
	}

	[Fact]
	public void SinceUntil_AreInclusiveOnBothEdges()
	{
		DateTime since = new(2026, 5, 19, 11, 0, 0, DateTimeKind.Utc);
		DateTime until = new(2026, 5, 19, 13, 0, 0, DateTimeKind.Utc);
		AttackStatsFilter f = new() { SinceUtc = since, UntilUtc = until };
		Assert.True(f.Matches(Sample(lastSeenUtc: since)));
		Assert.True(f.Matches(Sample(lastSeenUtc: until)));
		Assert.False(f.Matches(Sample(lastSeenUtc: since.AddTicks(-1))));
		Assert.False(f.Matches(Sample(lastSeenUtc: until.AddTicks(1))));
	}

	[Fact]
	public void AllClauses_CombineWithAndSemantics()
	{
		DateTime since = new(2026, 5, 19, 11, 0, 0, DateTimeKind.Utc);
		AttackStatsFilter f = new()
		{
			IpQuery = "113",
			MinThreatScore = 30,
			OnlyBlocked = true,
			SinceUtc = since,
		};

		AttackStatEntryDto pass = Sample(ip: "203.0.113.5", score: 60, isBlocked: true, lastSeenUtc: since.AddMinutes(30));
		Assert.True(f.Matches(pass));

		// Each clause individually flips the result.
		Assert.False(f.Matches(Sample(ip: "10.0.0.1", score: 60, isBlocked: true, lastSeenUtc: since.AddMinutes(30))));
		Assert.False(f.Matches(Sample(ip: "203.0.113.5", score: 10, isBlocked: true, lastSeenUtc: since.AddMinutes(30))));
		Assert.False(f.Matches(Sample(ip: "203.0.113.5", score: 60, isBlocked: false, lastSeenUtc: since.AddMinutes(30))));
		Assert.False(f.Matches(Sample(ip: "203.0.113.5", score: 60, isBlocked: true, lastSeenUtc: since.AddMinutes(-5))));
	}
}
