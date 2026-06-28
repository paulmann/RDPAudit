// File:    tests/RdpAudit.Core.Tests/AttackThreatScoringTests.cs
// Module:  RdpAudit.Core.Tests
// Purpose: Locks the deterministic Attack Statistics threat-scoring rules and the cameyo-style
//          green / yellow / red classification thresholds. Any drift in scoring components
//          (failure pressure, success-after-fail signal, intensity, active-block bonus, recentness)
//          must update both the helper and these tests in lock-step.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using RdpAudit.Core.Models;
using Xunit;

namespace RdpAudit.Core.Tests;

public class AttackThreatScoringTests
{
	private static readonly DateTime Now = new(2026, 5, 19, 12, 0, 0, DateTimeKind.Utc);

	[Fact]
	public void ZeroAttempts_RecentNotBlocked_StaysGreen()
	{
		double score = AttackThreatScoring.ComputeScore(
			failed: 0,
			successful: 0,
			durationSeconds: 0,
			isBlocked: false,
			lastSeenUtc: Now,
			nowUtc: Now);
		// Only the recentness bonus (now == now → very recent → 10) contributes.
		Assert.Equal(10.0, score, 6);
		Assert.Equal(AttackThreatLevel.Green, AttackThreatScoring.ClassifyScore(score));
	}

	[Fact]
	public void SingleSuccessfulLogon_DayOld_Green()
	{
		double score = AttackThreatScoring.ComputeScore(
			failed: 0,
			successful: 1,
			durationSeconds: 0,
			isBlocked: false,
			lastSeenUtc: Now.AddDays(-2),
			nowUtc: Now);
		Assert.Equal(0.0, score, 6);
		Assert.Equal(AttackThreatLevel.Green, AttackThreatScoring.ClassifyScore(score));
	}

	[Fact]
	public void LowIntensityFailures_LandInYellow()
	{
		// 40 failures over 1 hour → failure pressure = min(40, 20) = 20
		// intensity = min(20, 40/3600 * 1000) ≈ 11.11
		// recentness = 10 (last seen == now)
		// total ≈ 41.11 → Yellow.
		double score = AttackThreatScoring.ComputeScore(
			failed: 40,
			successful: 0,
			durationSeconds: 3600,
			isBlocked: false,
			lastSeenUtc: Now,
			nowUtc: Now);
		Assert.InRange(score, AttackThreatScoring.YellowThreshold, AttackThreatScoring.RedThreshold - 0.001);
		Assert.Equal(AttackThreatLevel.Yellow, AttackThreatScoring.ClassifyScore(score));
	}

	[Fact]
	public void HighIntensityBurst_ClassifiesRed()
	{
		// 200 failed attempts inside 10 seconds, currently blocked, last-seen now.
		// failure pressure = saturated 40
		// intensity = saturated 20
		// active block = 10
		// recentness = 10
		// total = 80 → Red.
		double score = AttackThreatScoring.ComputeScore(
			failed: 200,
			successful: 0,
			durationSeconds: 10,
			isBlocked: true,
			lastSeenUtc: Now,
			nowUtc: Now);
		Assert.Equal(80.0, score, 6);
		Assert.Equal(AttackThreatLevel.Red, AttackThreatScoring.ClassifyScore(score));
	}

	[Fact]
	public void SuccessAfterManyFailures_GetsBonusAndRed()
	{
		// 50 failed + 1 successful over 30 seconds, blocked.
		// failure pressure = min(40, 25) = 25
		// success-after-fail = 20
		// intensity = min(20, 50/30*1000=1666) → 20
		// active block = 10
		// recentness = 10
		// total = 85 → Red.
		double score = AttackThreatScoring.ComputeScore(
			failed: 50,
			successful: 1,
			durationSeconds: 30,
			isBlocked: true,
			lastSeenUtc: Now,
			nowUtc: Now);
		Assert.Equal(85.0, score, 6);
		Assert.Equal(AttackThreatLevel.Red, AttackThreatScoring.ClassifyScore(score));
	}

	[Fact]
	public void ScoreIsClampedToHundred()
	{
		// Pathological inputs must never push the score above 100.
		double score = AttackThreatScoring.ComputeScore(
			failed: long.MaxValue / 2,
			successful: 1,
			durationSeconds: 1,
			isBlocked: true,
			lastSeenUtc: Now,
			nowUtc: Now);
		Assert.Equal(100.0, score);
		Assert.Equal(AttackThreatLevel.Red, AttackThreatScoring.ClassifyScore(score));
	}

	[Fact]
	public void NegativeFailures_AreTreatedAsZero()
	{
		// Defensive: a malformed counter must not produce a negative score component.
		double score = AttackThreatScoring.ComputeScore(
			failed: -5,
			successful: 0,
			durationSeconds: 60,
			isBlocked: false,
			lastSeenUtc: Now,
			nowUtc: Now);
		Assert.Equal(10.0, score, 6); // recentness only
	}

	[Fact]
	public void RecentnessBuckets_AreThreeStep()
	{
		Assert.Equal(10.0, AttackThreatScoring.ComputeRecentnessBonus(Now.AddMinutes(-30), Now));
		Assert.Equal(5.0, AttackThreatScoring.ComputeRecentnessBonus(Now.AddHours(-12), Now));
		Assert.Equal(0.0, AttackThreatScoring.ComputeRecentnessBonus(Now.AddDays(-3), Now));
	}

	[Fact]
	public void ClockSkew_LastSeenInFuture_TreatedAsRecent()
	{
		Assert.Equal(10.0, AttackThreatScoring.ComputeRecentnessBonus(Now.AddMinutes(5), Now));
	}

	[Theory]
	[InlineData(0.0, AttackThreatLevel.Green)]
	[InlineData(29.99, AttackThreatLevel.Green)]
	[InlineData(30.0, AttackThreatLevel.Yellow)]
	[InlineData(50.0, AttackThreatLevel.Yellow)]
	[InlineData(69.99, AttackThreatLevel.Yellow)]
	[InlineData(70.0, AttackThreatLevel.Red)]
	[InlineData(100.0, AttackThreatLevel.Red)]
	public void Classification_BoundsAreInclusiveOnLowerEdge(double score, AttackThreatLevel expected)
	{
		Assert.Equal(expected, AttackThreatScoring.ClassifyScore(score));
	}
}
