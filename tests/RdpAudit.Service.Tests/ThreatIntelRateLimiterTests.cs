// File:    tests/RdpAudit.Service.Tests/ThreatIntelRateLimiterTests.cs
// Module:  RdpAudit.Service.Tests
// Purpose: Unit tests for the Backlog #5 ThreatIntelRateLimiter: the fixed per-minute window,
//          window reset, the daily budget gate and the clamp behaviour for invalid options.
//          Driven entirely by a fake TimeProvider so windows can be moved deterministically.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using RdpAudit.Core.Config;
using RdpAudit.Service.ThreatIntel;
using Xunit;

namespace RdpAudit.Service.Tests;

public class ThreatIntelRateLimiterTests
{
	private sealed class FakeTimeProvider : TimeProvider
	{
		private DateTimeOffset _now;

		public FakeTimeProvider(DateTimeOffset now) => _now = now;

		public override DateTimeOffset GetUtcNow() => _now;

		public void Advance(TimeSpan delta) => _now = _now.Add(delta);
	}

	private static AbuseIpDbOptions DefaultOptions() => new()
	{
		CheckMaxLookupsPerMinute = 3,
		CheckMaxLookupsPerDay = 500,
		CheckMaxAgeInDays = 30,
	};

	[Fact]
	public void CanLookup_AllowsUpToPerMinuteCap_ThenBlocks()
	{
		FakeTimeProvider time = new(new DateTimeOffset(2026, 9, 12, 10, 0, 0, TimeSpan.Zero));
		ThreatIntelRateLimiter limiter = new(time);
		AbuseIpDbOptions options = DefaultOptions();

		Assert.True(limiter.CanLookup(options, dailyCount: 0));
		limiter.RecordLookup();
		Assert.True(limiter.CanLookup(options, dailyCount: 0));
		limiter.RecordLookup();
		Assert.True(limiter.CanLookup(options, dailyCount: 0));
		limiter.RecordLookup();
		Assert.False(limiter.CanLookup(options, dailyCount: 0));
	}

	[Fact]
	public void CanLookup_WindowResets_AfterOneMinute()
	{
		FakeTimeProvider time = new(new DateTimeOffset(2026, 9, 12, 10, 0, 0, TimeSpan.Zero));
		ThreatIntelRateLimiter limiter = new(time);
		AbuseIpDbOptions options = DefaultOptions();

		Assert.True(limiter.CanLookup(options, dailyCount: 0));
		limiter.RecordLookup();
		Assert.True(limiter.CanLookup(options, dailyCount: 0));
		limiter.RecordLookup();
		Assert.True(limiter.CanLookup(options, dailyCount: 0));
		limiter.RecordLookup();
		Assert.False(limiter.CanLookup(options, dailyCount: 0));

		time.Advance(TimeSpan.FromSeconds(61));
		Assert.True(limiter.CanLookup(options, dailyCount: 0));
	}

	[Fact]
	public void CanLookup_DailyBudget_BlocksEvenWhenMinuteWindowIsFree()
	{
		FakeTimeProvider time = new(new DateTimeOffset(2026, 9, 12, 10, 0, 0, TimeSpan.Zero));
		ThreatIntelRateLimiter limiter = new(time);
		AbuseIpDbOptions options = DefaultOptions();

		Assert.False(limiter.CanLookup(options, dailyCount: 500));
		Assert.False(limiter.CanLookup(options, dailyCount: 999));
	}

	[Fact]
	public void CanLookup_ClampsCaps_FromOutOfRangeOptions()
	{
		FakeTimeProvider time = new(new DateTimeOffset(2026, 9, 12, 10, 0, 0, TimeSpan.Zero));
		ThreatIntelRateLimiter limiter = new(time);
		AbuseIpDbOptions options = new()
		{
			CheckMaxLookupsPerMinute = 0,
			CheckMaxLookupsPerDay = 0,
		};

		// Clamped to 1 per minute / 1 per day.
		Assert.True(limiter.CanLookup(options, dailyCount: 0));
		Assert.False(limiter.CanLookup(options, dailyCount: 1));
	}

	[Fact]
	public void CanLookup_NegativeDailyCount_TreatedAsExhaustedBudget()
	{
		FakeTimeProvider time = new(new DateTimeOffset(2026, 9, 12, 10, 0, 0, TimeSpan.Zero));
		ThreatIntelRateLimiter limiter = new(time);
		AbuseIpDbOptions options = DefaultOptions();

		Assert.False(limiter.CanLookup(options, dailyCount: -1));
	}

	[Fact]
	public void TodayKey_IsIsoUtcDate()
	{
		FakeTimeProvider time = new(new DateTimeOffset(2026, 3, 7, 23, 59, 0, TimeSpan.Zero));
		ThreatIntelRateLimiter limiter = new(time);

		Assert.Equal("2026-03-07", limiter.TodayKey());
	}
}
