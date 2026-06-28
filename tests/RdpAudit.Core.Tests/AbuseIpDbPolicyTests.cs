// File:    tests/RdpAudit.Core.Tests/AbuseIpDbPolicyTests.cs
// Module:  RdpAudit.Core.Tests
// Purpose: Unit tests for the Stage 8 AbuseIpDb policy decision. Validates whitelist precedence,
//          threshold gating, dedup window and hourly / daily rate-limit caps.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using RdpAudit.Core.AbuseIpDb;
using RdpAudit.Core.Config;
using Xunit;

namespace RdpAudit.Core.Tests;

/// <summary>Unit tests for <see cref="AbuseIpDbPolicy.Decide"/>.</summary>
public class AbuseIpDbPolicyTests
{
	private static AbuseIpDbOptions Opts() => new()
	{
		Enabled = true,
		ReportAttacks = true,
		ApiKey = "envelope",
		MinThreatScore = 50.0,
		MinFailedAttempts = 5,
		MaxReportsPerHour = 10,
		MaxReportsPerDay = 30,
		DeduplicationWindowMinutes = 15,
	};

	[Fact]
	public void Decide_ReportsHighThreatPublicIp()
	{
		AbuseIpDbReportDecision d = AbuseIpDbPolicy.Decide(
			Opts(), hasApiKey: true, ip: "203.0.113.10", threatScore: 80, failedAttempts: 30,
			isWhitelisted: false, lastReportUtc: null, reportsInHour: 0, reportsInDay: 0,
			nowUtc: DateTime.UtcNow);

		Assert.True(d.ShouldReport);
		Assert.Equal(AbuseIpDbSuppressionReason.None, d.Reason);
	}

	[Fact]
	public void Decide_ReportingDisabled_Suppresses()
	{
		AbuseIpDbOptions opts = Opts();
		opts.ReportAttacks = false;
		AbuseIpDbReportDecision d = AbuseIpDbPolicy.Decide(
			opts, hasApiKey: true, ip: "203.0.113.10", threatScore: 99, failedAttempts: 99,
			isWhitelisted: false, lastReportUtc: null, reportsInHour: 0, reportsInDay: 0,
			nowUtc: DateTime.UtcNow);

		Assert.False(d.ShouldReport);
		Assert.Equal(AbuseIpDbSuppressionReason.ReportingDisabled, d.Reason);
	}

	[Fact]
	public void Decide_NoApiKey_Suppresses()
	{
		AbuseIpDbReportDecision d = AbuseIpDbPolicy.Decide(
			Opts(), hasApiKey: false, ip: "203.0.113.10", threatScore: 99, failedAttempts: 99,
			isWhitelisted: false, lastReportUtc: null, reportsInHour: 0, reportsInDay: 0,
			nowUtc: DateTime.UtcNow);

		Assert.False(d.ShouldReport);
		Assert.Equal(AbuseIpDbSuppressionReason.NoApiKey, d.Reason);
	}

	[Fact]
	public void Decide_PrivateIp_Suppresses()
	{
		AbuseIpDbReportDecision d = AbuseIpDbPolicy.Decide(
			Opts(), hasApiKey: true, ip: "10.0.0.1", threatScore: 99, failedAttempts: 99,
			isWhitelisted: false, lastReportUtc: null, reportsInHour: 0, reportsInDay: 0,
			nowUtc: DateTime.UtcNow);

		Assert.False(d.ShouldReport);
		Assert.Equal(AbuseIpDbSuppressionReason.NotPublicIp, d.Reason);
	}

	[Fact]
	public void Decide_Whitelisted_Suppresses()
	{
		AbuseIpDbReportDecision d = AbuseIpDbPolicy.Decide(
			Opts(), hasApiKey: true, ip: "203.0.113.10", threatScore: 99, failedAttempts: 99,
			isWhitelisted: true, lastReportUtc: null, reportsInHour: 0, reportsInDay: 0,
			nowUtc: DateTime.UtcNow);

		Assert.False(d.ShouldReport);
		Assert.Equal(AbuseIpDbSuppressionReason.Whitelisted, d.Reason);
	}

	[Fact]
	public void Decide_BelowThreatScore_Suppresses()
	{
		AbuseIpDbReportDecision d = AbuseIpDbPolicy.Decide(
			Opts(), hasApiKey: true, ip: "203.0.113.10", threatScore: 30, failedAttempts: 99,
			isWhitelisted: false, lastReportUtc: null, reportsInHour: 0, reportsInDay: 0,
			nowUtc: DateTime.UtcNow);

		Assert.False(d.ShouldReport);
		Assert.Equal(AbuseIpDbSuppressionReason.BelowThreatScore, d.Reason);
	}

	[Fact]
	public void Decide_BelowFailedAttempts_Suppresses()
	{
		AbuseIpDbReportDecision d = AbuseIpDbPolicy.Decide(
			Opts(), hasApiKey: true, ip: "203.0.113.10", threatScore: 99, failedAttempts: 2,
			isWhitelisted: false, lastReportUtc: null, reportsInHour: 0, reportsInDay: 0,
			nowUtc: DateTime.UtcNow);

		Assert.False(d.ShouldReport);
		Assert.Equal(AbuseIpDbSuppressionReason.BelowFailedAttempts, d.Reason);
	}

	[Fact]
	public void Decide_WithinDedupWindow_Suppresses()
	{
		DateTime now = DateTime.UtcNow;
		AbuseIpDbReportDecision d = AbuseIpDbPolicy.Decide(
			Opts(), hasApiKey: true, ip: "203.0.113.10", threatScore: 99, failedAttempts: 99,
			isWhitelisted: false, lastReportUtc: now - TimeSpan.FromMinutes(5),
			reportsInHour: 0, reportsInDay: 0, nowUtc: now);

		Assert.False(d.ShouldReport);
		Assert.Equal(AbuseIpDbSuppressionReason.WithinDedupWindow, d.Reason);
	}

	[Fact]
	public void Decide_AfterDedupWindow_Reports()
	{
		DateTime now = DateTime.UtcNow;
		AbuseIpDbReportDecision d = AbuseIpDbPolicy.Decide(
			Opts(), hasApiKey: true, ip: "203.0.113.10", threatScore: 99, failedAttempts: 99,
			isWhitelisted: false, lastReportUtc: now - TimeSpan.FromHours(2),
			reportsInHour: 0, reportsInDay: 0, nowUtc: now);

		Assert.True(d.ShouldReport);
	}

	[Fact]
	public void Decide_HourlyLimit_Suppresses()
	{
		AbuseIpDbReportDecision d = AbuseIpDbPolicy.Decide(
			Opts(), hasApiKey: true, ip: "203.0.113.10", threatScore: 99, failedAttempts: 99,
			isWhitelisted: false, lastReportUtc: null, reportsInHour: 10, reportsInDay: 0,
			nowUtc: DateTime.UtcNow);

		Assert.False(d.ShouldReport);
		Assert.Equal(AbuseIpDbSuppressionReason.HourlyLimitReached, d.Reason);
	}

	[Fact]
	public void Decide_DailyLimit_Suppresses()
	{
		AbuseIpDbReportDecision d = AbuseIpDbPolicy.Decide(
			Opts(), hasApiKey: true, ip: "203.0.113.10", threatScore: 99, failedAttempts: 99,
			isWhitelisted: false, lastReportUtc: null, reportsInHour: 0, reportsInDay: 30,
			nowUtc: DateTime.UtcNow);

		Assert.False(d.ShouldReport);
		Assert.Equal(AbuseIpDbSuppressionReason.DailyLimitReached, d.Reason);
	}

	[Fact]
	public void Decide_InvalidIp_Suppresses()
	{
		AbuseIpDbReportDecision d = AbuseIpDbPolicy.Decide(
			Opts(), hasApiKey: true, ip: "", threatScore: 99, failedAttempts: 99,
			isWhitelisted: false, lastReportUtc: null, reportsInHour: 0, reportsInDay: 0,
			nowUtc: DateTime.UtcNow);

		Assert.False(d.ShouldReport);
		Assert.Equal(AbuseIpDbSuppressionReason.InvalidIp, d.Reason);
	}

	[Fact]
	public void Decide_DedupMinimumIsFifteenMinutes()
	{
		AbuseIpDbOptions opts = Opts();
		opts.DeduplicationWindowMinutes = 1;
		DateTime now = DateTime.UtcNow;
		AbuseIpDbReportDecision d = AbuseIpDbPolicy.Decide(
			opts, hasApiKey: true, ip: "203.0.113.10", threatScore: 99, failedAttempts: 99,
			isWhitelisted: false, lastReportUtc: now - TimeSpan.FromMinutes(5),
			reportsInHour: 0, reportsInDay: 0, nowUtc: now);

		Assert.False(d.ShouldReport);
		Assert.Equal(AbuseIpDbSuppressionReason.WithinDedupWindow, d.Reason);
	}

	[Fact]
	public void Decide_DedupeEnabled_SuccessWithinCooldown_Suppresses()
	{
		AbuseIpDbOptions opts = Opts();
		opts.ReportDedupeEnabled = true;
		opts.ReportCooldownHours = 24;
		DateTime now = DateTime.UtcNow;

		AbuseIpDbReportDecision d = AbuseIpDbPolicy.Decide(
			opts, hasApiKey: true, ip: "203.0.113.10", threatScore: 99, failedAttempts: 99,
			isWhitelisted: false, lastReportUtc: now - TimeSpan.FromHours(2),
			reportsInHour: 0, reportsInDay: 0, nowUtc: now,
			lastSuccessfulReportUtc: now - TimeSpan.FromHours(2));

		Assert.False(d.ShouldReport);
		Assert.Equal(AbuseIpDbSuppressionReason.WithinReportCooldown, d.Reason);
	}

	[Fact]
	public void Decide_DedupeEnabled_SuccessAfterCooldown_Reports()
	{
		AbuseIpDbOptions opts = Opts();
		opts.ReportDedupeEnabled = true;
		opts.ReportCooldownHours = 24;
		DateTime now = DateTime.UtcNow;

		AbuseIpDbReportDecision d = AbuseIpDbPolicy.Decide(
			opts, hasApiKey: true, ip: "203.0.113.10", threatScore: 99, failedAttempts: 99,
			isWhitelisted: false, lastReportUtc: now - TimeSpan.FromHours(48),
			reportsInHour: 0, reportsInDay: 0, nowUtc: now,
			lastSuccessfulReportUtc: now - TimeSpan.FromHours(48));

		Assert.True(d.ShouldReport);
		Assert.Equal(AbuseIpDbSuppressionReason.None, d.Reason);
	}

	[Fact]
	public void Decide_DedupeEnabled_NoPriorSuccess_Reports()
	{
		// A failed-only history (lastSuccessfulReportUtc == null) must never suppress, even when
		// the dedupe cooldown is enabled. Only successful prior reports gate re-reporting.
		AbuseIpDbOptions opts = Opts();
		opts.ReportDedupeEnabled = true;
		opts.ReportCooldownHours = 24;
		DateTime now = DateTime.UtcNow;

		AbuseIpDbReportDecision d = AbuseIpDbPolicy.Decide(
			opts, hasApiKey: true, ip: "203.0.113.10", threatScore: 99, failedAttempts: 99,
			isWhitelisted: false, lastReportUtc: now - TimeSpan.FromHours(2),
			reportsInHour: 0, reportsInDay: 0, nowUtc: now,
			lastSuccessfulReportUtc: null);

		Assert.True(d.ShouldReport);
		Assert.Equal(AbuseIpDbSuppressionReason.None, d.Reason);
	}

	[Fact]
	public void Decide_DedupeDisabled_RecentSuccess_DoesNotApplyCooldown()
	{
		// With dedupe off the cooldown is never consulted; only the 15-minute floor applies.
		AbuseIpDbOptions opts = Opts();
		opts.ReportDedupeEnabled = false;
		opts.ReportCooldownHours = 24;
		DateTime now = DateTime.UtcNow;

		AbuseIpDbReportDecision d = AbuseIpDbPolicy.Decide(
			opts, hasApiKey: true, ip: "203.0.113.10", threatScore: 99, failedAttempts: 99,
			isWhitelisted: false, lastReportUtc: now - TimeSpan.FromHours(2),
			reportsInHour: 0, reportsInDay: 0, nowUtc: now,
			lastSuccessfulReportUtc: now - TimeSpan.FromHours(2));

		Assert.True(d.ShouldReport);
		Assert.Equal(AbuseIpDbSuppressionReason.None, d.Reason);
	}

	[Fact]
	public void Decide_DedupeEnabled_DedupWindowTakesPrecedence()
	{
		// The 15-minute floor is evaluated before the cooldown; a very recent attempt of any kind
		// surfaces WithinDedupWindow rather than WithinReportCooldown.
		AbuseIpDbOptions opts = Opts();
		opts.ReportDedupeEnabled = true;
		opts.ReportCooldownHours = 24;
		DateTime now = DateTime.UtcNow;

		AbuseIpDbReportDecision d = AbuseIpDbPolicy.Decide(
			opts, hasApiKey: true, ip: "203.0.113.10", threatScore: 99, failedAttempts: 99,
			isWhitelisted: false, lastReportUtc: now - TimeSpan.FromMinutes(5),
			reportsInHour: 0, reportsInDay: 0, nowUtc: now,
			lastSuccessfulReportUtc: now - TimeSpan.FromMinutes(5));

		Assert.False(d.ShouldReport);
		Assert.Equal(AbuseIpDbSuppressionReason.WithinDedupWindow, d.Reason);
	}

	[Fact]
	public void Defaults_DedupeOn_CooldownTwentyFourHours()
	{
		// Req 4: "1 report per 1 IP" is enabled by default with a 24-hour cooldown.
		AbuseIpDbOptions defaults = new();
		Assert.True(defaults.ReportDedupeEnabled);
		Assert.Equal(24, defaults.ReportCooldownHours);
	}
}
