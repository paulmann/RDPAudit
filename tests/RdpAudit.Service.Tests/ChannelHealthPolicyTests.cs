// File:    tests/RdpAudit.Service.Tests/ChannelHealthPolicyTests.cs
// Module:  RdpAudit.Service.Tests
// Purpose: Stage 2 unit tests for ChannelHealthPolicy — covers first-failure bookmark-reset,
//          cooldown, disable-after-saturation, optional vs critical classification, and the
//          recovery path after a successful restart.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using RdpAudit.Service.Collectors;
using Xunit;

namespace RdpAudit.Service.Tests;

public class ChannelHealthPolicyTests
{
	private const string GatewayChannel = "Microsoft-Windows-TerminalServices-Gateway/Operational";
	private const string SecurityChannel = "Security";

	private sealed class FakeClock
	{
		public DateTime Now { get; set; } = new DateTime(2026, 1, 1, 0, 0, 0, DateTimeKind.Utc);

		public DateTime Read() => Now;

		public void Advance(TimeSpan delta) => Now += delta;
	}

	private static ChannelHealthPolicy NewPolicy(FakeClock clock)
		=> new ChannelHealthPolicy(clock.Read, ChannelHealthPolicy.DefaultOptionalChannels);

	[Fact]
	public void GatewayChannel_IsClassifiedAsOptional()
	{
		FakeClock clock = new();
		ChannelHealthPolicy policy = NewPolicy(clock);
		Assert.Equal(ChannelImportance.Optional, policy.ClassifyChannel(GatewayChannel));
	}

	[Fact]
	public void SecurityChannel_IsClassifiedAsCritical()
	{
		FakeClock clock = new();
		ChannelHealthPolicy policy = NewPolicy(clock);
		Assert.Equal(ChannelImportance.Critical, policy.ClassifyChannel(SecurityChannel));
	}

	[Fact]
	public void FirstInvalidHandle_ReturnsResetBookmarkAndRestart()
	{
		FakeClock clock = new();
		ChannelHealthPolicy policy = NewPolicy(clock);

		ChannelHealthOutcome outcome = policy.ReportFailure(SecurityChannel, isInvalidHandleLike: true);

		Assert.Equal(ChannelDecision.ResetBookmarkAndRestart, outcome.Decision);
		Assert.Equal(1, policy.ConsecutiveFailures(SecurityChannel));
	}

	[Fact]
	public void SecondInvalidHandle_AfterResetTried_ReturnsCooldown()
	{
		FakeClock clock = new();
		ChannelHealthPolicy policy = NewPolicy(clock);

		policy.ReportFailure(SecurityChannel, isInvalidHandleLike: true);
		ChannelHealthOutcome second = policy.ReportFailure(SecurityChannel, isInvalidHandleLike: true);

		Assert.Equal(ChannelDecision.Cooldown, second.Decision);
		Assert.NotNull(policy.NextAllowedRestartUtc(SecurityChannel));
	}

	[Fact]
	public void GatewayChannel_RepeatedInvalidHandle_DisablesQuietly()
	{
		FakeClock clock = new();
		ChannelHealthPolicy policy = NewPolicy(clock);

		// First failure → bookmark reset
		policy.ReportFailure(GatewayChannel, isInvalidHandleLike: true);
		// Drive to disable
		for (int i = 0; i < ChannelHealthPolicy.MaxConsecutiveFailures; i++)
		{
			ChannelHealthOutcome o = policy.ReportFailure(GatewayChannel, isInvalidHandleLike: true);
			if (o.Decision == ChannelDecision.DisablePermanently)
			{
				Assert.True(policy.IsDisabled(GatewayChannel));
				return;
			}
		}

		Assert.Fail("Channel was not disabled after saturating failure burst");
	}

	[Fact]
	public void Cooldown_NextAllowedRestartUtc_IsAtLeastTwoMinutesAhead()
	{
		FakeClock clock = new();
		ChannelHealthPolicy policy = NewPolicy(clock);

		policy.ReportFailure(SecurityChannel, isInvalidHandleLike: true);
		policy.ReportFailure(SecurityChannel, isInvalidHandleLike: true);

		DateTime? next = policy.NextAllowedRestartUtc(SecurityChannel);
		Assert.NotNull(next);
		Assert.True(next!.Value - clock.Now >= TimeSpan.FromMinutes(2) - TimeSpan.FromSeconds(1));
	}

	[Fact]
	public void ReportSuccess_ClearsFailureState()
	{
		FakeClock clock = new();
		ChannelHealthPolicy policy = NewPolicy(clock);

		policy.ReportFailure(SecurityChannel, isInvalidHandleLike: true);
		policy.ReportFailure(SecurityChannel, isInvalidHandleLike: true);
		Assert.Equal(2, policy.ConsecutiveFailures(SecurityChannel));

		policy.ReportSuccess(SecurityChannel);

		Assert.Equal(0, policy.ConsecutiveFailures(SecurityChannel));
		Assert.False(policy.IsDisabled(SecurityChannel));
		Assert.Null(policy.NextAllowedRestartUtc(SecurityChannel));
	}

	[Fact]
	public void FailureWindowExpiry_ResetsConsecutiveCount()
	{
		FakeClock clock = new();
		ChannelHealthPolicy policy = NewPolicy(clock);

		policy.ReportFailure(SecurityChannel, isInvalidHandleLike: true); // ResetBookmarkAndRestart
		policy.ReportFailure(SecurityChannel, isInvalidHandleLike: true); // Cooldown

		clock.Advance(ChannelHealthPolicy.FailureWindow + TimeSpan.FromMinutes(1));

		ChannelHealthOutcome next = policy.ReportFailure(SecurityChannel, isInvalidHandleLike: true);

		// Window expired → policy resets, so this is treated as the first failure again →
		// BookmarkResetTried got reset, so we should once again propose a bookmark reset.
		Assert.Equal(ChannelDecision.ResetBookmarkAndRestart, next.Decision);
		Assert.Equal(1, policy.ConsecutiveFailures(SecurityChannel));
	}

	[Fact]
	public void NonInvalidHandleFailure_DoesNotTriggerBookmarkReset()
	{
		FakeClock clock = new();
		ChannelHealthPolicy policy = NewPolicy(clock);

		ChannelHealthOutcome outcome = policy.ReportFailure(SecurityChannel, isInvalidHandleLike: false);

		// Without invalid-handle hint, first failure goes straight to cooldown.
		Assert.Equal(ChannelDecision.Cooldown, outcome.Decision);
	}

	[Fact]
	public void ReportUnavailable_DisablesChannel()
	{
		FakeClock clock = new();
		ChannelHealthPolicy policy = NewPolicy(clock);

		ChannelHealthOutcome outcome = policy.ReportUnavailable(GatewayChannel, "Channel not found");

		Assert.Equal(ChannelDecision.SkipUnavailable, outcome.Decision);
		Assert.True(policy.IsDisabled(GatewayChannel));
	}

	[Fact]
	public void DisabledChannel_FurtherFailures_StayDisabled()
	{
		FakeClock clock = new();
		ChannelHealthPolicy policy = NewPolicy(clock);

		policy.ReportUnavailable(GatewayChannel, "not found");
		ChannelHealthOutcome again = policy.ReportFailure(GatewayChannel, isInvalidHandleLike: true);

		Assert.Equal(ChannelDecision.DisablePermanently, again.Decision);
		Assert.True(policy.IsDisabled(GatewayChannel));
	}

	[Fact]
	public void SecurityChannel_InvalidHandleThenSuccess_ResetsForFutureRecovery()
	{
		FakeClock clock = new();
		ChannelHealthPolicy policy = NewPolicy(clock);

		ChannelHealthOutcome first = policy.ReportFailure(SecurityChannel, isInvalidHandleLike: true);
		Assert.Equal(ChannelDecision.ResetBookmarkAndRestart, first.Decision);

		policy.ReportSuccess(SecurityChannel);

		// Future invalid-handle should again propose a single bookmark reset.
		ChannelHealthOutcome later = policy.ReportFailure(SecurityChannel, isInvalidHandleLike: true);
		Assert.Equal(ChannelDecision.ResetBookmarkAndRestart, later.Decision);
	}
}
