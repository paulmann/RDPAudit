// Locks the poll backoff curve: reset, doubling, cap and clamping.
using RdpAudit.Notifier.Notifications;
using Xunit;

namespace RdpAudit.Notifier.Tests;

public class PollBackoffPolicyTests
{
	[Fact]
	public void Constructor_ClampsHealthyInterval()
	{
		Assert.Equal(1, new PollBackoffPolicy(0).CurrentDelaySeconds);
		Assert.Equal(60, new PollBackoffPolicy(90).CurrentDelaySeconds);
	}

	[Fact]
	public void OnUnhealthy_DoublesDelay()
	{
		PollBackoffPolicy policy = new(5);
		policy.OnUnhealthy();
		Assert.Equal(10, policy.CurrentDelaySeconds);
		policy.OnUnhealthy();
		Assert.Equal(20, policy.CurrentDelaySeconds);
	}

	[Fact]
	public void OnUnhealthy_CapsAtMaxBackoffSeconds()
	{
		PollBackoffPolicy policy = new(40);
		policy.OnUnhealthy();
		Assert.Equal(60, policy.CurrentDelaySeconds);
		policy.OnUnhealthy();
		Assert.Equal(60, policy.CurrentDelaySeconds);
	}

	[Fact]
	public void OnHealthy_ResetsToConfiguredInterval()
	{
		PollBackoffPolicy policy = new(5);
		policy.OnUnhealthy();
		policy.OnUnhealthy();
		policy.OnHealthy(7);
		Assert.Equal(7, policy.CurrentDelaySeconds);
	}

	[Fact]
	public void OnHealthy_ClampsConfiguredInterval()
	{
		PollBackoffPolicy policy = new(5);
		policy.OnUnhealthy();
		policy.OnHealthy(0);
		Assert.Equal(1, policy.CurrentDelaySeconds);
	}
}
