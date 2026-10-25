// Locks tray tooltip text shaping.
using RdpAudit.Notifier.Notifications;
using Xunit;

namespace RdpAudit.Notifier.Tests;

public class TrayStatusTextTests
{
	[Fact]
	public void Reachable_ReturnsBaseTitle()
		=> Assert.Equal(TrayStatusText.Healthy, TrayStatusText.For(true, 5));

	[Fact]
	public void Unreachable_ReportsRetryDelay()
		=> Assert.Contains("service unreachable, retry in 20s", TrayStatusText.For(false, 20));
}
