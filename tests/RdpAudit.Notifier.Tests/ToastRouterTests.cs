// Router behaviour: native channel selected when preferred and available,
// per-item fallback to balloon when the native path fails.
using RdpAudit.Core.Models;
using RdpAudit.Notifier.Notifications;
using Xunit;

namespace RdpAudit.Notifier.Tests;

public class ToastRouterTests
{
	[Fact]
	public void NativePreferredAndAvailable_RoutesToNative()
	{
		FakeToastRenderer native = new();
		FakeNotificationSink balloon = new();
		ToastRouter router = new(native, balloon) { PreferNativeToasts = true };

		bool ok = router.Show(AlertFactory.Alert(1));

		Assert.True(ok);
		Assert.Equal([1L], native.Shown);
		Assert.Empty(balloon.Shown);
	}

	[Fact]
	public void NativeUnavailable_FallsBackToBalloon()
	{
		FakeToastRenderer native = new() { Available = false };
		FakeNotificationSink balloon = new();
		ToastRouter router = new(native, balloon) { PreferNativeToasts = true };

		router.Show(AlertFactory.Alert(1));

		Assert.Empty(native.Shown);
		Assert.Equal([1L], balloon.Shown);
	}

	[Fact]
	public void NativeShowFails_FallsBackToBalloon()
	{
		FakeToastRenderer native = new() { ShowResult = false };
		FakeNotificationSink balloon = new();
		ToastRouter router = new(native, balloon) { PreferNativeToasts = true };

		router.Show(AlertFactory.Alert(1));

		Assert.Equal([1L], balloon.Shown);
	}

	[Fact]
	public void AggregateFallback_WhenNativeFails()
	{
		FakeToastRenderer native = new() { ShowResult = false };
		FakeNotificationSink balloon = new();
		ToastRouter router = new(native, balloon) { PreferNativeToasts = true };

		router.ShowAggregate(3);

		Assert.Equal([3], balloon.Aggregates);
	}
}
