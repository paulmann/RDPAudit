// File:    src/RdpAudit.Notifier/Notifications/ToastRouter.cs
// Module:  RdpAudit.Notifier.Notifications
// Purpose: INotificationSink router between the native WinRT channel and the balloon-tip
//          fallback. When the poller prefers native toasts, each item first goes to the
//          native renderer; an unavailable or failing native channel fails over to balloon.
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using RdpAudit.Core.Models;

namespace RdpAudit.Notifier.Notifications;

/// <summary>Routes notifications to the native toast channel with a balloon fallback.</summary>
public sealed class ToastRouter(IToastRenderer native, INotificationSink fallback) : INotificationSink
{
	/// <inheritdoc/>
	public bool PreferNativeToasts { get; set; }

	public bool Show(Alert alert)
	{
		if (PreferNativeToasts && native.IsAvailable && native.Show(alert))
		{
			return true;
		}

		return fallback.Show(alert);
	}

	public void ShowAggregate(int throttledCount)
	{
		if (PreferNativeToasts && native.IsAvailable && native.ShowAggregate(throttledCount))
		{
			return;
		}

		fallback.ShowAggregate(throttledCount);
	}
}
