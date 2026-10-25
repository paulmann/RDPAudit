// File:    src/RdpAudit.Notifier/Notifications/INotificationSink.cs
// Module:  RdpAudit.Notifier.Notifications
// Purpose: Abstraction over toast rendering so the polling coordinator can be unit-tested
//          without a tray icon or MessageBox. Production sink shows balloon tips via NotifyIcon.
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using RdpAudit.Core.Models;

namespace RdpAudit.Notifier.Notifications;

/// <summary>Renders alert notifications for the operator.</summary>
public interface INotificationSink
{
	/// <summary>When true the sink prefers native WinRT toasts over balloon tips.
	/// Set by the poller from the effective policy.</summary>
	bool PreferNativeToasts { get; set; }
	/// <summary>Shows one alert toast. Returns true when the toast was rendered.</summary>
	bool Show(Alert alert);

	/// <summary>Shows one aggregate toast for throttled alerts.</summary>
	void ShowAggregate(int throttledCount);
}
