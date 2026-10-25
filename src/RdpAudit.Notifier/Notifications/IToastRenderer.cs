// File:    src/RdpAudit.Notifier/Notifications/IToastRenderer.cs
// Module:  RdpAudit.Notifier.Notifications
// Purpose: Narrow contract for the native (WinRT) toast channel. The tray sink routes a
//          notification to this channel when the operator prefers native toasts, and falls
//          back to the balloon tip when the channel is unavailable or fails.
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using RdpAudit.Core.Models;

namespace RdpAudit.Notifier.Notifications;

/// <summary>Renders notifications through the native toast channel.</summary>
public interface IToastRenderer
{
	/// <summary>True when the native channel can currently display toasts.</summary>
	bool IsAvailable { get; }

	/// <summary>Shows one alert. Returns true when the toast was handed to the OS.</summary>
	bool Show(Alert alert);

	/// <summary>Shows one aggregate toast for throttled alerts. Returns true on success.</summary>
	bool ShowAggregate(int throttledCount);
}
