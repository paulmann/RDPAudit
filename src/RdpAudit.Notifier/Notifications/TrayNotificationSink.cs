// File:    src/RdpAudit.Notifier/Notifications/TrayNotificationSink.cs
// Module:  RdpAudit.Notifier.Notifications
// Purpose: Production INotificationSink rendering balloon tips through the tray NotifyIcon.
//          Windows-only by design; the sink itself stays UI-free so it is testable.
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System.Runtime.Versioning;
using RdpAudit.Core.Models;

namespace RdpAudit.Notifier.Notifications;

/// <summary>Balloon-tip renderer backed by the tray icon.</summary>
[SupportedOSPlatform("windows")]
public sealed class TrayNotificationSink(NotifyIcon icon) : INotificationSink
{
	/// <summary>Unused by the balloon fallback; kept for interface symmetry.</summary>
	public bool PreferNativeToasts { get; set; }

	public bool Show(Alert alert)
	{
		if (!icon.Visible)
		{
			return false;
		}

		icon.ShowBalloonTip(
			5000,
			AlertTextFormatter.Title(alert),
			AlertTextFormatter.Body(alert),
			ToolTipIcon.Warning);
		return true;
	}

	public void ShowAggregate(int throttledCount)
	{
		if (!icon.Visible)
		{
			return;
		}

		icon.ShowBalloonTip(
			5000,
			AlertTextFormatter.AggregateTitle,
			AlertTextFormatter.AggregateBody(throttledCount),
			ToolTipIcon.Info);
	}
}
