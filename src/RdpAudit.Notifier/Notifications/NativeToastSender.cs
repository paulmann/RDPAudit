// File:    src/RdpAudit.Notifier/Notifications/NativeToastSender.cs
// Module:  RdpAudit.Notifier.Notifications
// Purpose: Real WinRT toast renderer; every method degrades to false instead of throwing.

using System.Runtime.Versioning;
using RdpAudit.Core.Models;
using Windows.Data.Xml.Dom;
using Windows.UI.Notifications;

namespace RdpAudit.Notifier.Notifications;

/// <summary>WinRT toast sender for the unpackaged notifier.</summary>
[SupportedOSPlatform("windows10.0.19041.0")]
public sealed class NativeToastSender : IToastRenderer
{
	public bool IsAvailable
	{
		get
		{
			try
			{
				return ToastAppRegistration.IsRegistered()
					&& ToastNotificationManager.CreateToastNotifier(ToastAppRegistration.AppUserModelId).Setting
					== NotificationSetting.Enabled;
			}
			catch
			{
				return false;
			}
		}
	}

	public bool Show(Alert alert)
		=> TryShow(AlertTextFormatter.Title(alert), AlertTextFormatter.Body(alert), "alert-" + alert.Id);

	public bool ShowAggregate(int throttledCount)
		=> TryShow(AlertTextFormatter.AggregateTitle, AlertTextFormatter.AggregateBody(throttledCount), "aggregate");

	private bool TryShow(string title, string body, string tag)
	{
		try
		{
			XmlDocument xml = new();
			xml.LoadXml(ToastXmlBuilder.Build(title, body).OuterXml);
			ToastNotification toast = new(xml) { Tag = tag, Group = "rdpaudit" };
			ToastNotificationManager.CreateToastNotifier(ToastAppRegistration.AppUserModelId).Show(toast);
			return true;
		}
		catch
		{
			return false;
		}
	}
}
