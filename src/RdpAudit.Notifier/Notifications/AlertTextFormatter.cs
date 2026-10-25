// File:    src/RdpAudit.Notifier/Notifications/AlertTextFormatter.cs
// Module:  RdpAudit.Notifier.Notifications
// Purpose: Shared alert text shaping used by every sink so balloon tips and native WinRT
//          toasts render the same title and body for the same alert.
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using RdpAudit.Core.Models;

namespace RdpAudit.Notifier.Notifications;

/// <summary>Shapes the visible text of alerts and the aggregate notice.</summary>
public static class AlertTextFormatter
{
	/// <summary>Title used for the aggregate (throttled surplus) notice.</summary>
	public const string AggregateTitle = "RdpAudit";

	/// <summary>Toast title: product name plus alert severity.</summary>
	public static string Title(Alert alert) => "RdpAudit " + alert.Severity;

	/// <summary>Toast body: message plus optional IP / user lines.</summary>
	public static string Body(Alert alert)
	{
		string text = alert.Message;
		if (!string.IsNullOrWhiteSpace(alert.SourceIp))
		{
			text += "\nIP: " + alert.SourceIp;
		}

		if (!string.IsNullOrWhiteSpace(alert.UserName))
		{
			text += "\nUser: " + alert.UserName;
		}

		return text;
	}

	/// <summary>Body used for the aggregate notice about throttled alerts.</summary>
	public static string AggregateBody(int throttledCount)
		=> throttledCount + " more alert(s) suppressed by the toast rate limit.";
}
