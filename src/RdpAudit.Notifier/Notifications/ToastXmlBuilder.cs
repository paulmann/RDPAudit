// File:    src/RdpAudit.Notifier/Notifications/ToastXmlBuilder.cs
// Module:  RdpAudit.Notifier.Notifications
// Purpose: XML payload construction for native WinRT toasts (Windows.UI.Notifications
//          expects a Windows.Data.Xml.Dom.XmlDocument built from the toast template
//          provided by ToastNotificationManager.GetTemplateContent). This builder stays
//          WinRT-free so the markup is unit-testable; the native sender re-parses the
//          produced markup into the WinRT DOM before showing it.
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System.Xml;
using RdpAudit.Core.Models;

namespace RdpAudit.Notifier.Notifications;

/// <summary>Constructs the XML markup of a native toast without referencing WinRT.</summary>
public static class ToastXmlBuilder
{
	private const string Template =
		"<toast launch=\"\"><visual><binding template=\"ToastGeneric\"><text id=\"1\"/><text id=\"2\"/></binding></visual></toast>";

	/// <summary>Builds a toast XML document for one alert using the shared text formatter.</summary>
	public static XmlDocument Build(Alert alert)
		=> Build(AlertTextFormatter.Title(alert), AlertTextFormatter.Body(alert));

	/// <summary>Builds a toast XML document with the given title and body.</summary>
	public static XmlDocument Build(string title, string body)
	{
		XmlDocument doc = new();
		doc.LoadXml(Template);
		XmlNodeList texts = doc.GetElementsByTagName("text");
		texts[0]!.AppendChild(doc.CreateTextNode(title));
		texts[1]!.AppendChild(doc.CreateTextNode(body));
		return doc;
	}
}
