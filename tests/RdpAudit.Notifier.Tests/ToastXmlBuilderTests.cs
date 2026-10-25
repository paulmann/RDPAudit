// XML builder locks the native toast payload shape and escaping.
using System.Xml;
using RdpAudit.Notifier.Notifications;
using Xunit;

namespace RdpAudit.Notifier.Tests;

public class ToastXmlBuilderTests
{
	[Fact]
	public void Build_ReturnsWellFormedGenericToast()
	{
		XmlDocument xml = ToastXmlBuilder.Build("T", "B");
		Assert.Equal("toast", xml.DocumentElement!.Name);
		XmlElement binding = (XmlElement)xml.DocumentElement.SelectSingleNode("visual/binding")!;
		Assert.Equal("ToastGeneric", binding.GetAttribute("template"));
		Assert.Equal(2, binding.GetElementsByTagName("text").Count);
	}

	[Fact]
	public void Build_PreservesTitleAndBodyOrder()
	{
		XmlDocument xml = ToastXmlBuilder.Build("T", "B");
		XmlNodeList texts = xml.GetElementsByTagName("text");
		Assert.Equal("T", texts[0]!.InnerText);
		Assert.Equal("B", texts[1]!.InnerText);
	}

	[Fact]
	public void Build_EscapesMarkupInTitle()
	{
		XmlDocument xml = ToastXmlBuilder.Build("<b>alert</b>", "body");
		Assert.DoesNotContain("<b>", xml.OuterXml);
		Assert.Contains("&lt;", xml.OuterXml);
	}

	[Fact]
	public void Build_ComposesAlertViaFormatter()
	{
		XmlDocument xml = ToastXmlBuilder.Build(AlertFactory.Alert(7));
		Assert.Equal("RdpAudit High", xml.GetElementsByTagName("text")[0]!.InnerText);
	}
}
