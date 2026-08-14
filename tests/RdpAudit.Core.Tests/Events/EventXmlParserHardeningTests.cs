/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 2.0.3
// File   : EventXmlParserHardeningTests.cs
// Project: RdpAudit.Core.Tests (RdpAudit.Core.Tests.Events)
// Purpose: Verifies parser resource limits, XPath safety, and correlation field extraction.
// Depends: EventXmlParser, RawEventDto, XmlDocument, xUnit
// Extends: Add a red-team test whenever parser limits or event-specific field mappings change.

using System.Text;
using System.Xml;
using RdpAudit.Core.Events;
using Xunit;

namespace RdpAudit.Core.Tests.Events;

public sealed class EventXmlParserHardeningTests
{
	private const string Namespace = "http://schemas.microsoft.com/win/2004/08/events/event";

	[Fact]
	public void ParseSafe_RefusesOversizeAndDeepDocuments()
	{
		string oversize = "<Event xmlns='" + Namespace + "'><EventData><Data Name='X'>" + new string('x', (1024 * 1024) + 1) + "</Data></EventData></Event>";
		Assert.Null(EventXmlParser.ParseSafe(oversize));
		Assert.Null(EventXmlParser.ParseSafe(BuildNestedDocument(65)));
		Assert.NotNull(EventXmlParser.ParseSafe(BuildNestedDocument(64)));
	}

	[Fact]
	public void GetData_RefusesUnsafeNamesAndOversizeFields()
	{
		string huge = new('x', (4 * 1024) + 1);
		XmlDocument? document = EventXmlParser.ParseSafe("<Event xmlns='" + Namespace + "'><EventData><Data Name='IpAddress'>" + huge + "</Data></EventData></Event>");

		Assert.NotNull(document);
		Assert.Null(EventXmlParser.GetData(document, "Ip']|//*[local-name()='Data"));
		Assert.Null(EventXmlParser.GetData(document, "field with spaces"));
		Assert.Null(EventXmlParser.GetData(document, "IpAddress"));
	}

	[Fact]
	public void ExtractSourceIp_UsesPerEventFieldNames()
	{
		XmlDocument? remote = EventXmlParser.ParseSafe("<Event xmlns='" + Namespace + "'><EventData><Data Name='Param3'>203.0.113.10</Data></EventData></Event>");
		XmlDocument? local = EventXmlParser.ParseSafe("<Event xmlns='" + Namespace + "'><UserData><EventXML><Address>198.51.100.5</Address></EventXML></UserData></Event>");
		XmlDocument? reconnect = EventXmlParser.ParseSafe("<Event xmlns='" + Namespace + "'><EventData><Data Name='ClientAddress'>203.0.113.42</Data></EventData></Event>");

		Assert.Equal("203.0.113.10", EventXmlParser.ExtractSourceIp(remote, 1149));
		Assert.Equal("198.51.100.5", EventXmlParser.ExtractSourceIp(local, 22));
		Assert.Equal("203.0.113.42", EventXmlParser.ExtractSourceIp(reconnect, 4778));
	}

	[Fact]
	public void ExtractCorrelationValues_ParsesSupportedRepresentations()
	{
		XmlDocument? document = EventXmlParser.ParseSafe("<Event xmlns='" + Namespace + "'><System><Correlation ActivityID='{aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee}' /></System><EventData><Data Name='TargetLogonId'>0x12345678</Data><Data Name='SessionID'>7</Data></EventData></Event>");

		Assert.Equal(0x12345678L, EventXmlParser.ExtractLogonId(document));
		Assert.Equal(7, EventXmlParser.ExtractSessionId(document));
		Assert.Equal(Guid.Parse("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"), EventXmlParser.ExtractActivityId(document));
	}

	[Fact]
	public void PopulateFrom_FillsMissingValuesWithoutClobberingExistingValues()
	{
		XmlDocument? document = EventXmlParser.ParseSafe("<Event xmlns='" + Namespace + "'><System><Correlation ActivityID='aaaaaaaa-1111-2222-3333-444444444444' /></System><EventData><Data Name='IpAddress'>10.0.0.7</Data><Data Name='TargetLogonId'>0xC0FFEE</Data><Data Name='SessionID'>2</Data></EventData></Event>");
		RawEventDto dto = new() { EventId = 4624, SourceIp = "192.0.2.1" };

		EventXmlParser.PopulateFrom(document, dto);

		Assert.Equal(Guid.Parse("aaaaaaaa-1111-2222-3333-444444444444"), dto.ActivityId);
		Assert.Equal(0xC0FFEEL, dto.LogonId);
		Assert.Equal(2, dto.SessionId);
		Assert.Equal("192.0.2.1", dto.SourceIp);
	}

	private static string BuildNestedDocument(int elementsInsideRoot)
	{
		StringBuilder document = new("<Event xmlns='");
		document.Append(Namespace);
		document.Append("'>");
		for (int index = 0; index < elementsInsideRoot; index++)
		{
			document.Append("<n>");
		}
		for (int index = 0; index < elementsInsideRoot; index++)
		{
			document.Append("</n>");
		}
		document.Append("</Event>");
		return document.ToString();
	}
}
