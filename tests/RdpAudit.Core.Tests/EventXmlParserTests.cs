// File:    tests/RdpAudit.Core.Tests/EventXmlParserTests.cs
// Module:  RdpAudit.Core.Tests
// Purpose: Verifies EventXmlParser correctly extracts EventData / UserData fields and rejects DTD.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using RdpAudit.Core.Events;
using Xunit;

namespace RdpAudit.Core.Tests;

public class EventXmlParserTests
{
	private const string SampleXml = """
<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>
	<System>
		<EventID>4624</EventID>
	</System>
	<EventData>
		<Data Name='IpAddress'>10.0.0.7</Data>
		<Data Name='TargetUserName'>alice</Data>
		<Data Name='LogonType'>10</Data>
		<Data Name='Empty'>-</Data>
	</EventData>
</Event>
""";

	[Fact]
	public void ParseSafe_ParsesValidPayload()
	{
		var doc = EventXmlParser.ParseSafe(SampleXml);
		Assert.NotNull(doc);
		Assert.Equal("10.0.0.7", EventXmlParser.GetData(doc, "IpAddress"));
		Assert.Equal("alice", EventXmlParser.GetData(doc, "TargetUserName"));
		Assert.Equal(10, EventXmlParser.GetInt(doc, "LogonType"));
	}

	[Fact]
	public void GetData_ReturnsNullForBlankSentinel()
	{
		var doc = EventXmlParser.ParseSafe(SampleXml);
		Assert.Null(EventXmlParser.GetData(doc, "Empty"));
		Assert.Null(EventXmlParser.GetData(doc, "Missing"));
	}

	[Fact]
	public void ParseSafe_RejectsExternalDtd()
	{
		const string malicious =
			"<!DOCTYPE foo [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]>" +
			"<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><x>&xxe;</x></Event>";
		Assert.Null(EventXmlParser.ParseSafe(malicious));
	}
}
