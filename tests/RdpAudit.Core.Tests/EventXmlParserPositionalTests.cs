// File:    tests/RdpAudit.Core.Tests/EventXmlParserPositionalTests.cs
// Module:  RdpAudit.Core.Tests
// Purpose: Locks the EventXmlParser.GetDataAt positional accessor used as a cameyo-rdpmon
//          compatibility fallback for Security 4625/4648 payloads that omit the @Name attribute
//          on EventData/Data children. The positional probe is fallback-only — these tests
//          guarantee the index semantics match cameyo's EventRecord.Properties[N] contract.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System.Xml;
using RdpAudit.Core.Events;
using Xunit;

namespace RdpAudit.Core.Tests;

public class EventXmlParserPositionalTests
{
	private static string BuildPositionalEventXml(params string[] values)
	{
		// Mimic stripped Windows payloads: <Data> elements without @Name attributes.
		string body = string.Concat(Array.ConvertAll(values, v => $"<Data>{v}</Data>"));
		return "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>" +
			"<System><EventID>4625</EventID></System>" +
			"<EventData>" + body + "</EventData>" +
			"</Event>";
	}

	[Fact]
	public void GetDataAt_ReturnsValueAtIndex()
	{
		string[] values = new string[20];
		for (int i = 0; i < values.Length; i++)
		{
			values[i] = $"v{i}";
		}

		XmlDocument? doc = EventXmlParser.ParseSafe(BuildPositionalEventXml(values));
		Assert.NotNull(doc);
		Assert.Equal("v0", EventXmlParser.GetDataAt(doc, 0));
		Assert.Equal("v5", EventXmlParser.GetDataAt(doc, 5));
		Assert.Equal("v19", EventXmlParser.GetDataAt(doc, 19));
	}

	[Fact]
	public void GetDataAt_OutOfRange_ReturnsNull()
	{
		XmlDocument? doc = EventXmlParser.ParseSafe(BuildPositionalEventXml("a", "b", "c"));
		Assert.Null(EventXmlParser.GetDataAt(doc, 5));
		Assert.Null(EventXmlParser.GetDataAt(doc, -1));
	}

	[Fact]
	public void GetDataAt_BlankAndDashSentinel_ReturnsNull()
	{
		XmlDocument? doc = EventXmlParser.ParseSafe(BuildPositionalEventXml("real", "-", string.Empty, "N/A"));
		Assert.Equal("real", EventXmlParser.GetDataAt(doc, 0));
		Assert.Null(EventXmlParser.GetDataAt(doc, 1));
		Assert.Null(EventXmlParser.GetDataAt(doc, 2));
		Assert.Null(EventXmlParser.GetDataAt(doc, 3));
	}

	[Fact]
	public void GetDataAt_NullDoc_ReturnsNull()
	{
		Assert.Null(EventXmlParser.GetDataAt(null, 0));
	}
}
