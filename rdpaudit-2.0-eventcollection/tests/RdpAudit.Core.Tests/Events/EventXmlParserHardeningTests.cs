/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 2.0.1
// File   : EventXmlParserHardeningTests.cs
// Project: RdpAudit.Core.Tests (RdpAudit.Core.Tests.Events)
// Purpose: Locks the hardening and correlation-extraction surface added to EventXmlParser
//          in 2.0: XXE / DTD refusal, oversize payloads, deep-nesting refusal, oversize field
//          refusal, XPath-injection-safe field names, and the new Extract* / PopulateFrom API
//          covering events 22, 1150, 1158, 4778, 4779.
// Depends: xUnit, RdpAudit.Core.Events
// Extends: When adding hardening (new caught exception, new limit), add a red-team test here.

using System.Text;
using System.Xml;
using RdpAudit.Core.Events;
using Xunit;

namespace RdpAudit.Core.Tests.Events;

public sealed class EventXmlParserHardeningTests
{
	private const string XmlNs = "http://schemas.microsoft.com/win/2004/08/events/event";

	// ── ParseSafe hardening ──────────────────────────────────────────────────────

	[Fact]
	public void ParseSafe_RefusesDocumentLargerThan1MiB()
	{
		// Build a well-formed but oversized document. 2 MiB of `<Data>x</Data>` filler.
		StringBuilder sb = new(capacity: 2 * 1024 * 1024 + 128);
		sb.Append($"<Event xmlns='{XmlNs}'><EventData>");
		while (sb.Length < 2 * 1024 * 1024)
		{
			sb.Append("<Data Name='X'>x</Data>");
		}
		sb.Append("</EventData></Event>");

		XmlDocument? doc = EventXmlParser.ParseSafe(sb.ToString());

		Assert.Null(doc);
	}

	[Fact]
	public void ParseSafe_RefusesDeeplyNestedDocument()
	{
		// Nest 128 levels of `<n>` elements plus a text node inside `<Event>`.
		// Deepest node lands at depth 129 (text). Well beyond the 64-level cap.
		// Real Windows payloads nest 6 max.
		Assert.Null(EventXmlParser.ParseSafe(BuildNestedDocument(128)));
	}

	// ── Depth-cap boundary (MaxDepth = 64, inclusive) ──────────────────────────
	// Contract: any node with `reader.Depth > MaxDepth` aborts the parse.
	// `XmlReader.Depth` is 0 on the root element and increments per nested element
	// AND per text node inside them. These two tests pin the exact boundary
	// between accepted and refused nesting so a future off-by-one regression
	// (widening or narrowing MaxDepth by one, or flipping `>` to `>=`) is
	// caught immediately.

	[Fact]
	public void ParseSafe_AcceptsDocumentAtExactDepthCap()
	{
		// 64 wrapper elements inside `<Event>` (element-only, no text):
		//   <Event>=0  <n>=1  <n>=2  …  <n>=64.
		// The innermost `<n>` sits at depth 64 — exactly on the cap. No text
		// node is added so no descendant ever reaches depth 65. Parse must succeed.
		string xml = BuildNestedElementsOnly(elementsInsideRoot: 64);

		XmlDocument? doc = EventXmlParser.ParseSafe(xml);

		Assert.NotNull(doc);
	}

	[Fact]
	public void ParseSafe_RefusesDocumentOnePastDepthCap()
	{
		// 65 wrapper elements inside `<Event>`: the innermost `<n>` sits at
		// depth 65, which is `MaxDepth + 1`. Parse must abort before allocating
		// the DOM.
		string xml = BuildNestedElementsOnly(elementsInsideRoot: 65);

		Assert.Null(EventXmlParser.ParseSafe(xml));
	}

	private static string BuildNestedDocument(int wrapperLevels)
	{
		StringBuilder sb = new();
		sb.Append($"<Event xmlns='{XmlNs}'>");
		for (int i = 0; i < wrapperLevels; i++)
		{
			sb.Append("<n>");
		}
		sb.Append("payload");
		for (int i = 0; i < wrapperLevels; i++)
		{
			sb.Append("</n>");
		}
		sb.Append("</Event>");
		return sb.ToString();
	}

	/// <summary>Builds a document containing only elements (no text nodes) with the
	/// specified number of nested wrapper elements inside <c>&lt;Event&gt;</c>. The
	/// deepest element sits at <see cref="XmlReader.Depth"/> equal to
	/// <paramref name="elementsInsideRoot"/>.</summary>
	private static string BuildNestedElementsOnly(int elementsInsideRoot)
	{
		StringBuilder sb = new();
		sb.Append($"<Event xmlns='{XmlNs}'>");
		for (int i = 0; i < elementsInsideRoot; i++)
		{
			sb.Append("<n>");
		}
		for (int i = 0; i < elementsInsideRoot; i++)
		{
			sb.Append("</n>");
		}
		sb.Append("</Event>");
		return sb.ToString();
	}

	[Fact]
	public void ParseSafe_RefusesXxeEntityInjection()
	{
		const string malicious =
			"<?xml version='1.0'?>" +
			"<!DOCTYPE root [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]>" +
			"<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>" +
			"<EventData><Data Name='X'>&xxe;</Data></EventData></Event>";

		Assert.Null(EventXmlParser.ParseSafe(malicious));
	}

	[Fact]
	public void ParseSafe_RefusesMalformedInputWithoutThrowing()
	{
		Assert.Null(EventXmlParser.ParseSafe("<not-actually-xml"));
		Assert.Null(EventXmlParser.ParseSafe(">"));
		Assert.Null(EventXmlParser.ParseSafe("\0\0\0\0"));
	}

	[Fact]
	public void ParseSafe_ReturnsNullForNullOrEmptyInput()
	{
		Assert.Null(EventXmlParser.ParseSafe(null!));
		Assert.Null(EventXmlParser.ParseSafe(string.Empty));
	}

	// ── GetData hardening ────────────────────────────────────────────────────────

	[Fact]
	public void GetData_RefusesUnsafeFieldName_PreventingXPathInjection()
	{
		XmlDocument? doc = EventXmlParser.ParseSafe(
			$"<Event xmlns='{XmlNs}'><EventData><Data Name='IpAddress'>10.0.0.7</Data></EventData></Event>");

		// The interior single quote would break the XPath if not validated.
		Assert.Null(EventXmlParser.GetData(doc, "Ip']|//*[local-name()='X"));
		Assert.Null(EventXmlParser.GetData(doc, "with space"));
		Assert.Null(EventXmlParser.GetData(doc, "with-dash"));
		Assert.Null(EventXmlParser.GetData(doc, string.Empty));
	}

	[Fact]
	public void GetData_RefusesOversizeFieldValue()
	{
		// 8 KiB in a single Data field, well above the 4 KiB per-field cap.
		string huge = new('x', 8 * 1024);
		XmlDocument? doc = EventXmlParser.ParseSafe(
			$"<Event xmlns='{XmlNs}'><EventData><Data Name='IpAddress'>{huge}</Data></EventData></Event>");
		Assert.NotNull(doc);

		Assert.Null(EventXmlParser.GetData(doc, "IpAddress"));
	}

	// ── 2.0 correlation helpers ──────────────────────────────────────────────────

	[Fact]
	public void ExtractSourceIp_UsesPerEventFieldNames()
	{
		XmlDocument? d1149 = EventXmlParser.ParseSafe(
			$"<Event xmlns='{XmlNs}'><EventData>" +
			"<Data Name='Param1'>alice</Data>" +
			"<Data Name='Param2'>WS-CLIENT</Data>" +
			"<Data Name='Param3'>203.0.113.10</Data>" +
			"</EventData></Event>");
		Assert.Equal("203.0.113.10", EventXmlParser.ExtractSourceIp(d1149, 1149));

		XmlDocument? d22 = EventXmlParser.ParseSafe(
			$"<Event xmlns='{XmlNs}'><UserData><EventXML><Address>198.51.100.5</Address>" +
			"</EventXML></UserData></Event>");
		Assert.Equal("198.51.100.5", EventXmlParser.ExtractSourceIp(d22, 22));

		XmlDocument? d4778 = EventXmlParser.ParseSafe(
			$"<Event xmlns='{XmlNs}'><EventData>" +
			"<Data Name='ClientAddress'>203.0.113.42</Data>" +
			"</EventData></Event>");
		Assert.Equal("203.0.113.42", EventXmlParser.ExtractSourceIp(d4778, 4778));
	}

	[Fact]
	public void ExtractLogonId_ParsesHexAndDecimal()
	{
		XmlDocument? hex = EventXmlParser.ParseSafe(
			$"<Event xmlns='{XmlNs}'><EventData>" +
			"<Data Name='TargetLogonId'>0x12345678</Data></EventData></Event>");
		Assert.Equal(0x12345678L, EventXmlParser.ExtractLogonId(hex));

		XmlDocument? dec = EventXmlParser.ParseSafe(
			$"<Event xmlns='{XmlNs}'><EventData>" +
			"<Data Name='SubjectLogonId'>305419896</Data></EventData></Event>");
		Assert.Equal(305_419_896L, EventXmlParser.ExtractLogonId(dec));

		XmlDocument? none = EventXmlParser.ParseSafe(
			$"<Event xmlns='{XmlNs}'><EventData></EventData></Event>");
		Assert.Null(EventXmlParser.ExtractLogonId(none));
	}

	[Fact]
	public void ExtractSessionId_HandlesBothWindowsCasings()
	{
		XmlDocument? upper = EventXmlParser.ParseSafe(
			$"<Event xmlns='{XmlNs}'><EventData>" +
			"<Data Name='SessionID'>7</Data></EventData></Event>");
		Assert.Equal(7, EventXmlParser.ExtractSessionId(upper));

		XmlDocument? lower = EventXmlParser.ParseSafe(
			$"<Event xmlns='{XmlNs}'><EventData>" +
			"<Data Name='SessionId'>3</Data></EventData></Event>");
		Assert.Equal(3, EventXmlParser.ExtractSessionId(lower));
	}

	[Fact]
	public void ExtractActivityId_ReadsCorrelationAttribute_WithOrWithoutBraces()
	{
		XmlDocument? braced = EventXmlParser.ParseSafe(
			$"<Event xmlns='{XmlNs}'><System>" +
			"<Correlation ActivityID='{aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee}'/>" +
			"</System><EventData/></Event>");
		Assert.Equal(new Guid("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"),
			EventXmlParser.ExtractActivityId(braced));

		XmlDocument? bare = EventXmlParser.ParseSafe(
			$"<Event xmlns='{XmlNs}'><System>" +
			"<Correlation ActivityID='11111111-2222-3333-4444-555555555555'/>" +
			"</System><EventData/></Event>");
		Assert.Equal(new Guid("11111111-2222-3333-4444-555555555555"),
			EventXmlParser.ExtractActivityId(bare));

		XmlDocument? none = EventXmlParser.ParseSafe(
			$"<Event xmlns='{XmlNs}'><System/></Event>");
		Assert.Null(EventXmlParser.ExtractActivityId(none));
	}

	[Fact]
	public void PopulateFrom_FillsAllCorrelationFields_IdempotentAndNonClobbering()
	{
		XmlDocument? doc = EventXmlParser.ParseSafe(
			$"<Event xmlns='{XmlNs}'>" +
			"<System><Correlation ActivityID='{aaaaaaaa-1111-2222-3333-444444444444}'/></System>" +
			"<EventData>" +
			"<Data Name='IpAddress'>10.0.0.7</Data>" +
			"<Data Name='TargetLogonId'>0xC0FFEE</Data>" +
			"<Data Name='SessionID'>2</Data>" +
			"</EventData></Event>");

		RawEventDto dto = new() { EventId = 4624, Channel = "Security", TimeUtc = DateTime.UtcNow };
		EventXmlParser.PopulateFrom(doc, dto);

		Assert.Equal(new Guid("aaaaaaaa-1111-2222-3333-444444444444"), dto.ActivityId);
		Assert.Equal(0xC0FFEEL, dto.LogonId);
		Assert.Equal(2, dto.SessionId);
		Assert.Equal("10.0.0.7", dto.SourceIp);

		// Second call must not clobber pre-set fields with a different payload.
		XmlDocument? other = EventXmlParser.ParseSafe(
			$"<Event xmlns='{XmlNs}'><EventData>" +
			"<Data Name='IpAddress'>203.0.113.99</Data>" +
			"<Data Name='TargetLogonId'>0xBADBAD</Data>" +
			"</EventData></Event>");
		EventXmlParser.PopulateFrom(other, dto);

		// Idempotent: previously-set correlation ids are preserved.
		Assert.Equal(0xC0FFEEL, dto.LogonId);
		Assert.Equal(2, dto.SessionId);
		Assert.Equal("10.0.0.7", dto.SourceIp);
	}

	[Fact]
	public void PopulateFrom_ThrowsOnNullDto_ReturnsSilentlyOnNullDoc()
	{
		Assert.Throws<ArgumentNullException>(
			() => EventXmlParser.PopulateFrom(null, null!));

		RawEventDto dto = new() { EventId = 4624, Channel = "Security", TimeUtc = DateTime.UtcNow };
		EventXmlParser.PopulateFrom(null, dto);   // must not throw
		Assert.Null(dto.ActivityId);
	}
}
