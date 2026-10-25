// File:    tests/RdpAudit.Service.Tests/EtwPayloadXmlFormatterTests.cs
// Module:  RdpAudit.Service.Tests
// Purpose: Locks the RDPAudit 2.0 ETW → XML formatter. The formatter's output MUST round-trip
//          through EventXmlParser and EventNormalizer without loss so downstream alerts,
//          exports, and UI queries see byte-identical fields regardless of ingestion source.
//          These tests are pure functions — no ETW, no TraceEvent runtime — so they execute
//          on Linux CI in the standard test job.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System.Xml;
using RdpAudit.Core.Events;
using RdpAudit.Service.EventSources;
using Xunit;

namespace RdpAudit.Service.Tests;

public class EtwPayloadXmlFormatterTests
{
	// ── Helpers ──────────────────────────────────────────────────────────────────

	private static EtwEventPayload MakePayload(
		int eventId = 1149,
		string providerName = "Microsoft-Windows-TerminalServices-RemoteConnectionManager",
		Guid? providerGuid = null,
		string channel = "Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational",
		DateTime? timeUtc = null,
		Guid? activityId = null,
		IReadOnlyList<string>? names = null,
		IReadOnlyList<object?>? values = null)
	{
		return new EtwEventPayload
		{
			EventId = eventId,
			ProviderName = providerName,
			ProviderGuid = providerGuid ?? EtwProviderMap.TsRemoteConnectionManagerGuid,
			Channel = channel,
			TimeStampUtc = timeUtc ?? new DateTime(2026, 8, 14, 12, 34, 56, 789, DateTimeKind.Utc),
			ActivityId = activityId ?? Guid.Empty,
			Computer = "WIN-TESTHOST",
			ProcessId = 468,
			ThreadId = 968,
			Version = 0,
			Level = 4,
			Task = 0,
			Opcode = 0,
			Keywords = 0x1000000000000000UL,
			Names = names ?? ["Param1", "Param2", "Param3"],
			Values = values ?? (object?[])["administrator", "CORPDOMAIN", "10.0.1.14"],
		};
	}

	private static XmlDocument Parse(string xml)
	{
		XmlDocument? doc = EventXmlParser.ParseSafe(xml);
		Assert.NotNull(doc);
		return doc!;
	}

	// ── Header / shape ───────────────────────────────────────────────────────────

	[Fact]
	public void Format_ProducesParseableXml()
	{
		string xml = EtwPayloadXmlFormatter.Format(MakePayload());
		XmlDocument doc = Parse(xml);

		Assert.NotNull(doc.SelectSingleNode("//*[local-name()='Event']"));
		Assert.NotNull(doc.SelectSingleNode("//*[local-name()='System']"));
		Assert.NotNull(doc.SelectSingleNode("//*[local-name()='EventData']"));
	}

	[Fact]
	public void Format_HasCanonicalEventNamespace()
	{
		string xml = EtwPayloadXmlFormatter.Format(MakePayload());
		Assert.Contains(
			"xmlns=\"http://schemas.microsoft.com/win/2004/08/events/event\"",
			xml, StringComparison.Ordinal);
	}

	// ── EventXmlParser round-trip: named payload fields ──────────────────────────

	[Fact]
	public void Format_RoundTripsTsRemote1149_Param3AsSourceIp()
	{
		// Real Windows shape for 1149: <UserData><EventXML><Param3>ip</Param3></EventXML></UserData>.
		// We deliberately emit the flat <EventData><Data Name="Param3"> form because ETW
		// consumers receive PayloadNames = ["Param1","Param2","Param3"] verbatim. EventXmlParser
		// accepts both shapes.
		EtwEventPayload payload = MakePayload();
		string xml = EtwPayloadXmlFormatter.Format(payload);
		XmlDocument doc = Parse(xml);

		Assert.Equal("10.0.1.14", EventXmlParser.ExtractSourceIp(doc, 1149));
	}

	[Fact]
	public void Format_RoundTripsSecurity4624_IpAddressAndTargetLogonId()
	{
		// Provider is Security-Auditing (we still exercise its shape because a test-only
		// payload is legitimate — Security channel simply cannot use ETW in real time).
		EtwEventPayload payload = MakePayload(
			eventId: 4624,
			providerName: "Microsoft-Windows-Security-Auditing",
			providerGuid: EtwProviderMap.SecurityAuditingGuid,
			channel: "Security",
			names:  ["TargetUserName", "TargetDomainName", "TargetLogonId",
					 "LogonType", "IpAddress", "AuthenticationPackageName"],
			values: (object?[])["alice", "CORP", "0x12345678", 10, "203.0.113.7", "Negotiate"]);

		string xml = EtwPayloadXmlFormatter.Format(payload);
		XmlDocument doc = Parse(xml);

		Assert.Equal("203.0.113.7", EventXmlParser.ExtractSourceIp(doc, 4624));
		Assert.Equal(0x12345678L, EventXmlParser.ExtractLogonId(doc));
	}

	[Fact]
	public void Format_RoundTripsTsLocal21_AddressAndSessionId()
	{
		// TerminalServices 21 uses Address for the IP, SessionID for the session number.
		EtwEventPayload payload = MakePayload(
			eventId: 21,
			providerName: "Microsoft-Windows-TerminalServices-LocalSessionManager",
			providerGuid: EtwProviderMap.TsLocalSessionManagerGuid,
			channel: "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational",
			names:  ["User", "SessionID", "Address"],
			values: (object?[])["CORP\\alice", 7, "203.0.113.42"]);

		string xml = EtwPayloadXmlFormatter.Format(payload);
		XmlDocument doc = Parse(xml);

		Assert.Equal("203.0.113.42", EventXmlParser.ExtractSourceIp(doc, 21));
		Assert.Equal(7, EventXmlParser.ExtractSessionId(doc));
		// (ExtractSessionId returns int?, Assert.Equal picks the overload for int.)
	}

	// ── Correlation ──────────────────────────────────────────────────────────────

	[Fact]
	public void Format_EmitsCorrelationWhenActivityIdSet()
	{
		Guid activity = new("f42005b9-c322-4bd9-962e-c985c22d0000");
		EtwEventPayload payload = MakePayload(activityId: activity);
		string xml = EtwPayloadXmlFormatter.Format(payload);
		XmlDocument doc = Parse(xml);

		Guid? extracted = EventXmlParser.ExtractActivityId(doc);
		Assert.Equal(activity, extracted);
	}

	[Fact]
	public void Format_EmitsEmptyCorrelationWhenActivityIdMissing()
	{
		EtwEventPayload payload = MakePayload(activityId: Guid.Empty);
		string xml = EtwPayloadXmlFormatter.Format(payload);
		XmlDocument doc = Parse(xml);

		// Element exists but has no ActivityID attribute — parser returns null.
		Assert.Null(EventXmlParser.ExtractActivityId(doc));
	}

	// ── EventId, timestamp, channel ──────────────────────────────────────────────

	[Fact]
	public void Format_EmitsEventIdAsPlainInteger()
	{
		string xml = EtwPayloadXmlFormatter.Format(MakePayload(eventId: 4625));
		XmlDocument doc = Parse(xml);
		string? id = doc.SelectSingleNode("//*[local-name()='EventID']")?.InnerText;
		Assert.Equal("4625", id);
	}

	[Fact]
	public void Format_EmitsTimestampInUtcRoundTripFormat()
	{
		DateTime t = new DateTime(2026, 8, 14, 12, 34, 56, DateTimeKind.Utc).AddTicks(7_890_123);
		EtwEventPayload payload = MakePayload(timeUtc: t);
		string xml = EtwPayloadXmlFormatter.Format(payload);
		XmlDocument doc = Parse(xml);

		string? systemTime = doc.SelectSingleNode("//*[local-name()='TimeCreated']/@SystemTime")?.Value;
		Assert.Equal("2026-08-14T12:34:56.7890123Z", systemTime);
	}

	[Fact]
	public void Format_ConvertsLocalTimestampToUtc()
	{
		DateTime local = DateTime.SpecifyKind(new DateTime(2026, 1, 1, 15, 0, 0), DateTimeKind.Local);
		DateTime expectedUtc = local.ToUniversalTime();
		EtwEventPayload payload = MakePayload(timeUtc: local);
		string xml = EtwPayloadXmlFormatter.Format(payload);
		XmlDocument doc = Parse(xml);

		string? systemTime = doc.SelectSingleNode("//*[local-name()='TimeCreated']/@SystemTime")?.Value;
		Assert.EndsWith("Z", systemTime);
		Assert.Contains(expectedUtc.ToString("yyyy-MM-ddTHH:mm:ss"), systemTime);
	}

	[Fact]
	public void Format_EmitsChannelName()
	{
		EtwEventPayload payload = MakePayload(channel: "Microsoft-Windows-TerminalServices-RDPClient/Operational");
		string xml = EtwPayloadXmlFormatter.Format(payload);
		XmlDocument doc = Parse(xml);

		Assert.Equal(
			"Microsoft-Windows-TerminalServices-RDPClient/Operational",
			doc.SelectSingleNode("//*[local-name()='Channel']")?.InnerText);
	}

	[Fact]
	public void Format_EmitsProviderNameAndGuid()
	{
		string xml = EtwPayloadXmlFormatter.Format(MakePayload());
		Assert.Contains(
			"Name=\"Microsoft-Windows-TerminalServices-RemoteConnectionManager\"",
			xml, StringComparison.Ordinal);
		Assert.Contains(
			"Guid=\"{c76baa63-ae81-421c-b425-340b4b24157f}\"",
			xml, StringComparison.OrdinalIgnoreCase);
	}

	// ── Value rendering ──────────────────────────────────────────────────────────

	[Theory]
	[InlineData("plain")]
	[InlineData("with spaces and 123 digits")]
	[InlineData("mixed 日本語 unicode")]
	public void Format_RendersStringValuesVerbatim(string value)
	{
		EtwEventPayload payload = MakePayload(
			names:  ["Field"],
			values: (object?[])[value]);
		string xml = EtwPayloadXmlFormatter.Format(payload);
		XmlDocument doc = Parse(xml);

		Assert.Equal(value, EventXmlParser.GetData(doc, "Field"));
	}

	[Fact]
	public void Format_RendersNumericValuesInInvariantCulture()
	{
		EtwEventPayload payload = MakePayload(
			names:  ["Int32Val", "Int64Val", "UInt32Val", "DoubleVal", "BoolVal"],
			values: (object?[])[42, 1_234_567_890_123L, 4_294_967_295u, 3.14159, true]);
		string xml = EtwPayloadXmlFormatter.Format(payload);
		XmlDocument doc = Parse(xml);

		Assert.Equal("42", EventXmlParser.GetData(doc, "Int32Val"));
		Assert.Equal("1234567890123", EventXmlParser.GetData(doc, "Int64Val"));
		Assert.Equal("4294967295", EventXmlParser.GetData(doc, "UInt32Val"));
		Assert.Equal("3.14159", EventXmlParser.GetData(doc, "DoubleVal"));
		Assert.Equal("true", EventXmlParser.GetData(doc, "BoolVal"));
	}

	[Fact]
	public void Format_RendersGuidWithBraces()
	{
		Guid g = new("f42005b9-c322-4bd9-962e-c985c22d0000");
		EtwEventPayload payload = MakePayload(
			names:  ["GuidField"],
			values: (object?[])[g]);
		string xml = EtwPayloadXmlFormatter.Format(payload);
		XmlDocument doc = Parse(xml);

		Assert.Equal(
			"{f42005b9-c322-4bd9-962e-c985c22d0000}",
			EventXmlParser.GetData(doc, "GuidField"));
	}

	[Fact]
	public void Format_RendersNullValueAsEmptyString()
	{
		EtwEventPayload payload = MakePayload(
			names:  ["Nothing"],
			values: (object?[])[null]);
		string xml = EtwPayloadXmlFormatter.Format(payload);
		XmlDocument doc = Parse(xml);

		// Parser normalises empty/dashes/N-A to null, so GetData returns null. That IS the
		// intended behaviour — a downstream normaliser needs to see "field not populated".
		Assert.Null(EventXmlParser.GetData(doc, "Nothing"));
	}

	[Fact]
	public void Format_RendersByteArrayAsHexUpper()
	{
		EtwEventPayload payload = MakePayload(
			names:  ["Bytes"],
			values: (object?[])[new byte[] { 0x01, 0xAB, 0xCD, 0xEF }]);
		string xml = EtwPayloadXmlFormatter.Format(payload);
		XmlDocument doc = Parse(xml);

		Assert.Equal("01ABCDEF", EventXmlParser.GetData(doc, "Bytes"));
	}

	// ── XML escaping ─────────────────────────────────────────────────────────────

	[Theory]
	[InlineData("a<b", "a<b")]
	[InlineData("a>b", "a>b")]
	[InlineData("a&b", "a&b")]
	[InlineData("with \"quote\"", "with \"quote\"")]
	[InlineData("with 'apostrophe'", "with 'apostrophe'")]
	[InlineData("mixed <>&\"' all", "mixed <>&\"' all")]
	public void Format_EscapesXmlSpecialCharactersInValues(string input, string expected)
	{
		EtwEventPayload payload = MakePayload(
			names:  ["Field"],
			values: (object?[])[input]);
		string xml = EtwPayloadXmlFormatter.Format(payload);
		XmlDocument doc = Parse(xml);

		Assert.Equal(expected, EventXmlParser.GetData(doc, "Field"));
	}

	[Fact]
	public void Format_DropsControlCharacters()
	{
		// XML 1.0 forbids raw C0 controls except tab/LF/CR. The formatter silently drops
		// them rather than emit an invalid document. Note: C# \x is a variable-length escape
		// (up to 4 hex digits and greedy), so the control chars are spelled out explicitly.
		string value = "before" + '\u0001' + '\u0002' + '\u0003' + "after";
		EtwEventPayload payload = MakePayload(
			names:  ["Field"],
			values: (object?[])[value]);
		string xml = EtwPayloadXmlFormatter.Format(payload);
		XmlDocument doc = Parse(xml);

		Assert.Equal("beforeafter", EventXmlParser.GetData(doc, "Field"));
	}

	[Fact]
	public void Format_PreservesAllowedWhitespace()
	{
		string value = "line1\nline2\tcol";
		EtwEventPayload payload = MakePayload(
			names:  ["Field"],
			values: (object?[])[value]);
		string xml = EtwPayloadXmlFormatter.Format(payload);
		XmlDocument doc = Parse(xml);

		Assert.Equal(value, EventXmlParser.GetData(doc, "Field"));
	}

	// ── Empty and mismatched inputs ──────────────────────────────────────────────

	[Fact]
	public void Format_EmptyPayloadStillProducesParseableXml()
	{
		EtwEventPayload payload = MakePayload(
			names:  Array.Empty<string>(),
			values: Array.Empty<object?>());
		string xml = EtwPayloadXmlFormatter.Format(payload);
		XmlDocument doc = Parse(xml);

		Assert.NotNull(doc.SelectSingleNode("//*[local-name()='EventData']"));
	}

	[Fact]
	public void Format_ThrowsOnMisalignedNamesAndValues()
	{
		EtwEventPayload payload = MakePayload(
			names:  ["A", "B"],
			values: (object?[])["only-one"]);

		ArgumentException ex = Assert.Throws<ArgumentException>(
			() => EtwPayloadXmlFormatter.Format(payload));
		Assert.Contains("Names", ex.Message, StringComparison.Ordinal);
	}

	[Fact]
	public void Format_ThrowsOnNullPayload()
	{
		Assert.Throws<ArgumentNullException>(
			() => EtwPayloadXmlFormatter.Format(null!));
	}

	// ── Truncation ───────────────────────────────────────────────────────────────

	[Fact]
	public void Format_TruncatesOversizePayloadAtCeiling()
	{
		// Build a value large enough to blow through the 65,536-char ceiling.
		string huge = new('x', 100_000);
		EtwEventPayload payload = MakePayload(
			names:  ["Bulk"],
			values: (object?[])[huge]);
		string xml = EtwPayloadXmlFormatter.Format(payload);

		Assert.True(xml.Length <= EtwPayloadXmlFormatter.MaxXmlLength);
		Assert.Contains("<!--truncated-->", xml, StringComparison.Ordinal);
		Assert.EndsWith("</Event>", xml, StringComparison.Ordinal);
	}

	[Fact]
	public void Format_TruncatedOutputIsStillParseable()
	{
		// After the safe-boundary truncation the document is intentionally still parseable
		// (we close </Event> and append a diagnostic comment). This lets downstream code see
		// the header fields even when the payload was chopped.
		string huge = new('x', 100_000);
		EtwEventPayload payload = MakePayload(
			names:  ["Bulk"],
			values: (object?[])[huge]);
		string xml = EtwPayloadXmlFormatter.Format(payload);
		XmlDocument doc = Parse(xml);

		Assert.NotNull(doc.SelectSingleNode("//*[local-name()='EventID']"));
	}

	// ── Determinism ──────────────────────────────────────────────────────────────

	[Fact]
	public void Format_IsDeterministicForSameInput()
	{
		EtwEventPayload p = MakePayload();
		string first = EtwPayloadXmlFormatter.Format(p);
		string second = EtwPayloadXmlFormatter.Format(p);

		Assert.Equal(first, second);
	}

	[Fact]
	public void Format_IsThreadSafeWithConcurrentCallers()
	{
		// The formatter uses a ThreadStatic StringBuilder cache. This test proves that two
		// threads calling in parallel do not corrupt each other's output.
		EtwEventPayload p1 = MakePayload(eventId: 1149);
		EtwEventPayload p2 = MakePayload(eventId: 4625,
			providerName: "Microsoft-Windows-Security-Auditing",
			providerGuid: EtwProviderMap.SecurityAuditingGuid,
			channel: "Security");

		string expected1 = EtwPayloadXmlFormatter.Format(p1);
		string expected2 = EtwPayloadXmlFormatter.Format(p2);

		Parallel.For(0, 200, i =>
		{
			string got = EtwPayloadXmlFormatter.Format((i & 1) == 0 ? p1 : p2);
			string want = (i & 1) == 0 ? expected1 : expected2;
			Assert.Equal(want, got);
		});
	}
}
