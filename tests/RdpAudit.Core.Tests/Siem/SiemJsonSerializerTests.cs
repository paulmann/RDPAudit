// File:    tests/RdpAudit.Core.Tests/Siem/SiemJsonSerializerTests.cs
// Module:  RdpAudit.Core.Tests.Siem
// Purpose: Golden + adversarial tests for SiemJsonSerializer: exact camelCase NDJSON lines, enum
//          strings, omitted nulls, strict JSON escaping of embedded control characters, LF-only
//          line endings and no trailing newline.
// Depends: SiemJsonSerializer, SiemEvent, xUnit
// Extends: Append a golden test whenever the SiemEvent projection changes.
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System.Text.Json;
using RdpAudit.Core.Siem;
using Xunit;

namespace RdpAudit.Core.Tests.Siem;

public sealed class SiemJsonSerializerTests
{
	private readonly SiemJsonSerializer _serializer = new();

	[Fact]
	public void EventGolden_IsCamelCaseLineWithEnumString()
	{
		SiemEvent e = new()
		{
			Type = SiemEventType.Event,
			SignatureId = "event:4625",
			Name = "Failed logon",
			Severity = 5,
			TimeUtc = new DateTime(2026, 9, 12, 13, 45, 7, DateTimeKind.Utc),
			SourceIp = "203.0.113.7",
			DeviceVendor = "RdpAudit",
			DeviceProduct = "RdpAudit",
			DeviceVersion = "2.0.2",
		};

		string actual = _serializer.Format([e]);

		using JsonDocument doc = JsonDocument.Parse(actual);
		JsonElement root = doc.RootElement;
		Assert.Equal("event", root.GetProperty("type").GetString());
		Assert.Equal("event:4625", root.GetProperty("signatureId").GetString());
		Assert.Equal("Failed logon", root.GetProperty("name").GetString());
		Assert.Equal(5, root.GetProperty("severity").GetInt32());
		Assert.Equal("2026-09-12T13:45:07Z", root.GetProperty("timeUtc").GetString());
		Assert.Equal("203.0.113.7", root.GetProperty("sourceIp").GetString());
		Assert.Equal("2.0.2", root.GetProperty("deviceVersion").GetString());
		Assert.False(root.TryGetProperty("sourcePort", out _));
	}

	[Fact]
	public void MultipleRecords_JoinWithLfAndNoTrailingNewline()
	{
		SiemEvent a = NewAlert();
		SiemEvent b = NewAlert();
		b.ExternalId = "778";

		string actual = _serializer.Format([a, b]);

		Assert.Equal(2, actual.Split('\n').Length);
		Assert.DoesNotContain("\r", actual);
		Assert.False(actual.EndsWith('\n'));
	}

	[Fact]
	public void EmptySequence_YieldsEmptyString()
	{
		Assert.Equal(string.Empty, _serializer.Format([]));
	}

	[Fact]
	public void NullSequence_Throws()
	{
		Assert.Throws<ArgumentNullException>(() => _serializer.Format(null!));
	}

	[Fact]
	public void NullElement_Throws()
	{
		Assert.Throws<ArgumentNullException>(() => _serializer.Format([NewAlert(), null!]));
	}

	[Fact]
	public void AdversarialControlCharacters_AreJsonEscapedNotRaw()
	{
		SiemEvent e = NewAlert();
		e.Name = "line1\nline2\rline3\tline4";

		string actual = _serializer.Format([e]);

		Assert.DoesNotContain('\n', actual);
		Assert.DoesNotContain('\r', actual);
		Assert.DoesNotContain('\t', actual);
		Assert.Contains("\\n", actual);
		Assert.Contains("\\r", actual);
		Assert.Contains("\\t", actual);

		using JsonDocument doc = JsonDocument.Parse(actual);
		Assert.Equal("line1\nline2\rline3\tline4", doc.RootElement.GetProperty("name").GetString());
	}

	private static SiemEvent NewAlert() => new()
	{
		Type = SiemEventType.Alert,
		SignatureId = "BruteForce",
		Name = "Brute force attempt",
		Severity = 10,
		TimeUtc = new DateTime(2026, 9, 12, 13, 46, 0, DateTimeKind.Utc),
		SourceIp = "203.0.113.7",
		ExternalId = "777",
		DeviceVendor = "RdpAudit",
		DeviceProduct = "RdpAudit",
		DeviceVersion = "2.0.2",
	};
}
