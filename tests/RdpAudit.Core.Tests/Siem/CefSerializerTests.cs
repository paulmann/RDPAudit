// File:    tests/RdpAudit.Core.Tests/Siem/CefSerializerTests.cs
// Module:  RdpAudit.Core.Tests.Siem
// Purpose: Golden + adversarial tests for CefSerializer: exact Splunk-shaped record text for an
//          event and an alert, CEF:0 header, epoch-millisecond rt, UTC deviceCustomDate1,
//          extension escaping and CR / LF / TAB neutralisation.
// Depends: CefSerializer, SiemEvent, xUnit
// Extends: Append a golden test whenever a new extension field is added.
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using RdpAudit.Core.Siem;
using Xunit;

namespace RdpAudit.Core.Tests.Siem;

public sealed class CefSerializerTests
{
	private readonly CefSerializer _serializer = new();

	private static SiemEvent NewEvent() => new()
	{
		Type = SiemEventType.Event,
		SignatureId = "event:4625",
		Name = "Failed logon",
		Severity = 5,
		TimeUtc = new DateTime(2026, 9, 12, 13, 45, 7, DateTimeKind.Utc),
		SourceIp = "203.0.113.7",
		SourceUser = "Boris",
		DestinationUser = "WORKGROUP",
		Channel = "Security",
		LogonType = 3,
		AuthPackage = "NTLM",
		ProcessName = "svchost",
		Status = "0xC000006A",
		AttackType = "BruteForce",
		EventId = 4625,
		FailedCount = 41,
		TotalEvents = 42,
		ExternalId = "12345",
		DeviceVendor = "RdpAudit",
		DeviceProduct = "RdpAudit",
		DeviceVersion = "2.0.2",
	};

	private static SiemEvent NewAlert() => new()
	{
		Type = SiemEventType.Alert,
		SignatureId = "BruteForce",
		Name = "Brute force attempt",
		Severity = 10,
		TimeUtc = new DateTime(2026, 9, 12, 13, 46, 0, DateTimeKind.Utc),
		SourceIp = "203.0.113.7",
		SourceUser = "Boris",
		Msg = "Brute force attempt",
		ExternalId = "777",
		Acknowledged = true,
		TriggerEventId = 12345,
		DeviceVendor = "RdpAudit",
		DeviceProduct = "RdpAudit",
		DeviceVersion = "2.0.2",
	};

	[Fact]
	public void EventGolden_MatchesSplunkShape()
	{
		const string Expected =
			"CEF:0|RdpAudit|RdpAudit|2.0.2|event:4625|Failed logon|5 "
			+ "rt=1789220707000 deviceCustomDate1Label=eventTime "
			+ "deviceCustomDate1=Sep 12 2026 13:45:07 +00:00 "
			+ "src=203.0.113.7 suser=Boris duser=WORKGROUP "
			+ "cn1Label=failedLogons cn1=41 cn2Label=totalEvents cn2=42 "
			+ "cs1Label=channel cs1=Security cs2Label=logonType cs2=3 "
			+ "cs3Label=authPackage cs3=NTLM cs4Label=processName cs4=svchost "
			+ "cs5Label=status cs5=0xC000006A cs6Label=attackType cs6=BruteForce "
			+ "cs7Label=externalId cs7=12345 cs8Label=recordType cs8=event";

		string actual = _serializer.Format([NewEvent()]);
		Assert.Equal(Expected, actual);
	}

	[Fact]
	public void AlertGolden_MatchesSplunkShape()
	{
		const string Expected =
			"CEF:0|RdpAudit|RdpAudit|2.0.2|BruteForce|Brute force attempt|10 "
			+ "rt=1789220760000 deviceCustomDate1Label=eventTime "
			+ "deviceCustomDate1=Sep 12 2026 13:46:00 +00:00 "
			+ "src=203.0.113.7 suser=Boris msg=Brute force attempt "
			+ "cs7Label=externalId cs7=777 cs8Label=recordType cs8=alert";

		string actual = _serializer.Format([NewAlert()]);
		Assert.Equal(Expected, actual);
	}

	[Fact]
	public void MultipleRecords_JoinWithLfAndNoTrailingNewline()
	{
		string actual = _serializer.Format([NewEvent(), NewAlert()]);

		Assert.Equal(2, actual.Split('\n').Length);
		Assert.DoesNotContain("\r", actual);
		Assert.False(actual.EndsWith('\n'));
		Assert.StartsWith("CEF:0|RdpAudit|RdpAudit|2.0.2|event:4625", actual);
		Assert.Contains("\nCEF:0|RdpAudit|RdpAudit|2.0.2|BruteForce", actual);
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
		Assert.Throws<ArgumentNullException>(() => _serializer.Format([NewEvent(), null!]));
	}

	[Fact]
	public void AdversarialValues_AreEscapedAndNeutralised()
	{
		SiemEvent e = NewEvent();
		e.Name = "bad|name\\slash\nnext";
		e.SourceUser = "u=t|x\r";
		e.Status = "tab\there";

		string actual = _serializer.Format([e]);

		Assert.DoesNotContain('\r', actual);
		Assert.DoesNotContain('\n', actual);
		Assert.DoesNotContain('\t', actual);
		Assert.Contains("bad\\|name\\\\slash next", actual);
		Assert.Contains("suser=u\\=t\\|x ", actual);
		Assert.Contains("cs5=tab here", actual);
	}
}
