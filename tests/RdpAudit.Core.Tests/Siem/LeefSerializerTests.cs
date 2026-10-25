// File:    tests/RdpAudit.Core.Tests/Siem/LeefSerializerTests.cs
// Module:  RdpAudit.Core.Tests.Siem
// Purpose: Golden + adversarial tests for LeefSerializer: exact QRadar-shaped record text for an
//          event and an alert, LEEF:2.0 header, ISO-8601 UTC devTime, TAB-separated attributes,
//          caret/pipe/backslash escaping and CR / LF / TAB neutralisation.
// Depends: LeefSerializer, SiemEvent, xUnit
// Extends: Append a golden test whenever a new attribute is added.
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using RdpAudit.Core.Siem;
using Xunit;

namespace RdpAudit.Core.Tests.Siem;

public sealed class LeefSerializerTests
{
	private readonly LeefSerializer _serializer = new();

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
	public void EventGolden_MatchesQRadarShape()
	{
		const string Expected =
			"LEEF:2.0|RdpAudit|RdpAudit|2.0.2|event:4625"
			+ "\tdevTime=2026-09-12T13:45:07.000Z"
			+ "\tname=Failed logon"
			+ "\tsev=5"
			+ "\tsrc=203.0.113.7"
			+ "\tusrName=Boris"
			+ "\tdstUser=WORKGROUP"
			+ "\tchannel=Security"
			+ "\tlogonType=3"
			+ "\tauthPackage=NTLM"
			+ "\tprocessName=svchost"
			+ "\tstatus=0xC000006A"
			+ "\tcat=BruteForce"
			+ "\tfailedLogons=41"
			+ "\ttotalEvents=42"
			+ "\texternalId=12345"
			+ "\teventId=4625"
			+ "\tacknowledged=false"
			+ "\trecordType=event";

		string actual = _serializer.Format([NewEvent()]);
		Assert.Equal(Expected, actual);
	}

	[Fact]
	public void AlertGolden_MatchesQRadarShape()
	{
		const string Expected =
			"LEEF:2.0|RdpAudit|RdpAudit|2.0.2|BruteForce"
			+ "\tdevTime=2026-09-12T13:46:00.000Z"
			+ "\tname=Brute force attempt"
			+ "\tsev=10"
			+ "\tsrc=203.0.113.7"
			+ "\tusrName=Boris"
			+ "\tmsg=Brute force attempt"
			+ "\texternalId=777"
			+ "\ttriggerEventId=12345"
			+ "\tacknowledged=true"
			+ "\trecordType=alert";

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
		Assert.StartsWith("LEEF:2.0|RdpAudit|RdpAudit|2.0.2|event:4625", actual);
		Assert.Contains("\nLEEF:2.0|RdpAudit|RdpAudit|2.0.2|BruteForce", actual);
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
		e.Name = "bad^caret|pipe\\slash";
		e.Status = "tab\tcontrol\r\n";

		string actual = _serializer.Format([e]);

		Assert.DoesNotContain('\r', actual);
		Assert.DoesNotContain('\n', actual);
		Assert.Contains("name=bad\\^caret\\|pipe\\\\slash", actual);
		Assert.Contains("status=tab control  ", actual);
	}
}
