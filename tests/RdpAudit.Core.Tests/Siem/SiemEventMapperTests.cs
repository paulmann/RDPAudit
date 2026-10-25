// File:    tests/RdpAudit.Core.Tests/Siem/SiemEventMapperTests.cs
// Module:  RdpAudit.Core.Tests.Siem
// Purpose: Locks the pure SiemEventMapper contract: the single severity table (AlertSeverity and
//          event ids to the CEF/LEEF 0..10 scale), event-name resolution through EventCatalog,
//          event/alert field mapping, defaults and null-handling.
// Depends: SiemEventMapper, EventsForIpDto, AlertEntryDto, AlertSeverity, xUnit
// Extends: Append assertions whenever a severity row or mapped field is added.
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using RdpAudit.Core.Ipc.Contracts;
using RdpAudit.Core.Models;
using RdpAudit.Core.Siem;
using Xunit;

namespace RdpAudit.Core.Tests.Siem;

public sealed class SiemEventMapperTests
{
	private const string Version = "2.0.2";

	private static EventsForIpDto NewSummary() => new()
	{
		Ip = "203.0.113.7",
		AttackType = "BruteForce",
		FailedCount = 41,
		TotalEvents = 42,
	};

	private static IpEventEntryDto NewEntry(int eventId = 4625) => new()
	{
		Id = 12345,
		TimeUtc = new DateTime(2026, 9, 12, 13, 45, 7, DateTimeKind.Utc),
		EventId = eventId,
		Channel = "Security",
		UserName = "Boris",
		Domain = "WORKGROUP",
		LogonType = 3,
		AuthPackage = "NTLM",
		ProcessName = "svchost",
		Status = "0xC000006A",
	};

	[Theory]
	[InlineData(AlertSeverity.Info, 1)]
	[InlineData(AlertSeverity.Low, 3)]
	[InlineData(AlertSeverity.Medium, 5)]
	[InlineData(AlertSeverity.High, 8)]
	[InlineData(AlertSeverity.Critical, 10)]
	public void SeverityForAlert_MapsKnownValues(AlertSeverity severity, int expected)
	{
		Assert.Equal(expected, SiemEventMapper.SeverityForAlert(severity));
	}

	[Fact]
	public void SeverityForAlert_OutOfRangeValue_DefaultsToInfo()
	{
		Assert.Equal(1, SiemEventMapper.SeverityForAlert((AlertSeverity)99));
	}

	[Theory]
	[InlineData(4625, 5)]
	[InlineData(4771, 5)]
	[InlineData(4776, 5)]
	[InlineData(4624, 1)]
	[InlineData(4648, 1)]
	[InlineData(9999, 1)]
	public void SeverityForEvent_MapsOnlyFailedAuthToMedium(int eventId, int expected)
	{
		Assert.Equal(expected, SiemEventMapper.SeverityForEvent(eventId));
	}

	[Theory]
	[InlineData(4625, "Failed logon")]
	[InlineData(9999, "Windows event 9999")]
	public void NameForEvent_UsesCatalogWithUnknownFallback(int eventId, string expected)
	{
		Assert.Equal(expected, SiemEventMapper.NameForEvent(eventId));
	}

	[Fact]
	public void FromEvent_MapsAllFieldsAndUsesSummaryIp()
	{
		SiemEvent mapped = SiemEventMapper.FromEvent(NewEntry(), NewSummary(), Version);

		Assert.Equal(SiemEventType.Event, mapped.Type);
		Assert.Equal("event:4625", mapped.SignatureId);
		Assert.Equal("Failed logon", mapped.Name);
		Assert.Equal(5, mapped.Severity);
		Assert.Equal(new DateTime(2026, 9, 12, 13, 45, 7, DateTimeKind.Utc), mapped.TimeUtc);
		Assert.Equal("203.0.113.7", mapped.SourceIp);
		Assert.Equal("Boris", mapped.SourceUser);
		Assert.Equal("WORKGROUP", mapped.DestinationUser);
		Assert.Equal("Security", mapped.Channel);
		Assert.Equal(3, mapped.LogonType);
		Assert.Equal("NTLM", mapped.AuthPackage);
		Assert.Equal("svchost", mapped.ProcessName);
		Assert.Equal("0xC000006A", mapped.Status);
		Assert.Equal("BruteForce", mapped.AttackType);
		Assert.Equal(4625, mapped.EventId);
		Assert.Equal(41, mapped.FailedCount);
		Assert.Equal(42, mapped.TotalEvents);
		Assert.Equal("12345", mapped.ExternalId);
		Assert.Equal(SiemEventMapper.Vendor, mapped.DeviceVendor);
		Assert.Equal(SiemEventMapper.Product, mapped.DeviceProduct);
		Assert.Equal(Version, mapped.DeviceVersion);
		Assert.False(mapped.Acknowledged);
		Assert.Null(mapped.TriggerEventId);
	}

	[Fact]
	public void FromEvent_EmptyOrMissingSummaryAttackType_YieldsNull()
	{
		EventsForIpDto empty = NewSummary();
		empty.AttackType = "   ";

		SiemEvent mapped = SiemEventMapper.FromEvent(NewEntry(), empty, Version);

		Assert.Null(mapped.AttackType);
	}

	[Fact]
	public void FromEvent_NullArguments_Throw()
	{
		Assert.Throws<ArgumentNullException>(
			() => SiemEventMapper.FromEvent(null!, NewSummary(), Version));
		Assert.Throws<ArgumentNullException>(
			() => SiemEventMapper.FromEvent(NewEntry(), null!, Version));
		Assert.Throws<ArgumentNullException>(
			() => SiemEventMapper.FromEvent(NewEntry(), NewSummary(), null!));
	}

	[Fact]
	public void FromAlert_MapsAllFields()
	{
		AlertEntryDto alert = new()
		{
			Id = 777,
			RuleId = "BruteForce",
			Severity = AlertSeverity.High,
			TimeUtc = new DateTime(2026, 9, 12, 13, 46, 0, DateTimeKind.Utc),
			SourceIp = "203.0.113.7",
			UserName = "Boris",
			Message = "Brute force attempt",
			Acknowledged = true,
			TriggerEventId = 12345,
		};

		SiemEvent mapped = SiemEventMapper.FromAlert(alert, Version);

		Assert.Equal(SiemEventType.Alert, mapped.Type);
		Assert.Equal("BruteForce", mapped.SignatureId);
		Assert.Equal("Brute force attempt", mapped.Name);
		Assert.Equal(8, mapped.Severity);
		Assert.Equal(alert.TimeUtc, mapped.TimeUtc);
		Assert.Equal("203.0.113.7", mapped.SourceIp);
		Assert.Equal("Boris", mapped.SourceUser);
		Assert.Equal("Brute force attempt", mapped.Msg);
		Assert.Equal("777", mapped.ExternalId);
		Assert.True(mapped.Acknowledged);
		Assert.Equal(12345, mapped.TriggerEventId);
		Assert.Equal(Version, mapped.DeviceVersion);
	}

	[Fact]
	public void FromAlert_EmptyRuleId_FallsBackToUnknownSignature()
	{
		AlertEntryDto alert = new()
		{
			RuleId = " ",
			Message = string.Empty,
			Severity = AlertSeverity.Low,
		};

		SiemEvent mapped = SiemEventMapper.FromAlert(alert, Version);

		Assert.Equal("Unknown", mapped.SignatureId);
		Assert.Equal("Unknown", mapped.Name);
		Assert.Equal(3, mapped.Severity);
		Assert.Equal(string.Empty, mapped.SourceIp);
	}

	[Fact]
	public void FromAlert_EmptyMessage_FallsBackToRuleIdName()
	{
		AlertEntryDto alert = new() { RuleId = "LsassAccess", Message = string.Empty };

		SiemEvent mapped = SiemEventMapper.FromAlert(alert, Version);

		Assert.Equal("LsassAccess", mapped.Name);
		Assert.Equal(string.Empty, mapped.Msg);
	}

	[Fact]
	public void FromAlert_NullArguments_Throw()
	{
		Assert.Throws<ArgumentNullException>(() => SiemEventMapper.FromAlert(null!, Version));
		Assert.Throws<ArgumentNullException>(
			() => SiemEventMapper.FromAlert(new AlertEntryDto(), null!));
	}
}
