// File:    tests/RdpAudit.Service.Tests/EventNormalizerStage6Tests.cs
// Module:  RdpAudit.Service.Tests
// Purpose: Stage 6 normalization tests — Security 4625 with a missing or "-" IpAddress field
//          must mark RawEvent.SourceIpUnresolved while preserving UserName, and SourceIp must
//          remain null (no synthetic placeholder).
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using RdpAudit.Core.Events;
using RdpAudit.Core.Models;
using RdpAudit.Service.Processors;
using Xunit;

namespace RdpAudit.Service.Tests;

public class EventNormalizerStage6Tests
{
	private const string SecurityChannel = "Security";

	private static string EventData(string eventId, params (string Name, string Value)[] fields)
	{
		string body = string.Join(string.Empty, Array.ConvertAll(fields,
			f => $"<Data Name='{f.Name}'>{f.Value}</Data>"));
		return $"<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><EventID>{eventId}</EventID></System><EventData>{body}</EventData></Event>";
	}

	private static EventNormalizer NewNormalizer() => new(new SessionCorrelationCache());

	[Fact]
	public void Security4625_MissingIpAddress_MarksUnresolved_PreservesUser()
	{
		EventNormalizer normalizer = NewNormalizer();
		RawEventDto dto = new()
		{
			EventId = 4625,
			Channel = SecurityChannel,
			TimeUtc = DateTime.UtcNow,
			XmlPayload = EventData("4625",
				("TargetUserName", "attacker"),
				("LogonType", "3")),
		};

		RawEvent evt = normalizer.Normalize(dto);
		Assert.Null(evt.SourceIp);
		Assert.False(evt.SourceIpDerived);
		Assert.True(evt.SourceIpUnresolved);
		Assert.Equal("attacker", evt.UserName);
		Assert.Equal(3, evt.LogonType);
	}

	[Fact]
	public void Security4625_DashIpAddress_MarksUnresolved()
	{
		EventNormalizer normalizer = NewNormalizer();
		RawEventDto dto = new()
		{
			EventId = 4625,
			Channel = SecurityChannel,
			TimeUtc = DateTime.UtcNow,
			XmlPayload = EventData("4625",
				("IpAddress", "-"),
				("TargetUserName", "attacker")),
		};

		RawEvent evt = normalizer.Normalize(dto);
		Assert.Null(evt.SourceIp);
		Assert.True(evt.SourceIpUnresolved);
	}

	[Fact]
	public void Security4625_WithValidIp_DoesNotMarkUnresolved()
	{
		EventNormalizer normalizer = NewNormalizer();
		RawEventDto dto = new()
		{
			EventId = 4625,
			Channel = SecurityChannel,
			TimeUtc = DateTime.UtcNow,
			XmlPayload = EventData("4625",
				("IpAddress", "203.0.113.5"),
				("TargetUserName", "attacker")),
		};

		RawEvent evt = normalizer.Normalize(dto);
		Assert.Equal("203.0.113.5", evt.SourceIp);
		Assert.False(evt.SourceIpDerived);
		Assert.False(evt.SourceIpUnresolved);
	}

	[Fact]
	public void NonFailedLogon_NoIp_DoesNotMarkUnresolved()
	{
		// 4624 without IP must not set the unresolved sentinel — the flag is reserved for
		// failed-logon evidence preservation. Other events should leave SourceIpUnresolved=false.
		EventNormalizer normalizer = NewNormalizer();
		RawEventDto dto = new()
		{
			EventId = 4624,
			Channel = SecurityChannel,
			TimeUtc = DateTime.UtcNow,
			XmlPayload = EventData("4624",
				("TargetUserName", "alice"),
				("LogonType", "2")),
		};

		RawEvent evt = normalizer.Normalize(dto);
		Assert.Null(evt.SourceIp);
		Assert.False(evt.SourceIpUnresolved);
	}

	[Fact]
	public void Security4625_CachedIpFromCorrelation_DoesNotMarkUnresolved()
	{
		// When session correlation can supply a derived IP, the row is not unresolved.
		SessionCorrelationCache cache = new();
		EventNormalizer normalizer = new(cache);
		DateTime t0 = new(2026, 5, 26, 10, 0, 0, DateTimeKind.Utc);

		// Seed via a successful logon.
		normalizer.Normalize(new RawEventDto
		{
			EventId = 4624,
			Channel = SecurityChannel,
			TimeUtc = t0,
			XmlPayload = EventData("4624",
				("IpAddress", "203.0.113.55"),
				("TargetUserName", "alice"),
				("TargetLogonId", "0x42")),
		});

		RawEvent failed = normalizer.Normalize(new RawEventDto
		{
			EventId = 4625,
			Channel = SecurityChannel,
			TimeUtc = t0.AddSeconds(10),
			XmlPayload = EventData("4625",
				("TargetUserName", "alice"),
				("TargetLogonId", "0x42")),
		});

		Assert.Equal("203.0.113.55", failed.SourceIp);
		Assert.True(failed.SourceIpDerived);
		Assert.False(failed.SourceIpUnresolved);
	}
}
