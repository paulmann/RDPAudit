// File:    tests/RdpAudit.Service.Tests/EventNormalizerStageIpATests.cs
// Module:  RdpAudit.Service.Tests
// Purpose: End-to-end checks that EventNormalizer attaches direct IP for events that carry one,
//          attaches a derived IP via SessionCorrelationCache for events that do not, and never
//          allows a hostname (e.g. 4776 Workstation) to land in RawEvent.SourceIp.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using RdpAudit.Core.Events;
using RdpAudit.Core.Models;
using RdpAudit.Service.Processors;
using Xunit;

namespace RdpAudit.Service.Tests;

public class EventNormalizerStageIpATests
{
	private const string SecurityChannel = "Security";

	private static string EventData(string eventId, params (string Name, string Value)[] fields)
	{
		string body = string.Join(string.Empty, Array.ConvertAll(fields,
			f => $"<Data Name='{f.Name}'>{f.Value}</Data>"));
		return $"<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><EventID>{eventId}</EventID></System><EventData>{body}</EventData></Event>";
	}

	private static EventNormalizer NewNormalizer(out SessionCorrelationCache cache)
	{
		cache = new SessionCorrelationCache();
		return new EventNormalizer(cache);
	}

	[Fact]
	public void Logon_4624_PopulatesSourceIp_NotDerived()
	{
		EventNormalizer normalizer = NewNormalizer(out _);
		RawEventDto dto = new()
		{
			EventId = 4624,
			Channel = SecurityChannel,
			TimeUtc = DateTime.UtcNow,
			XmlPayload = EventData("4624",
				("IpAddress", "203.0.113.5"),
				("TargetUserName", "alice"),
				("TargetLogonId", "0x42")),
		};

		RawEvent evt = normalizer.Normalize(dto);
		Assert.Equal("203.0.113.5", evt.SourceIp);
		Assert.False(evt.SourceIpDerived);
	}

	[Fact]
	public void Logoff_4634_FollowingLogon_HasDerivedIp()
	{
		EventNormalizer normalizer = NewNormalizer(out _);
		DateTime t0 = new(2026, 5, 20, 12, 0, 0, DateTimeKind.Utc);
		// First: 4624 seeds the cache with (LogonId=0x42, IP=203.0.113.5).
		normalizer.Normalize(new RawEventDto
		{
			EventId = 4624,
			Channel = SecurityChannel,
			TimeUtc = t0,
			XmlPayload = EventData("4624",
				("IpAddress", "203.0.113.5"),
				("TargetUserName", "alice"),
				("TargetLogonId", "0x42")),
		});

		// Then: 4634 (logoff) with the same LogonId — has no IP field, should be derived.
		RawEvent logoff = normalizer.Normalize(new RawEventDto
		{
			EventId = 4634,
			Channel = SecurityChannel,
			TimeUtc = t0.AddSeconds(30),
			XmlPayload = EventData("4634",
				("TargetUserName", "alice"),
				("TargetLogonId", "0x42")),
		});

		Assert.Equal("203.0.113.5", logoff.SourceIp);
		Assert.True(logoff.SourceIpDerived);
	}

	[Fact]
	public void Hostname_4776_NeverLandsInSourceIp()
	{
		EventNormalizer normalizer = NewNormalizer(out _);
		RawEvent evt = normalizer.Normalize(new RawEventDto
		{
			EventId = 4776,
			Channel = SecurityChannel,
			TimeUtc = DateTime.UtcNow,
			XmlPayload = EventData("4776",
				("Workstation", "DESKTOP-X"),
				("TargetUserName", "carol")),
		});

		Assert.Null(evt.SourceIp);
		Assert.False(evt.SourceIpDerived);
	}

	[Fact]
	public void Logoff_WithNoPriorLogon_HasNoIp()
	{
		EventNormalizer normalizer = NewNormalizer(out _);
		RawEvent evt = normalizer.Normalize(new RawEventDto
		{
			EventId = 4634,
			Channel = SecurityChannel,
			TimeUtc = DateTime.UtcNow,
			XmlPayload = EventData("4634",
				("TargetUserName", "alice"),
				("TargetLogonId", "0xabc")),
		});

		Assert.Null(evt.SourceIp);
		Assert.False(evt.SourceIpDerived);
	}
}
