// File:    tests/RdpAudit.Service.Tests/EventNormalizerPositionalFallbackTests.cs
// Module:  RdpAudit.Service.Tests
// Purpose: Cameyo-rdpmon-style positional fallback in the normalizer — when a Security 4625 /
//          4648 payload omits @Name attributes on its Data children (older Windows builds, audit
//          policy variants, or stripped event sources), the user / IP must still be recovered
//          via Properties[5] / Properties[19] / Properties[12].
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using RdpAudit.Core.Events;
using RdpAudit.Core.Models;
using RdpAudit.Service.Processors;
using Xunit;

namespace RdpAudit.Service.Tests;

public class EventNormalizerPositionalFallbackTests
{
	private const string SecurityChannel = "Security";

	private static string PositionalEvent(string eventId, string[] values)
	{
		string body = string.Concat(Array.ConvertAll(values, v => $"<Data>{v}</Data>"));
		return "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>" +
			$"<System><EventID>{eventId}</EventID></System>" +
			$"<EventData>{body}</EventData></Event>";
	}

	private static EventNormalizer NewNormalizer() => new(new SessionCorrelationCache());

	[Fact]
	public void Security4625_PositionalUserAndIp_Resolved()
	{
		string[] values = new string[21];
		for (int i = 0; i < values.Length; i++)
		{
			values[i] = i switch
			{
				5 => "attacker",
				19 => "203.0.113.42",
				_ => "-",
			};
		}

		RawEvent evt = NewNormalizer().Normalize(new RawEventDto
		{
			EventId = 4625,
			Channel = SecurityChannel,
			TimeUtc = DateTime.UtcNow,
			XmlPayload = PositionalEvent("4625", values),
		});

		Assert.Equal("attacker", evt.UserName);
		Assert.Equal("203.0.113.42", evt.SourceIp);
		Assert.False(evt.SourceIpUnresolved);
	}

	[Fact]
	public void Security4648_PositionalUserAndIp_Resolved()
	{
		string[] values = new string[14];
		for (int i = 0; i < values.Length; i++)
		{
			values[i] = i switch
			{
				5 => "alice",
				12 => "198.51.100.5",
				_ => "-",
			};
		}

		RawEvent evt = NewNormalizer().Normalize(new RawEventDto
		{
			EventId = 4648,
			Channel = SecurityChannel,
			TimeUtc = DateTime.UtcNow,
			XmlPayload = PositionalEvent("4648", values),
		});

		Assert.Equal("alice", evt.UserName);
		Assert.Equal("198.51.100.5", evt.SourceIp);
	}

	[Fact]
	public void Security4625_PositionalUser_NoIp_MarksUnresolved()
	{
		string[] values = new string[10];
		for (int i = 0; i < values.Length; i++)
		{
			values[i] = i == 5 ? "ghost" : "-";
		}

		RawEvent evt = NewNormalizer().Normalize(new RawEventDto
		{
			EventId = 4625,
			Channel = SecurityChannel,
			TimeUtc = DateTime.UtcNow,
			XmlPayload = PositionalEvent("4625", values),
		});

		Assert.Equal("ghost", evt.UserName);
		Assert.Null(evt.SourceIp);
		Assert.True(evt.SourceIpUnresolved);
	}

	[Fact]
	public void Security4625_NamedUserName_StillTakesPrecedence()
	{
		// Hybrid payload: positional index 5 has one value, but a named TargetUserName field is
		// present — the named field wins. Positional is fallback-only.
		string xml = "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>" +
			"<System><EventID>4625</EventID></System>" +
			"<EventData>" +
			"<Data>0</Data><Data>1</Data><Data>2</Data><Data>3</Data><Data>4</Data>" +
			"<Data>positionalUser</Data>" +
			"<Data Name='TargetUserName'>namedUser</Data>" +
			"</EventData></Event>";

		RawEvent evt = NewNormalizer().Normalize(new RawEventDto
		{
			EventId = 4625,
			Channel = SecurityChannel,
			TimeUtc = DateTime.UtcNow,
			XmlPayload = xml,
		});

		Assert.Equal("namedUser", evt.UserName);
	}
}
