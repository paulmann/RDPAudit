// File:    tests/RdpAudit.Core.Tests/PerEventIpResolverPositionalFallbackTests.cs
// Module:  RdpAudit.Core.Tests
// Purpose: Cameyo rdpmon compatibility — verifies PerEventIpResolver applies the positional
//          Properties[19] fallback for Security 4625 and Properties[12] fallback for 4648 only
//          when the named IpAddress field is absent, and never overrides a valid named IpAddress.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System.Xml;
using RdpAudit.Core.Events;
using Xunit;

namespace RdpAudit.Core.Tests;

public class PerEventIpResolverPositionalFallbackTests
{
	private const string SecurityChannel = "Security";

	private static XmlDocument? Parse(string xml) => EventXmlParser.ParseSafe(xml);

	private static string PositionalEvent(string eventId, string[] values)
	{
		string body = string.Concat(Array.ConvertAll(values, v => $"<Data>{v}</Data>"));
		return "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>" +
			$"<System><EventID>{eventId}</EventID></System>" +
			$"<EventData>{body}</EventData></Event>";
	}

	private static string NamedEvent(string eventId, params (string Name, string Value)[] fields)
	{
		string body = string.Concat(Array.ConvertAll(fields,
			f => $"<Data Name='{f.Name}'>{f.Value}</Data>"));
		return "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>" +
			$"<System><EventID>{eventId}</EventID></System>" +
			$"<EventData>{body}</EventData></Event>";
	}

	[Fact]
	public void Security4625_NoNamedIp_PositionalIndex19_Resolves()
	{
		string[] values = new string[21];
		for (int i = 0; i < values.Length; i++)
		{
			values[i] = i == 19 ? "203.0.113.42" : (i == 5 ? "attacker" : "-");
		}

		string? ip = PerEventIpResolver.Resolve(Parse(PositionalEvent("4625", values)), SecurityChannel, 4625);
		Assert.Equal("203.0.113.42", ip);
	}

	[Fact]
	public void Security4625_NamedIpAddress_TakesPrecedenceOverIndex19()
	{
		// When both named IpAddress and a different positional value at index 19 are present, the
		// named field is authoritative. The positional probe is strictly fallback.
		string xml =
			"<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>" +
			"<System><EventID>4625</EventID></System>" +
			"<EventData>" +
			string.Concat(System.Linq.Enumerable.Range(0, 19).Select(_ => "<Data>x</Data>")) +
			"<Data>203.0.113.99</Data>" +
			"<Data Name='IpAddress'>198.51.100.7</Data>" +
			"</EventData></Event>";

		string? ip = PerEventIpResolver.Resolve(Parse(xml), SecurityChannel, 4625);
		Assert.Equal("198.51.100.7", ip);
	}

	[Fact]
	public void Security4648_NoNamedIp_PositionalIndex12_Resolves()
	{
		string[] values = new string[14];
		for (int i = 0; i < values.Length; i++)
		{
			values[i] = i == 12 ? "198.51.100.55" : (i == 5 ? "alice" : "-");
		}

		string? ip = PerEventIpResolver.Resolve(Parse(PositionalEvent("4648", values)), SecurityChannel, 4648);
		Assert.Equal("198.51.100.55", ip);
	}

	[Fact]
	public void Security4625_DashAtIndex19_StaysNull()
	{
		string[] values = new string[20];
		for (int i = 0; i < values.Length; i++)
		{
			values[i] = "-";
		}

		string? ip = PerEventIpResolver.Resolve(Parse(PositionalEvent("4625", values)), SecurityChannel, 4625);
		Assert.Null(ip);
	}

	[Fact]
	public void Security4625_WithNamedIpAddress_DoesNotConsultPositional()
	{
		string? ip = PerEventIpResolver.Resolve(
			Parse(NamedEvent("4625", ("IpAddress", "203.0.113.10"), ("TargetUserName", "bob"))),
			SecurityChannel, 4625);
		Assert.Equal("203.0.113.10", ip);
	}
}
