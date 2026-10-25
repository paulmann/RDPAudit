// File:    tests/RdpAudit.Core.Tests/PerEventIpResolverTests.cs
// Module:  RdpAudit.Core.Tests
// Purpose: Verifies PerEventIpResolver extracts the correct IP field per (Channel, EventId) and
//          rejects hostname-only events (no NetBIOS name should ever land in SourceIp).
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using RdpAudit.Core.Events;
using Xunit;

namespace RdpAudit.Core.Tests;

public class PerEventIpResolverTests
{
	private const string SecurityChannel = "Security";
	private const string TsLsmChannel = "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational";
	private const string TsRcmChannel = "Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational";
	private const string RdpCoreTsChannel = "Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational";

	private static string EventData(string eventId, params (string Name, string Value)[] fields)
	{
		string body = string.Join(string.Empty, Array.ConvertAll(fields,
			f => $"<Data Name='{f.Name}'>{f.Value}</Data>"));
		return $"<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><EventID>{eventId}</EventID></System><EventData>{body}</EventData></Event>";
	}

	private static string UserData(string eventId, params (string Name, string Value)[] fields)
	{
		string body = string.Join(string.Empty, Array.ConvertAll(fields,
			f => $"<{f.Name}>{f.Value}</{f.Name}>"));
		return $"<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><EventID>{eventId}</EventID></System><UserData><EventXML>{body}</EventXML></UserData></Event>";
	}

	[Fact]
	public void Security_4624_UsesIpAddress()
	{
		var doc = EventXmlParser.ParseSafe(EventData("4624",
			("IpAddress", "203.0.113.5"),
			("TargetUserName", "alice")));
		Assert.Equal("203.0.113.5", PerEventIpResolver.Resolve(doc, SecurityChannel, 4624));
	}

	[Theory]
	[InlineData(4624)]
	[InlineData(4625)]
	[InlineData(4648)]
	[InlineData(4768)]
	[InlineData(4769)]
	[InlineData(4770)]
	[InlineData(4771)]
	public void Security_IpAddressEvents_AllReadIpAddress(int eventId)
	{
		var doc = EventXmlParser.ParseSafe(EventData(
			eventId.ToString(System.Globalization.CultureInfo.InvariantCulture),
			("IpAddress", "198.51.100.7")));
		Assert.Equal("198.51.100.7", PerEventIpResolver.Resolve(doc, SecurityChannel, eventId));
	}

	[Theory]
	[InlineData(4778)]
	[InlineData(4779)]
	public void Security_4778_4779_UseClientAddress(int eventId)
	{
		var doc = EventXmlParser.ParseSafe(EventData(
			eventId.ToString(System.Globalization.CultureInfo.InvariantCulture),
			("ClientAddress", "192.0.2.42"),
			("AccountName", "bob")));
		Assert.Equal("192.0.2.42", PerEventIpResolver.Resolve(doc, SecurityChannel, eventId));
	}

	[Fact]
	public void Security_4776_HostnameOnly_ReturnsNull()
	{
		// 4776 carries only a Workstation hostname; the resolver must never write that into SourceIp.
		var doc = EventXmlParser.ParseSafe(EventData("4776",
			("Workstation", "DESKTOP-X"),
			("TargetUserName", "carol")));
		Assert.Null(PerEventIpResolver.Resolve(doc, SecurityChannel, 4776));
	}

	[Fact]
	public void Security_4634_HasNoDirectIp_ReturnsNull()
	{
		var doc = EventXmlParser.ParseSafe(EventData("4634",
			("TargetUserName", "dave"),
			("TargetLogonId", "0x42")));
		Assert.Null(PerEventIpResolver.Resolve(doc, SecurityChannel, 4634));
	}

	[Fact]
	public void TsLsm_21_ReadsAddressFromUserData()
	{
		var doc = EventXmlParser.ParseSafe(UserData("21",
			("Address", "203.0.113.20"),
			("User", "eve"),
			("SessionID", "3")));
		Assert.Equal("203.0.113.20", PerEventIpResolver.Resolve(doc, TsLsmChannel, 21));
	}

	[Theory]
	[InlineData(24)]
	[InlineData(25)]
	public void TsLsm_24_25_ReadAddress(int eventId)
	{
		var doc = EventXmlParser.ParseSafe(UserData(
			eventId.ToString(System.Globalization.CultureInfo.InvariantCulture),
			("Address", "192.0.2.11"),
			("SessionID", "4")));
		Assert.Equal("192.0.2.11", PerEventIpResolver.Resolve(doc, TsLsmChannel, eventId));
	}

	[Fact]
	public void TsRcm_1149_ReadsParam3()
	{
		var doc = EventXmlParser.ParseSafe(UserData("1149",
			("Param1", "frank"),
			("Param2", "WORKGROUP"),
			("Param3", "198.51.100.9")));
		Assert.Equal("198.51.100.9", PerEventIpResolver.Resolve(doc, TsRcmChannel, 1149));
	}

	[Fact]
	public void RdpCoreTs_131_ReadsClientIP()
	{
		var doc = EventXmlParser.ParseSafe(UserData("131",
			("ClientIP", "203.0.113.99")));
		Assert.Equal("203.0.113.99", PerEventIpResolver.Resolve(doc, RdpCoreTsChannel, 131));
	}

	[Fact]
	public void RdpCoreTs_131_FallsBackToConnectionName()
	{
		var doc = EventXmlParser.ParseSafe(UserData("131",
			("ConnectionName", "198.51.100.55")));
		Assert.Equal("198.51.100.55", PerEventIpResolver.Resolve(doc, RdpCoreTsChannel, 131));
	}

	[Fact]
	public void RdpCoreTs_140_ReadsIPString()
	{
		var doc = EventXmlParser.ParseSafe(UserData("140",
			("IPString", "192.0.2.200")));
		Assert.Equal("192.0.2.200", PerEventIpResolver.Resolve(doc, RdpCoreTsChannel, 140));
	}

	[Fact]
	public void Unparseable_IpReturnsNull()
	{
		var doc = EventXmlParser.ParseSafe(EventData("4624",
			("IpAddress", "not-an-ip")));
		Assert.Null(PerEventIpResolver.Resolve(doc, SecurityChannel, 4624));
	}

	[Fact]
	public void Ipv4MappedIpv6_ReturnsDottedQuad()
	{
		var doc = EventXmlParser.ParseSafe(EventData("4624",
			("IpAddress", "::ffff:1.2.3.4")));
		Assert.Equal("1.2.3.4", PerEventIpResolver.Resolve(doc, SecurityChannel, 4624));
	}

	[Fact]
	public void LocalSentinel_ReturnsNull()
	{
		var doc = EventXmlParser.ParseSafe(EventData("4624",
			("IpAddress", "127.0.0.1")));
		// Loopback parses as IP but IsLocalSentinel rejects it before we even try TryParse.
		Assert.Null(PerEventIpResolver.Resolve(doc, SecurityChannel, 4624));
	}

	[Fact]
	public void NullDocument_ReturnsNull()
	{
		Assert.Null(PerEventIpResolver.Resolve(null, SecurityChannel, 4624));
	}

	[Fact]
	public void UnknownChannel_FallsBackToIpAddressOnly()
	{
		var doc = EventXmlParser.ParseSafe(EventData("9999",
			("IpAddress", "203.0.113.77"),
			("Workstation", "DESKTOP-Y")));
		Assert.Equal("203.0.113.77", PerEventIpResolver.Resolve(doc, "SomeOther", 9999));
	}

	[Fact]
	public void UnknownChannel_RejectsHostnameOnly()
	{
		var doc = EventXmlParser.ParseSafe(EventData("9999",
			("Workstation", "DESKTOP-Y"),
			("ClientName", "DESKTOP-Z")));
		Assert.Null(PerEventIpResolver.Resolve(doc, "SomeOther", 9999));
	}

	// --- Stage 6: TS-RCM 261 pre-auth listener ----------------------------------------------

	[Fact]
	public void TsRcm_261_PrefersAddressField()
	{
		var doc = EventXmlParser.ParseSafe(UserData("261",
			("Address", "203.0.113.61")));
		Assert.Equal("203.0.113.61", PerEventIpResolver.Resolve(doc, TsRcmChannel, 261));
	}

	[Fact]
	public void TsRcm_261_FallsBackToIpAddress()
	{
		var doc = EventXmlParser.ParseSafe(UserData("261",
			("IpAddress", "198.51.100.61")));
		Assert.Equal("198.51.100.61", PerEventIpResolver.Resolve(doc, TsRcmChannel, 261));
	}

	[Fact]
	public void TsRcm_261_FallsBackToClientAddress()
	{
		var doc = EventXmlParser.ParseSafe(UserData("261",
			("ClientAddress", "192.0.2.61")));
		Assert.Equal("192.0.2.61", PerEventIpResolver.Resolve(doc, TsRcmChannel, 261));
	}

	[Fact]
	public void TsRcm_261_RejectsHostnameOnly()
	{
		// The fallback for 261 must never consult hostname-only fields.
		var doc = EventXmlParser.ParseSafe(UserData("261",
			("ClientName", "DESKTOP-FOO"),
			("Workstation", "DESKTOP-BAR")));
		Assert.Null(PerEventIpResolver.Resolve(doc, TsRcmChannel, 261));
	}

	// --- Stage 6: TS-LSM 39/40 lifecycle ---------------------------------------------------

	[Theory]
	[InlineData(39)]
	[InlineData(40)]
	public void TsLsm_39_40_ReadAddressWhenPresent(int eventId)
	{
		var doc = EventXmlParser.ParseSafe(UserData(
			eventId.ToString(System.Globalization.CultureInfo.InvariantCulture),
			("Address", "203.0.113.40"),
			("SessionID", "7")));
		Assert.Equal("203.0.113.40", PerEventIpResolver.Resolve(doc, TsLsmChannel, eventId));
	}

	[Theory]
	[InlineData(39)]
	[InlineData(40)]
	public void TsLsm_39_40_NoAddress_ReturnsNull(int eventId)
	{
		var doc = EventXmlParser.ParseSafe(UserData(
			eventId.ToString(System.Globalization.CultureInfo.InvariantCulture),
			("SessionID", "8")));
		Assert.Null(PerEventIpResolver.Resolve(doc, TsLsmChannel, eventId));
	}

	// --- Stage 6: Security 4634/4647 may now read IpAddress if present ---------------------

	[Fact]
	public void Security_4634_WithIpAddress_ReturnsIt()
	{
		var doc = EventXmlParser.ParseSafe(EventData("4634",
			("IpAddress", "203.0.113.34"),
			("TargetUserName", "dave"),
			("TargetLogonId", "0x42")));
		Assert.Equal("203.0.113.34", PerEventIpResolver.Resolve(doc, SecurityChannel, 4634));
	}

	[Fact]
	public void Security_4647_WithIpAddress_ReturnsIt()
	{
		var doc = EventXmlParser.ParseSafe(EventData("4647",
			("IpAddress", "203.0.113.47"),
			("TargetUserName", "dave")));
		Assert.Equal("203.0.113.47", PerEventIpResolver.Resolve(doc, SecurityChannel, 4647));
	}
}
