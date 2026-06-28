// File:    tests/RdpAudit.Core.Tests/IpNormalizerTests.cs
// Module:  RdpAudit.Core.Tests
// Purpose: v1.2.1 stabilisation gate — pins the canonical-form contract of IpNormalizer so
//          punctuation-wrapped, port-suffixed, IPv6-zone-tagged, and IPv4-mapped-IPv6 values
//          collapse to the single textual key Attack-Statistics / RDP-Clients aggregates rely
//          on. The real-host bug report was a 4776 NTLM failure where Live Events showed the
//          attacker as ".77.37.192.246" but the Attack Statistics row appeared under
//          (unresolved) because the previous normalizer rejected the leading-dot form.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using RdpAudit.Core.Util;
using Xunit;

namespace RdpAudit.Core.Tests;

public class IpNormalizerTests
{
	[Theory]
	[InlineData(".77.37.192.246", "77.37.192.246")]
	[InlineData(" 77.37.192.246", "77.37.192.246")]
	[InlineData("77.37.192.246 ", "77.37.192.246")]
	[InlineData("\t77.37.192.246\t", "77.37.192.246")]
	[InlineData(".77.37.192.246.", "77.37.192.246")]
	[InlineData(",77.37.192.246;", "77.37.192.246")]
	[InlineData("'77.37.192.246'", "77.37.192.246")]
	[InlineData("\"77.37.192.246\"", "77.37.192.246")]
	[InlineData("(77.37.192.246)", "77.37.192.246")]
	[InlineData("[77.37.192.246]", "77.37.192.246")]
	[InlineData("77.37.192.246:443", "77.37.192.246")]
	[InlineData("77.37.192.246:", "77.37.192.246")]
	public void Ipv4_PunctuationOrPort_StripsToCanonical(string input, string expected)
	{
		Assert.Equal(expected, IpNormalizer.Normalize(input));
	}

	[Theory]
	[InlineData("::ffff:77.37.192.246", "77.37.192.246")]
	[InlineData("::ffff:1.2.3.4", "1.2.3.4")]
	[InlineData(" ::ffff:1.2.3.4 ", "1.2.3.4")]
	[InlineData("[::ffff:1.2.3.4]", "1.2.3.4")]
	public void Ipv4MappedIpv6_CollapsesToDottedQuad(string input, string expected)
	{
		Assert.Equal(expected, IpNormalizer.Normalize(input));
	}

	[Theory]
	[InlineData("2001:db8::1", "2001:db8::1")]
	[InlineData("[2001:db8::1]", "2001:db8::1")]
	[InlineData("[2001:db8::1]:443", "2001:db8::1")]
	[InlineData("fe80::1%eth0", "fe80::1")]
	public void Ipv6_BracketPortAndZone_AreStripped(string input, string expected)
	{
		// IPAddress.ToString lowercases the canonical IPv6 form; assert case-insensitively.
		Assert.Equal(expected, IpNormalizer.Normalize(input), ignoreCase: true);
	}

	[Theory]
	[InlineData(null)]
	[InlineData("")]
	[InlineData("   ")]
	[InlineData(".")]
	[InlineData("..")]
	[InlineData("...")]
	[InlineData("not-an-ip")]
	[InlineData("999.999.999.999")]
	[InlineData("hostname")]
	[InlineData("DESKTOP-X")]
	[InlineData("-")]
	[InlineData("N/A")]
	[InlineData("127.0.0.1")]
	[InlineData("::1")]
	public void InvalidOrLocal_ReturnsNull(string? input)
	{
		Assert.Null(IpNormalizer.Normalize(input));
	}

	[Fact]
	public void IsParseable_TracksNormalize()
	{
		Assert.True(IpNormalizer.IsParseable(".77.37.192.246"));
		Assert.True(IpNormalizer.IsParseable("::ffff:1.2.3.4"));
		Assert.False(IpNormalizer.IsParseable("not-an-ip"));
		Assert.False(IpNormalizer.IsParseable(null));
	}
}
