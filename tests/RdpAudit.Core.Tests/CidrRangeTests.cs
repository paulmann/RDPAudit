// File:    tests/RdpAudit.Core.Tests/CidrRangeTests.cs
// Module:  RdpAudit.Core.Tests
// Purpose: Unit tests for CidrRange — IPv4 and IPv6 parsing, host-bit canonicalisation, and the
//          family-aware bitwise prefix membership test used by the firewall whitelist. Covers the
//          five private/local networks the "Add local network IPs" button inserts so a regression
//          in range matching (which would silently let those ranges be auto-blocked) is caught.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com
// Version: 1.0.0

using RdpAudit.Core.Util;
using Xunit;

namespace RdpAudit.Core.Tests;

public class CidrRangeTests
{
	// ── Parsing ──────────────────────────────────────────────────────────────────

	[Theory]
	[InlineData("10.0.0.0/8")]
	[InlineData("172.16.0.0/12")]
	[InlineData("192.168.0.0/16")]
	[InlineData("fc00::/7")]
	[InlineData("fd00::/8")]
	[InlineData("0.0.0.0/0")]
	[InlineData("::/0")]
	[InlineData("203.0.113.5/32")]
	[InlineData("2001:db8::1/128")]
	public void TryParse_ValidCidr_Succeeds(string text)
	{
		Assert.True(CidrRange.TryParse(text, out CidrRange? range));
		Assert.NotNull(range);
	}

	[Theory]
	[InlineData("")]
	[InlineData("   ")]
	[InlineData("10.0.0.0")]            // no prefix
	[InlineData("10.0.0.0/")]           // empty prefix
	[InlineData("/8")]                  // empty address
	[InlineData("10.0.0.0/33")]         // IPv4 prefix out of range
	[InlineData("fc00::/129")]          // IPv6 prefix out of range
	[InlineData("10.0.0.0/-1")]         // negative prefix
	[InlineData("not-an-ip/8")]         // bad address
	[InlineData("10.0.0.0/abc")]        // non-numeric prefix
	[InlineData("10.0.0.0/ 8")]         // whitespace in prefix
	public void TryParse_InvalidCidr_Fails(string text)
	{
		Assert.False(CidrRange.TryParse(text, out CidrRange? range));
		Assert.Null(range);
	}

	[Fact]
	public void Parse_CanonicalisesHostBits()
	{
		// Host bits beyond the prefix must be masked to zero in the textual form.
		Assert.Equal("10.0.0.0/8", CidrRange.Parse("10.123.45.67/8").ToString());
		Assert.Equal("192.168.0.0/16", CidrRange.Parse("192.168.5.9/16").ToString());
	}

	// ── IPv4 membership ────────────────────────────────────────────────────────────

	[Theory]
	[InlineData("10.0.0.0/8", "10.0.0.1", true)]
	[InlineData("10.0.0.0/8", "10.255.255.254", true)]
	[InlineData("10.0.0.0/8", "11.0.0.1", false)]
	[InlineData("172.16.0.0/12", "172.16.0.5", true)]
	[InlineData("172.16.0.0/12", "172.31.255.255", true)]
	[InlineData("172.16.0.0/12", "172.32.0.1", false)]
	[InlineData("172.16.0.0/12", "172.15.255.255", false)]
	[InlineData("192.168.0.0/16", "192.168.1.60", true)]
	[InlineData("192.168.0.0/16", "192.169.0.1", false)]
	public void Contains_Ipv4_ReturnsExpected(string cidr, string ip, bool expected)
		=> Assert.Equal(expected, CidrRange.Parse(cidr).Contains(ip));

	// ── IPv6 membership ────────────────────────────────────────────────────────────

	[Theory]
	[InlineData("fc00::/7", "fc00::1", true)]
	[InlineData("fc00::/7", "fdff:ffff::1", true)]   // fd00::/8 is inside fc00::/7
	[InlineData("fc00::/7", "fe80::1", false)]       // link-local is outside fc00::/7
	[InlineData("fd00::/8", "fd12:3456::1", true)]
	[InlineData("fd00::/8", "fc00::1", false)]       // fc00::/8 is not in fd00::/8
	[InlineData("fd00::/8", "fe00::1", false)]
	public void Contains_Ipv6_ReturnsExpected(string cidr, string ip, bool expected)
		=> Assert.Equal(expected, CidrRange.Parse(cidr).Contains(ip));

	// ── Family isolation ───────────────────────────────────────────────────────────

	[Fact]
	public void Contains_DifferentFamily_ReturnsFalse()
	{
		// An IPv4 host must never match an IPv6 network or vice versa.
		Assert.False(CidrRange.Parse("fc00::/7").Contains("10.0.0.1"));
		Assert.False(CidrRange.Parse("10.0.0.0/8").Contains("fc00::1"));
	}

	[Fact]
	public void Contains_NullOrInvalid_ReturnsFalse()
	{
		CidrRange range = CidrRange.Parse("10.0.0.0/8");
		Assert.False(range.Contains((string?)null));
		Assert.False(range.Contains("   "));
		Assert.False(range.Contains("not-an-ip"));
	}

	// ── Zero-prefix (match all in family) ────────────────────────────────────────────

	[Fact]
	public void Contains_ZeroPrefix_MatchesEntireFamily()
	{
		Assert.True(CidrRange.Parse("0.0.0.0/0").Contains("8.8.8.8"));
		Assert.True(CidrRange.Parse("::/0").Contains("2001:db8::1"));
		Assert.False(CidrRange.Parse("0.0.0.0/0").Contains("2001:db8::1")); // family still isolates
	}

	// ── Equality ───────────────────────────────────────────────────────────────────

	[Fact]
	public void Equals_SameNetwork_IsTrue()
	{
		Assert.Equal(CidrRange.Parse("10.0.0.0/8"), CidrRange.Parse("10.5.6.7/8"));
		Assert.Equal(
			CidrRange.Parse("10.0.0.0/8").GetHashCode(),
			CidrRange.Parse("10.5.6.7/8").GetHashCode());
	}
}
