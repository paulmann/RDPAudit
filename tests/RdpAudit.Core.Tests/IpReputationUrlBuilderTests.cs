// File:    tests/RdpAudit.Core.Tests/IpReputationUrlBuilderTests.cs
// Module:  RdpAudit.Core.Tests
// Purpose: Stage 3 URL composition tests for the RIPEstat / AbuseIPDB deep-link builders. Verifies
//          the shared validation pipeline accepts valid IPv4 / IPv6 (including bracketed and
//          IPv4-mapped IPv6) and rejects hostnames, blanks, "(unresolved)" sentinels, "-", "0.0.0.0"
//          and IPv6 unspecified. Also pins the canonical URL formats so accidental template changes
//          are caught immediately.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using RdpAudit.Core.Util;
using Xunit;

namespace RdpAudit.Core.Tests;

public class IpReputationUrlBuilderTests
{
	[Theory]
	[InlineData("8.8.8.8", "https://stat.ripe.net/resource/8.8.8.8#tab=overview")]
	[InlineData(" 8.8.8.8 ", "https://stat.ripe.net/resource/8.8.8.8#tab=overview")]
	[InlineData("2001:db8::1", "https://stat.ripe.net/resource/2001:db8::1#tab=overview")]
	[InlineData("[2001:db8::1]", "https://stat.ripe.net/resource/2001:db8::1#tab=overview")]
	public void BuildRipeStat_AcceptsValidIp(string ip, string expected)
	{
		IpReputationUrlBuilder.Result r = IpReputationUrlBuilder.BuildRipeStat(ip);
		Assert.True(r.Ok);
		Assert.Equal(expected, r.Url);
		Assert.Null(r.Error);
	}

	[Theory]
	[InlineData("8.8.8.8", "https://www.abuseipdb.com/check/8.8.8.8")]
	[InlineData("2001:db8::1", "https://www.abuseipdb.com/check/2001:db8::1")]
	[InlineData("[2001:db8::1]", "https://www.abuseipdb.com/check/2001:db8::1")]
	public void BuildAbuseIpDb_AcceptsValidIp(string ip, string expected)
	{
		IpReputationUrlBuilder.Result r = IpReputationUrlBuilder.BuildAbuseIpDb(ip);
		Assert.True(r.Ok);
		Assert.Equal(expected, r.Url);
		Assert.Null(r.Error);
	}

	[Theory]
	[InlineData(null)]
	[InlineData("")]
	[InlineData("   ")]
	[InlineData("\t")]
	public void BuildRipeStat_RejectsBlankInput(string? ip)
	{
		IpReputationUrlBuilder.Result r = IpReputationUrlBuilder.BuildRipeStat(ip);
		Assert.False(r.Ok);
		Assert.NotNull(r.Error);
	}

	[Theory]
	[InlineData("(unresolved)")]
	[InlineData("unresolved")]
	[InlineData("-")]
	[InlineData("--")]
	[InlineData("N/A")]
	[InlineData("n/a")]
	[InlineData("null")]
	[InlineData("none")]
	[InlineData("unknown")]
	[InlineData("localhost")]
	[InlineData("LOCAL")]
	public void BuildRipeStat_RejectsSentinel(string ip)
	{
		IpReputationUrlBuilder.Result r = IpReputationUrlBuilder.BuildRipeStat(ip);
		Assert.False(r.Ok);
		Assert.NotNull(r.Error);
	}

	[Theory]
	[InlineData("0.0.0.0")]
	[InlineData("::")]
	[InlineData("[::]")]
	public void BuildRipeStat_RejectsUnspecifiedAddress(string ip)
	{
		IpReputationUrlBuilder.Result r = IpReputationUrlBuilder.BuildRipeStat(ip);
		Assert.False(r.Ok);
		Assert.NotNull(r.Error);
	}

	[Theory]
	[InlineData("example.com")]
	[InlineData("router.lab")]
	[InlineData("not an ip")]
	[InlineData("999.999.999.999")]
	[InlineData("8.8.8.8 extra")]
	public void BuildRipeStat_RejectsHostnameOrGarbage(string ip)
	{
		IpReputationUrlBuilder.Result r = IpReputationUrlBuilder.BuildRipeStat(ip);
		Assert.False(r.Ok);
		Assert.NotNull(r.Error);
	}

	[Fact]
	public void BuildRipeStat_StripsIpv6ZoneIdentifier()
	{
		IpReputationUrlBuilder.Result r = IpReputationUrlBuilder.BuildRipeStat("fe80::1%eth0");
		Assert.True(r.Ok);
		Assert.Equal("https://stat.ripe.net/resource/fe80::1#tab=overview", r.Url);
	}

	[Fact]
	public void BuildRipeStat_CollapsesIpv4MappedIpv6_ToIpv4()
	{
		IpReputationUrlBuilder.Result r = IpReputationUrlBuilder.BuildRipeStat("::ffff:1.2.3.4");
		Assert.True(r.Ok);
		Assert.Equal("https://stat.ripe.net/resource/1.2.3.4#tab=overview", r.Url);
	}

	[Fact]
	public void BuildAbuseIpDb_CollapsesIpv4MappedIpv6_ToIpv4()
	{
		IpReputationUrlBuilder.Result r = IpReputationUrlBuilder.BuildAbuseIpDb("::ffff:8.8.8.8");
		Assert.True(r.Ok);
		Assert.Equal("https://www.abuseipdb.com/check/8.8.8.8", r.Url);
	}

	[Fact]
	public void IsLookupEligible_AgreesWithBuilder()
	{
		Assert.True(IpReputationUrlBuilder.IsLookupEligible("1.1.1.1"));
		Assert.True(IpReputationUrlBuilder.IsLookupEligible("2001:db8::1"));
		Assert.False(IpReputationUrlBuilder.IsLookupEligible(null));
		Assert.False(IpReputationUrlBuilder.IsLookupEligible("0.0.0.0"));
		Assert.False(IpReputationUrlBuilder.IsLookupEligible("(unresolved)"));
		Assert.False(IpReputationUrlBuilder.IsLookupEligible("example.com"));
	}

	[Fact]
	public void Loopback_IsAccepted_BecauseRipeStatHandlesItGracefully()
	{
		// Loopback is a real IP literal; the upstream services display a "no data" page rather
		// than rejecting the request. The Configurator already filters loopback rows from most
		// grids via IpClassifier; this builder only needs to gate sentinels / blanks.
		IpReputationUrlBuilder.Result r = IpReputationUrlBuilder.BuildRipeStat("127.0.0.1");
		Assert.True(r.Ok);
		Assert.Equal("https://stat.ripe.net/resource/127.0.0.1#tab=overview", r.Url);
	}
}
