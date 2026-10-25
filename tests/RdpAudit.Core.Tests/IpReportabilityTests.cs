// File:    tests/RdpAudit.Core.Tests/IpReportabilityTests.cs
// Module:  RdpAudit.Core.Tests
// Purpose: Validates the centralized IpReportability classifier across IPv4 private/public, IPv6
//          link-local / loopback / unique-local / multicast, CGNAT, documentation/test, reserved,
//          invalid, unresolved, and whitelisted inputs. Covers the live-RDP diagnostics fixtures
//          named in the brief (77.37.192.246 public, 192.168.x private, fe80::/10 link-local).
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using RdpAudit.Core.Util;
using Xunit;

namespace RdpAudit.Core.Tests;

/// <summary>Validates the centralized reportability classifier.</summary>
public class IpReportabilityTests
{
	[Theory]
	// Public — reportable.
	[InlineData("77.37.192.246", IpReportClassification.Public, true)]
	[InlineData("8.8.8.8", IpReportClassification.Public, true)]
	[InlineData("185.220.101.1", IpReportClassification.Public, true)]
	[InlineData("2001:4860:4860::8888", IpReportClassification.Public, true)]
	// Private RFC1918.
	[InlineData("10.0.0.1", IpReportClassification.Private, false)]
	[InlineData("172.16.0.1", IpReportClassification.Private, false)]
	[InlineData("172.31.255.255", IpReportClassification.Private, false)]
	[InlineData("192.168.1.60", IpReportClassification.Private, false)]
	// Public boundary just outside RFC1918.
	[InlineData("172.32.0.1", IpReportClassification.Public, true)]
	// Loopback.
	[InlineData("127.0.0.1", IpReportClassification.Loopback, false)]
	[InlineData("::1", IpReportClassification.Loopback, false)]
	// Link-local / APIPA.
	[InlineData("169.254.1.1", IpReportClassification.LinkLocal, false)]
	[InlineData("fe80::1", IpReportClassification.LinkLocal, false)]
	[InlineData("fe80::ef3c:55b2:5545:ca8c", IpReportClassification.LinkLocal, false)]
	// CGNAT.
	[InlineData("100.64.0.1", IpReportClassification.Cgnat, false)]
	[InlineData("100.127.255.255", IpReportClassification.Cgnat, false)]
	// Reserved / protocol.
	[InlineData("0.0.0.0", IpReportClassification.SpecialPurpose, false)]
	[InlineData("192.0.0.1", IpReportClassification.SpecialPurpose, false)]
	[InlineData("240.0.0.1", IpReportClassification.SpecialPurpose, false)]
	[InlineData("255.255.255.255", IpReportClassification.SpecialPurpose, false)]
	[InlineData("fc00::1", IpReportClassification.SpecialPurpose, false)]
	[InlineData("fd12:3456::1", IpReportClassification.SpecialPurpose, false)]
	// Documentation / test.
	[InlineData("192.0.2.10", IpReportClassification.Documentation, false)]
	[InlineData("198.51.100.5", IpReportClassification.Documentation, false)]
	[InlineData("203.0.113.10", IpReportClassification.Documentation, false)]
	[InlineData("2001:db8::1", IpReportClassification.Documentation, false)]
	// Multicast.
	[InlineData("224.0.0.1", IpReportClassification.Multicast, false)]
	[InlineData("239.255.255.250", IpReportClassification.Multicast, false)]
	[InlineData("ff02::1", IpReportClassification.Multicast, false)]
	// Invalid / unresolved.
	[InlineData("not-an-ip", IpReportClassification.Invalid, false)]
	[InlineData("example.com", IpReportClassification.Invalid, false)]
	[InlineData("", IpReportClassification.Unresolved, false)]
	[InlineData("-", IpReportClassification.Unresolved, false)]
	[InlineData("unresolved", IpReportClassification.Unresolved, false)]
	[InlineData("unknown", IpReportClassification.Unresolved, false)]
	[InlineData("(unresolved)", IpReportClassification.Unresolved, false)]
	public void Classify_ReturnsExpectedClassificationAndReportability(
		string ip, IpReportClassification expected, bool reportable)
	{
		IpReportabilityResult result = IpReportability.Classify(ip);
		Assert.Equal(expected, result.Classification);
		Assert.Equal(reportable, result.IsReportable);
	}

	[Fact]
	public void Classify_Null_IsUnresolved()
	{
		IpReportabilityResult result = IpReportability.Classify(null);
		Assert.Equal(IpReportClassification.Unresolved, result.Classification);
		Assert.False(result.IsReportable);
	}

	[Fact]
	public void Classify_WhitelistedPublicIp_NotReportable_ReasonWhitelisted()
	{
		IpReportabilityResult result = IpReportability.Classify(
			"77.37.192.246",
			ip => string.Equals(ip, "77.37.192.246", System.StringComparison.Ordinal));

		Assert.Equal(IpReportClassification.Whitelisted, result.Classification);
		Assert.False(result.IsReportable);
		Assert.Equal(IpReportability.Reasons.WhitelistedIp, result.Reason);
	}

	[Fact]
	public void Classify_WhitelistPredicateNotMatchingPublicIp_StaysReportable()
	{
		IpReportabilityResult result = IpReportability.Classify(
			"77.37.192.246",
			ip => string.Equals(ip, "1.2.3.4", System.StringComparison.Ordinal));

		Assert.Equal(IpReportClassification.Public, result.Classification);
		Assert.True(result.IsReportable);
	}

	[Fact]
	public void Classify_PrivateIp_NotConsultedAgainstWhitelist()
	{
		bool predicateCalled = false;
		IpReportabilityResult result = IpReportability.Classify(
			"192.168.1.60",
			_ => { predicateCalled = true; return true; });

		Assert.Equal(IpReportClassification.Private, result.Classification);
		Assert.False(result.IsReportable);
		Assert.False(predicateCalled);
	}

	[Theory]
	[InlineData("77.37.192.246", true)]
	[InlineData("192.168.1.60", false)]
	[InlineData("fe80::1", false)]
	[InlineData("unresolved", false)]
	public void IsPublic_MatchesClassification(string ip, bool expected)
	{
		Assert.Equal(expected, IpReportability.IsPublic(ip));
	}

	[Fact]
	public void Classify_NormalizesWrappedIpv6AndPortSuffix()
	{
		Assert.Equal(IpReportClassification.Public, IpReportability.Classify("[2001:4860:4860::8888]:443").Classification);
		Assert.Equal(IpReportClassification.Public, IpReportability.Classify("77.37.192.246:8701").Classification);
		Assert.Equal(IpReportClassification.LinkLocal, IpReportability.Classify("fe80::1%11").Classification);
	}

	[Fact]
	public void Reason_TokensMatchKnownSet()
	{
		Assert.Equal(IpReportability.Reasons.PrivateIp, IpReportability.Classify("10.0.0.1").Reason);
		Assert.Equal(IpReportability.Reasons.LoopbackIp, IpReportability.Classify("127.0.0.1").Reason);
		Assert.Equal(IpReportability.Reasons.LinkLocalIp, IpReportability.Classify("169.254.1.1").Reason);
		Assert.Equal(IpReportability.Reasons.CgnatIp, IpReportability.Classify("100.64.0.1").Reason);
		Assert.Equal(IpReportability.Reasons.MulticastIp, IpReportability.Classify("224.0.0.1").Reason);
		Assert.Equal(IpReportability.Reasons.DocumentationIp, IpReportability.Classify("203.0.113.10").Reason);
		Assert.Equal(IpReportability.Reasons.ReservedIp, IpReportability.Classify("240.0.0.1").Reason);
		Assert.Equal(IpReportability.Reasons.InvalidIp, IpReportability.Classify("nope").Reason);
		Assert.Equal(IpReportability.Reasons.UnresolvedIp, IpReportability.Classify("-").Reason);
	}
}
