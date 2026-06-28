// File:    tests/RdpAudit.Core.Tests/IpClassifierTests.cs
// Module:  RdpAudit.Core.Tests
// Purpose: Validates IpClassifier coverage for RFC1918 and special-purpose ranges.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using RdpAudit.Core.Util;
using Xunit;

namespace RdpAudit.Core.Tests;

/// <summary>Validates IpClassifier coverage for RFC1918 and special-purpose ranges.</summary>
public class IpClassifierTests
{
	[Theory]
	[InlineData("10.0.0.1", false)]
	[InlineData("172.16.0.1", false)]
	[InlineData("172.31.255.255", false)]
	[InlineData("172.32.0.1", true)]
	[InlineData("192.168.1.100", false)]
	[InlineData("169.254.1.1", false)]
	[InlineData("100.64.0.1", false)]
	[InlineData("100.127.255.255", false)]
	[InlineData("127.0.0.1", false)]
	[InlineData("0.0.0.0", false)]
	[InlineData("224.0.0.1", false)]
	[InlineData("8.8.8.8", true)]
	[InlineData("185.220.101.1", true)]
	[InlineData("::1", false)]
	[InlineData("fe80::1", false)]
	[InlineData("2001:db8::1", true)]
	[InlineData("not-an-ip", false)]
	[InlineData("", false)]
	public void IsPublicIp_ReturnsExpected(string ip, bool expected)
	{
		Assert.Equal(expected, IpClassifier.IsPublicIp(ip));
	}

	[Theory]
	[InlineData("-", true)]
	[InlineData("LOCAL", true)]
	[InlineData("0.0.0.0", true)]
	[InlineData("127.0.0.1", true)]
	[InlineData("8.8.8.8", false)]
	public void IsLocalSentinel_RecognisesKnownValues(string value, bool expected)
	{
		Assert.Equal(expected, IpClassifier.IsLocalSentinel(value));
	}
}
