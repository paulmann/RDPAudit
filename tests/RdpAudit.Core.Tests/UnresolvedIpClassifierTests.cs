// File:    tests/RdpAudit.Core.Tests/UnresolvedIpClassifierTests.cs
// Module:  RdpAudit.Core.Tests
// Purpose: Unit tests for UnresolvedIpClassifier — pinning the reason taxonomy used by the Attack
//          Statistics tab to group the unresolved-IP sentinel by *why* a logon event lacked a usable
//          source IP (parser error, missing security-event IP, correlation miss, invalid value,
//          private/loopback).
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using RdpAudit.Core.Models;
using Xunit;

namespace RdpAudit.Core.Tests;

public class UnresolvedIpClassifierTests
{
	[Fact]
	public void UnparsablePayload_IsParserError()
	{
		UnresolvedIpReason reason = UnresolvedIpClassifier.Classify(
			rawIpValue: "203.0.113.10",
			payloadParsed: false,
			expectedIpSlot: true,
			correlationAttempted: false);

		Assert.Equal(UnresolvedIpReason.ParserError, reason);
	}

	[Theory]
	[InlineData(null)]
	[InlineData("")]
	[InlineData("   ")]
	[InlineData("-")]
	public void BlankSecurityEventSlot_WithoutCorrelation_IsNoIpInSecurityEvent(string? raw)
	{
		UnresolvedIpReason reason = UnresolvedIpClassifier.Classify(
			rawIpValue: raw,
			payloadParsed: true,
			expectedIpSlot: true,
			correlationAttempted: false);

		Assert.Equal(UnresolvedIpReason.NoIpInSecurityEvent, reason);
	}

	[Fact]
	public void BlankValue_AfterCorrelationAttempt_IsCorrelationFailed()
	{
		UnresolvedIpReason reason = UnresolvedIpClassifier.Classify(
			rawIpValue: null,
			payloadParsed: true,
			expectedIpSlot: true,
			correlationAttempted: true);

		Assert.Equal(UnresolvedIpReason.CorrelationFailed, reason);
	}

	[Fact]
	public void BlankValue_NoSlotNoCorrelation_IsCorrelationFailed()
	{
		UnresolvedIpReason reason = UnresolvedIpClassifier.Classify(
			rawIpValue: "",
			payloadParsed: true,
			expectedIpSlot: false,
			correlationAttempted: false);

		Assert.Equal(UnresolvedIpReason.CorrelationFailed, reason);
	}

	[Theory]
	[InlineData("not-an-ip")]
	[InlineData("999.999.999.999")]
	[InlineData("::ffff:garbage")]
	public void NonEmptyButUnparseable_IsInvalidIp(string raw)
	{
		UnresolvedIpReason reason = UnresolvedIpClassifier.Classify(
			rawIpValue: raw,
			payloadParsed: true,
			expectedIpSlot: true,
			correlationAttempted: false);

		Assert.Equal(UnresolvedIpReason.InvalidIp, reason);
	}

	[Theory]
	[InlineData("10.0.0.5")]
	[InlineData("172.16.4.9")]
	[InlineData("172.31.255.1")]
	[InlineData("192.168.1.1")]
	[InlineData("169.254.10.20")]
	[InlineData("127.0.0.1")]
	[InlineData("0.0.0.0")]
	[InlineData("::1")]
	[InlineData("fe80::1")]
	[InlineData("fc00::1")]
	public void PrivateOrLoopback_IsIgnoredPrivateLoopback(string raw)
	{
		UnresolvedIpReason reason = UnresolvedIpClassifier.Classify(
			rawIpValue: raw,
			payloadParsed: true,
			expectedIpSlot: true,
			correlationAttempted: false);

		Assert.Equal(UnresolvedIpReason.IgnoredPrivateLoopback, reason);
	}

	[Theory]
	[InlineData("203.0.113.10")]
	[InlineData("8.8.8.8")]
	[InlineData("2606:4700:4700::1111")]
	public void RoutablePublicAddress_IsNone(string raw)
	{
		UnresolvedIpReason reason = UnresolvedIpClassifier.Classify(
			rawIpValue: raw,
			payloadParsed: true,
			expectedIpSlot: true,
			correlationAttempted: true);

		Assert.Equal(UnresolvedIpReason.None, reason);
	}

	[Fact]
	public void NonPublicHostBytes_172_15_IsNotPrivate()
	{
		// 172.15.x is outside the 172.16.0.0/12 private block and must classify as a real public IP.
		UnresolvedIpReason reason = UnresolvedIpClassifier.Classify(
			rawIpValue: "172.15.0.1",
			payloadParsed: true,
			expectedIpSlot: true,
			correlationAttempted: false);

		Assert.Equal(UnresolvedIpReason.None, reason);
	}

	[Theory]
	[InlineData(UnresolvedIpReason.None, "Resolved")]
	[InlineData(UnresolvedIpReason.NoIpInSecurityEvent, "No IP in security event")]
	[InlineData(UnresolvedIpReason.CorrelationFailed, "Session correlation failed")]
	[InlineData(UnresolvedIpReason.InvalidIp, "Invalid IP value")]
	[InlineData(UnresolvedIpReason.IgnoredPrivateLoopback, "Private / loopback (ignored)")]
	[InlineData(UnresolvedIpReason.ParserError, "Event payload parse error")]
	public void Describe_ReturnsStableLabel(UnresolvedIpReason reason, string expected)
	{
		Assert.Equal(expected, UnresolvedIpClassifier.Describe(reason));
	}

	[Fact]
	public void EnumOrdinals_AreAppendOnlyStable()
	{
		Assert.Equal(0, (int)UnresolvedIpReason.None);
		Assert.Equal(1, (int)UnresolvedIpReason.NoIpInSecurityEvent);
		Assert.Equal(2, (int)UnresolvedIpReason.CorrelationFailed);
		Assert.Equal(3, (int)UnresolvedIpReason.InvalidIp);
		Assert.Equal(4, (int)UnresolvedIpReason.IgnoredPrivateLoopback);
		Assert.Equal(5, (int)UnresolvedIpReason.ParserError);
	}
}
