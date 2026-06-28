// File:    tests/RdpAudit.Core.Tests/RouteBlackholeCommandBuilderTests.cs
// Module:  RdpAudit.Core.Tests
// Purpose: Unit tests for the experimental route-blackhole command builder: destination / gateway
//          validation, gateway classification (the gate that prevents forwarding attacker traffic
//          to a live next-hop), and the route add / delete / print argument vectors.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using RdpAudit.Core.Firewall;
using Xunit;

namespace RdpAudit.Core.Tests;

public class RouteBlackholeCommandBuilderTests
{
	[Theory]
	[InlineData("203.0.113.10")]
	[InlineData("8.8.8.8")]
	public void ParseAndValidateDestination_AcceptsIpv4(string ip)
	{
		Assert.Equal(ip, RouteBlackholeCommandBuilder.ParseAndValidateDestination(ip).ToString());
	}

	[Theory]
	[InlineData("not-an-ip")]
	[InlineData("999.1.1.1")]
	[InlineData("")]
	public void ParseAndValidateDestination_RejectsInvalid(string ip)
	{
		Assert.Throws<ArgumentException>(() => RouteBlackholeCommandBuilder.ParseAndValidateDestination(ip));
	}

	[Fact]
	public void ParseAndValidateDestination_RejectsIpv6()
	{
		Assert.Throws<ArgumentException>(() => RouteBlackholeCommandBuilder.ParseAndValidateDestination("2001:db8::1"));
	}

	[Fact]
	public void ClassifyGateway_UnreachableValidIpv4_IsUsable()
	{
		Assert.Equal(
			BlackholeGatewayValidation.UsableUnreachable,
			RouteBlackholeCommandBuilder.ClassifyGateway("10.255.255.254", isReachable: false));
	}

	[Fact]
	public void ClassifyGateway_ReachableGateway_IsUnsafe()
	{
		Assert.Equal(
			BlackholeGatewayValidation.ReachableUnsafe,
			RouteBlackholeCommandBuilder.ClassifyGateway("10.255.255.254", isReachable: true));
	}

	[Theory]
	[InlineData("not-an-ip")]
	[InlineData("2001:db8::1")]
	public void ClassifyGateway_InvalidOrIpv6_IsInvalidAddress(string gateway)
	{
		Assert.Equal(
			BlackholeGatewayValidation.InvalidAddress,
			RouteBlackholeCommandBuilder.ClassifyGateway(gateway, isReachable: false));
	}

	[Theory]
	[InlineData("127.0.0.1")]
	[InlineData("0.0.0.0")]
	[InlineData("255.255.255.255")]
	[InlineData("224.0.0.1")]
	[InlineData("239.1.2.3")]
	public void ClassifyGateway_ReservedNextHop_IsUnsuitable(string gateway)
	{
		Assert.Equal(
			BlackholeGatewayValidation.UnsuitableNextHop,
			RouteBlackholeCommandBuilder.ClassifyGateway(gateway, isReachable: false));
	}

	[Fact]
	public void BuildAddRouteArgs_EmitsHostRouteVector()
	{
		IReadOnlyList<string> args = RouteBlackholeCommandBuilder.BuildAddRouteArgs("203.0.113.10", "10.255.255.254");
		Assert.Equal(new[] { "add", "203.0.113.10", "mask", "255.255.255.255", "10.255.255.254" }, args);
	}

	[Fact]
	public void BuildDeleteRouteArgs_TargetsDestination()
	{
		IReadOnlyList<string> args = RouteBlackholeCommandBuilder.BuildDeleteRouteArgs("203.0.113.10");
		Assert.Equal(new[] { "delete", "203.0.113.10" }, args);
	}

	[Fact]
	public void BuildPrintRouteArgs_TargetsDestination()
	{
		IReadOnlyList<string> args = RouteBlackholeCommandBuilder.BuildPrintRouteArgs("203.0.113.10");
		Assert.Equal(new[] { "print", "203.0.113.10" }, args);
	}

	[Fact]
	public void BuildAddRouteArgs_RejectsIpv6Gateway()
	{
		Assert.Throws<ArgumentException>(() =>
			RouteBlackholeCommandBuilder.BuildAddRouteArgs("203.0.113.10", "2001:db8::1"));
	}
}
