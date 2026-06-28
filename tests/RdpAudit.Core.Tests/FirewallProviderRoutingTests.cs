// File:    tests/RdpAudit.Core.Tests/FirewallProviderRoutingTests.cs
// Module:  RdpAudit.Core.Tests
// Purpose: Unit tests for FirewallProviderRouting — the pure mapping from provider kind + local
//          enforcement backend to the stable IFirewallProvider.ProviderId string. Guarantees the
//          auto-block and expiration workers agree on which provider services a block so a row is
//          unblocked by the same provider that installed it.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using RdpAudit.Core.Config;
using RdpAudit.Core.Firewall;
using Xunit;

namespace RdpAudit.Core.Tests;

public class FirewallProviderRoutingTests
{
	[Fact]
	public void Windows_WithWindowsFirewallBackend_ResolvesWindows()
	{
		Assert.Equal(
			FirewallProviderRouting.WindowsProviderId,
			FirewallProviderRouting.ResolveProviderId(FirewallProviderKind.Windows, FirewallEnforcementBackend.WindowsFirewall));
	}

	[Fact]
	public void Windows_WithRouteBlackholeBackend_ResolvesRouteBlackhole()
	{
		Assert.Equal(
			FirewallProviderRouting.RouteBlackholeProviderId,
			FirewallProviderRouting.ResolveProviderId(FirewallProviderKind.Windows, FirewallEnforcementBackend.RouteBlackhole));
	}

	[Fact]
	public void Windows_WithIPsecBackend_ResolvesIPsec()
	{
		Assert.Equal(
			FirewallProviderRouting.IPsecProviderId,
			FirewallProviderRouting.ResolveProviderId(FirewallProviderKind.Windows, FirewallEnforcementBackend.IPsecPolicy));
	}

	[Theory]
	[InlineData(FirewallEnforcementBackend.WindowsFirewall)]
	[InlineData(FirewallEnforcementBackend.RouteBlackhole)]
	[InlineData(FirewallEnforcementBackend.IPsecPolicy)]
	public void MikroTik_AlwaysResolvesMikroTik_RegardlessOfBackend(FirewallEnforcementBackend backend)
	{
		Assert.Equal(
			FirewallProviderRouting.MikroTikProviderId,
			FirewallProviderRouting.ResolveProviderId(FirewallProviderKind.MikroTik, backend));
	}

	[Theory]
	[InlineData(FirewallProviderKind.None)]
	[InlineData(FirewallProviderKind.Both)]
	public void NoneOrBoth_ResolveEmpty(FirewallProviderKind kind)
	{
		Assert.Equal(string.Empty, FirewallProviderRouting.ResolveProviderId(kind, FirewallEnforcementBackend.WindowsFirewall));
	}
}
