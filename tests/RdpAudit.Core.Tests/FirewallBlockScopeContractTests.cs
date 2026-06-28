// File:    tests/RdpAudit.Core.Tests/FirewallBlockScopeContractTests.cs
// Module:  RdpAudit.Core.Tests
// Purpose: Pins the persisted contract behind the Firewall "Block scope" dropdown. The Configurator
//          writes (int)FirewallBlockScope into config ("Firewall:BlockScope") and the Service binds
//          it straight back to FirewallOptions.BlockScope, so these enum ordinals are an on-disk ABI:
//          reordering or renumbering them would silently flip a saved "RDP port only" selection into
//          "All inbound" (or vice versa) on the next service read. These tests guard the exact int
//          values the dropdown options map to, and the backward-compatible default (AllInbound).
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using RdpAudit.Core.Config;
using Xunit;

namespace RdpAudit.Core.Tests;

public class FirewallBlockScopeContractTests
{
	[Fact]
	public void RdpPortOnly_HasStableOrdinalZero()
	{
		// The Configurator persists (int)scope; ordinal 0 must remain "RDP port only".
		Assert.Equal(0, (int)FirewallBlockScope.RdpPortOnly);
	}

	[Fact]
	public void AllInbound_HasStableOrdinalOne()
	{
		// Ordinal 1 must remain "All inbound traffic from IP".
		Assert.Equal(1, (int)FirewallBlockScope.AllInbound);
	}

	[Fact]
	public void DefaultBlockScope_IsAllInbound_ForBackwardCompatibility()
	{
		// Existing installs that never selected a scope must keep blocking all inbound traffic.
		FirewallOptions options = new();
		Assert.Equal(FirewallBlockScope.AllInbound, options.BlockScope);
	}
}
