// File:    tests/RdpAudit.Core.Tests/FirewallContractTests.cs
// Module:  RdpAudit.Core.Tests
// Purpose: Validates invariants on the firewall abstraction DTOs and provider-kind enum.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com
// Version: 1.4.2

using RdpAudit.Core.Config;
using RdpAudit.Core.Firewall;
using Xunit;

namespace RdpAudit.Core.Tests;

/// <summary>Invariants on the firewall abstraction DTOs and provider-kind enum.</summary>
public class FirewallContractTests
{
	[Fact]
	public void FirewallProviderKind_OrdinalsAreStable()
	{
		Assert.Equal(0, (int)FirewallProviderKind.None);
		Assert.Equal(1, (int)FirewallProviderKind.Windows);
		Assert.Equal(2, (int)FirewallProviderKind.MikroTik);
		Assert.Equal(3, (int)FirewallProviderKind.Both);
	}

	[Fact]
	public void FirewallActionStatus_OrdinalsAreStable()
	{
		Assert.Equal(0, (int)FirewallActionStatus.Success);
		Assert.Equal(1, (int)FirewallActionStatus.NotImplemented);
		Assert.Equal(2, (int)FirewallActionStatus.Unavailable);
		Assert.Equal(3, (int)FirewallActionStatus.Refused);
		Assert.Equal(4, (int)FirewallActionStatus.InvalidRequest);
		Assert.Equal(5, (int)FirewallActionStatus.AlreadyExists);
		Assert.Equal(6, (int)FirewallActionStatus.NotFound);
	}

	[Fact]
	public void FirewallProviderStatus_OrdinalsAreStable()
	{
		Assert.Equal(0, (int)FirewallProviderStatus.Available);
		Assert.Equal(1, (int)FirewallProviderStatus.Unreachable);
		Assert.Equal(2, (int)FirewallProviderStatus.Disabled);
		Assert.Equal(3, (int)FirewallProviderStatus.NotConfigured);
		Assert.Equal(4, (int)FirewallProviderStatus.NotImplemented);
	}

	[Fact]
	public void BlockRequest_RejectsEmptyArguments()
	{
		Assert.Throws<ArgumentException>(() => new FirewallBlockRequest(string.Empty, "rule"));
		Assert.Throws<ArgumentException>(() => new FirewallBlockRequest("1.2.3.4", string.Empty));
		Assert.Throws<ArgumentNullException>(() => new FirewallBlockRequest(null!, "rule"));
	}

	[Fact]
	public void NotImplementedHelper_ProducesStableShape()
	{
		FirewallActionResult result = FirewallActionResult.NotImplementedFor("Windows", "Block");

		Assert.Equal(FirewallActionStatus.NotImplemented, result.Status);
		Assert.Equal("Windows", result.ProviderId);
		Assert.NotNull(result.Message);
		Assert.Contains("Windows", result.Message!, StringComparison.Ordinal);
	}

	[Fact]
	public void FirewallOptions_DefaultsAreBackwardCompatible()
	{
		FirewallOptions opts = new();

		Assert.False(opts.AutoBlockBruteForce);
		Assert.Equal(50, opts.AutoBlockThreshold);
		Assert.Equal("RdpAudit-Block", opts.BlockRuleName);
		Assert.Equal(FirewallProviderKind.Windows, opts.Provider);
		Assert.Empty(opts.Whitelist);
		Assert.Empty(opts.Blacklist);
		Assert.False(opts.BlockOnBlacklistedLogin);
		Assert.Empty(opts.InstantBlockLogins);
		Assert.Equal(4320, opts.DefaultBlockDurationMinutes);
		Assert.True(opts.MaxActiveBlocks > 0);
	}
}
