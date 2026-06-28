// File:    tests/RdpAudit.Core.Tests/EnforcementReconcilerHealthTests.cs
// Module:  RdpAudit.Core.Tests
// Purpose: Unit tests for EnforcementReconciler.DeriveHealth / DescribeHealth — the pure mapping that
//          turns reconciliation counts into the operator-facing Firewall enforcement health. Guards the
//          core guarantee that a "configured but unenforced" deployment can never read as Healthy.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using RdpAudit.Core.Firewall;
using RdpAudit.Core.Ipc.Contracts;
using Xunit;

namespace RdpAudit.Core.Tests;

/// <summary>Health-derivation scenarios mapping (enabledRows, verified, unenforced) to a health state.</summary>
public class EnforcementReconcilerHealthTests
{
	[Fact]
	public void DeriveHealth_NoEnabledRows_Idle()
	{
		Assert.Equal(FirewallEnforcementHealth.Idle, EnforcementReconciler.DeriveHealth(0, 0, 0));
	}

	[Fact]
	public void DeriveHealth_EnabledRowsButNothingVerified_MissingRule()
	{
		// The central guarantee: enabled blocks intended, zero verified enforcement → never Healthy.
		Assert.Equal(FirewallEnforcementHealth.MissingRule, EnforcementReconciler.DeriveHealth(5, 0, 5));
	}

	[Fact]
	public void DeriveHealth_PartiallyVerifiedWithUnenforced_Failed()
	{
		Assert.Equal(FirewallEnforcementHealth.Failed, EnforcementReconciler.DeriveHealth(5, 3, 2));
	}

	[Fact]
	public void DeriveHealth_AllVerifiedNoUnenforced_Healthy()
	{
		Assert.Equal(FirewallEnforcementHealth.Healthy, EnforcementReconciler.DeriveHealth(5, 5, 0));
	}

	[Fact]
	public void DeriveHealth_SomeVerifiedNoUnenforced_Healthy()
	{
		// Fewer verified than enabled but nothing flagged unenforced (e.g. expired rows fell out of scope).
		Assert.Equal(FirewallEnforcementHealth.Healthy, EnforcementReconciler.DeriveHealth(5, 3, 0));
	}

	[Fact]
	public void DescribeHealth_MissingRule_PointsToRepairAndVerify()
	{
		string text = EnforcementReconciler.DescribeHealth(FirewallEnforcementHealth.MissingRule, 5, 0);
		Assert.Contains("Repair selected", text, StringComparison.Ordinal);
		Assert.Contains("Verify all", text, StringComparison.Ordinal);
	}

	[Fact]
	public void DescribeHealth_Failed_PointsToRepairAndVerify()
	{
		string text = EnforcementReconciler.DescribeHealth(FirewallEnforcementHealth.Failed, 5, 3);
		Assert.Contains("Repair selected", text, StringComparison.Ordinal);
		Assert.Contains("Verify all", text, StringComparison.Ordinal);
	}

	[Fact]
	public void DescribeHealth_Healthy_ReportsVerifiedCount()
	{
		string text = EnforcementReconciler.DescribeHealth(FirewallEnforcementHealth.Healthy, 5, 5);
		Assert.Contains("5", text, StringComparison.Ordinal);
	}
}
