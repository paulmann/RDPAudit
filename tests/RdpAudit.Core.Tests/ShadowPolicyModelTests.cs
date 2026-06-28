// File:    tests/RdpAudit.Core.Tests/ShadowPolicyModelTests.cs
// Module:  RdpAudit.Core.Tests
// Purpose: Validates the pure ShadowPolicyModel — value classification, mode/permission
//          mapping and the "enable all permissions" preset constant.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using RdpAudit.Core.Util;
using Xunit;

namespace RdpAudit.Core.Tests;

public class ShadowPolicyModelTests
{
	[Theory]
	[InlineData(0, true)]
	[InlineData(1, true)]
	[InlineData(2, true)]
	[InlineData(3, true)]
	[InlineData(4, true)]
	[InlineData(-1, false)]
	[InlineData(5, false)]
	[InlineData(int.MaxValue, false)]
	public void IsValidShadowValue_ReturnsExpected(int input, bool expected)
	{
		Assert.Equal(expected, ShadowPolicyModel.IsValidShadowValue(input));
	}

	[Fact]
	public void EnableAllPermissionsValue_MapsToFullControlNoConsent()
	{
		Assert.Equal((int)ShadowPolicyMode.FullControlNoConsent, ShadowPolicyModel.EnableAllPermissionsValue);
	}

	[Fact]
	public void FromRawValue_NullReturnsNotConfigured()
	{
		Assert.Equal(ShadowPolicyMode.NotConfigured, ShadowPolicyModel.FromRawValue(null));
	}

	[Fact]
	public void FromRawValue_OutOfRangeReturnsNotConfigured()
	{
		Assert.Equal(ShadowPolicyMode.NotConfigured, ShadowPolicyModel.FromRawValue(7));
	}

	[Theory]
	[InlineData(ShadowPolicyMode.NoShadow, SessionCommandBuilder.ShadowMode.ViewOnly, false)]
	[InlineData(ShadowPolicyMode.ViewWithConsent, SessionCommandBuilder.ShadowMode.ViewOnly, true)]
	[InlineData(ShadowPolicyMode.ViewWithConsent, SessionCommandBuilder.ShadowMode.Control, false)]
	[InlineData(ShadowPolicyMode.FullControlWithConsent, SessionCommandBuilder.ShadowMode.Control, true)]
	[InlineData(ShadowPolicyMode.FullControlWithConsent, SessionCommandBuilder.ShadowMode.ControlNoConsent, false)]
	[InlineData(ShadowPolicyMode.FullControlNoConsent, SessionCommandBuilder.ShadowMode.ControlNoConsent, true)]
	[InlineData(ShadowPolicyMode.FullControlNoConsent, SessionCommandBuilder.ShadowMode.ViewOnly, true)]
	public void AllowsMode_ReflectsPolicy(ShadowPolicyMode policy, SessionCommandBuilder.ShadowMode requested, bool expected)
	{
		Assert.Equal(expected, ShadowPolicyModel.AllowsMode(policy, requested));
	}

	[Fact]
	public void BackupRegistryKeys_IncludesGroupPolicyKey()
	{
		Assert.Contains(ShadowPolicyModel.TerminalServicesPolicyKey, ShadowPolicyModel.BackupRegistryKeys);
	}

	[Fact]
	public void Describe_KnownModes_ReturnsNonEmpty()
	{
		foreach (ShadowPolicyMode mode in Enum.GetValues<ShadowPolicyMode>())
		{
			Assert.False(string.IsNullOrWhiteSpace(ShadowPolicyModel.Describe(mode)));
		}
	}
}
