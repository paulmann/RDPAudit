// File:    tests/RdpAudit.Core.Tests/RdpListenerPortResolverTests.cs
// Module:  RdpAudit.Core.Tests
// Purpose: Validates the pure ClassifyRaw branch of RdpListenerPortResolver. The
//          Resolve() entry point reads HKLM and is Windows-only, so it is exercised
//          through the pure helper here — every meaningful path (registry value present
//          and valid; missing; out of range) maps to a deterministic outcome.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using RdpAudit.Core.Util;
using Xunit;

namespace RdpAudit.Core.Tests;

public class RdpListenerPortResolverTests
{
	[Fact]
	public void ClassifyRaw_RegistryValueValid_UsesRegistry()
	{
		RdpListenerPortResolution result = RdpListenerPortResolver.ClassifyRaw(55554);
		Assert.Equal(55554, result.Port);
		Assert.Equal(RdpListenerPortSource.Registry, result.Source);
		Assert.True(result.IsFromRegistry);
	}

	[Fact]
	public void ClassifyRaw_RegistryValueDefault3389_UsesRegistry()
	{
		RdpListenerPortResolution result = RdpListenerPortResolver.ClassifyRaw(3389);
		Assert.Equal(3389, result.Port);
		Assert.Equal(RdpListenerPortSource.Registry, result.Source);
	}

	[Fact]
	public void ClassifyRaw_NullValue_UsesDefault()
	{
		RdpListenerPortResolution result = RdpListenerPortResolver.ClassifyRaw(null);
		Assert.Equal(RdpConfigurationModel.DefaultRdpPort, result.Port);
		Assert.Equal(RdpListenerPortSource.Default, result.Source);
		Assert.False(result.IsFromRegistry);
		Assert.Contains("missing", result.Detail, System.StringComparison.OrdinalIgnoreCase);
	}

	[Theory]
	[InlineData(0)]
	[InlineData(-1)]
	[InlineData(65536)]
	[InlineData(int.MaxValue)]
	public void ClassifyRaw_OutOfRange_UsesDefaultWithDetail(int raw)
	{
		RdpListenerPortResolution result = RdpListenerPortResolver.ClassifyRaw(raw);
		Assert.Equal(RdpConfigurationModel.DefaultRdpPort, result.Port);
		Assert.Equal(RdpListenerPortSource.Default, result.Source);
		Assert.Contains("out of range", result.Detail, System.StringComparison.OrdinalIgnoreCase);
	}

	[Theory]
	[InlineData(1)]
	[InlineData(65535)]
	public void ClassifyRaw_EdgeValuesInRange_UsesRegistry(int raw)
	{
		RdpListenerPortResolution result = RdpListenerPortResolver.ClassifyRaw(raw);
		Assert.Equal(raw, result.Port);
		Assert.Equal(RdpListenerPortSource.Registry, result.Source);
	}
}
