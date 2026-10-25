// File:    tests/RdpAudit.Core.Tests/BlockExpiryCalculatorTests.cs
// Module:  RdpAudit.Core.Tests
// Purpose: Unit tests for BlockExpiryCalculator, pinning the v1.3.9 ExpiresUtc precedence
//          (explicit request > configured default > permanent). Regression guard for the manual-add
//          path that previously ignored DefaultBlockDurationMinutes and showed "Never" even when a
//          positive default was configured.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using RdpAudit.Core.Firewall;
using Xunit;

namespace RdpAudit.Core.Tests;

public class BlockExpiryCalculatorTests
{
	private static readonly DateTime Added = new(2026, 6, 10, 12, 0, 0, DateTimeKind.Utc);

	[Fact]
	public void ResolveDurationMinutes_ExplicitRequest_Wins()
	{
		Assert.Equal(15, BlockExpiryCalculator.ResolveDurationMinutes(requestedDurationMinutes: 15, defaultDurationMinutes: 60));
	}

	[Fact]
	public void ResolveDurationMinutes_NoRequest_UsesDefault()
	{
		Assert.Equal(60, BlockExpiryCalculator.ResolveDurationMinutes(requestedDurationMinutes: 0, defaultDurationMinutes: 60));
	}

	[Fact]
	public void ResolveDurationMinutes_NeitherPositive_ReturnsZeroMeaningPermanent()
	{
		Assert.Equal(0, BlockExpiryCalculator.ResolveDurationMinutes(requestedDurationMinutes: 0, defaultDurationMinutes: 0));
		Assert.Equal(0, BlockExpiryCalculator.ResolveDurationMinutes(requestedDurationMinutes: -5, defaultDurationMinutes: -1));
	}

	[Fact]
	public void ComputeExpiresUtc_ExplicitRequest_AddsRequestedMinutes()
	{
		DateTime? expires = BlockExpiryCalculator.ComputeExpiresUtc(Added, requestedDurationMinutes: 30, defaultDurationMinutes: 60);
		Assert.Equal(Added.AddMinutes(30), expires);
	}

	[Fact]
	public void ComputeExpiresUtc_NoRequest_UsesConfiguredDefault()
	{
		DateTime? expires = BlockExpiryCalculator.ComputeExpiresUtc(Added, requestedDurationMinutes: 0, defaultDurationMinutes: 120);
		Assert.Equal(Added.AddMinutes(120), expires);
	}

	[Fact]
	public void ComputeExpiresUtc_ZeroDefaultAndNoRequest_IsPermanentNull()
	{
		DateTime? expires = BlockExpiryCalculator.ComputeExpiresUtc(Added, requestedDurationMinutes: 0, defaultDurationMinutes: 0);
		Assert.Null(expires);
	}

	[Fact]
	public void ComputeExpiresUtc_NegativeInputs_IsPermanentNull()
	{
		DateTime? expires = BlockExpiryCalculator.ComputeExpiresUtc(Added, requestedDurationMinutes: -10, defaultDurationMinutes: -3);
		Assert.Null(expires);
	}
}
