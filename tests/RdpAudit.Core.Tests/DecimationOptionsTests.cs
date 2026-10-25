// File:    tests/RdpAudit.Core.Tests/DecimationOptionsTests.cs
// Module:  RdpAudit.Core.Tests
// Purpose: Locks the frequency-decimation defaults and clamping policy: disabled by default,
//          the [7..] minimum-age floor, the [10..] burst-gap floor, the [10,000..] candidate
//          threshold floor, the [1..100,000] per-burst keep range, the [1..32] candidate-count
//          range, and the [100..100,000] delete batch range. A regression here could let the
//          retention worker delete head/tail rows, scan arbitrarily many event ids, or hold the
//          writer lock for unbounded deletes.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using RdpAudit.Core.Config;
using Xunit;

namespace RdpAudit.Core.Tests;

/// <summary>Pins the decimation option defaults and clamping behaviour.</summary>
public class DecimationOptionsTests
{
	[Fact]
	public void Defaults_AreDisabledWithSafeWideSettings()
	{
		DecimationOptions options = new();
		Assert.False(options.Enabled);
		Assert.Equal(30, options.MinAgeDays);
		Assert.Equal(300, options.BurstGapSeconds);
		Assert.Equal(100_000, options.CandidateMinRows);
		Assert.Equal(100, options.HeadKeepPerBurst);
		Assert.Equal(100, options.TailKeepPerBurst);
		Assert.Equal(5, options.MaxCandidateEventIds);
		Assert.Equal(5_000, options.BatchSize);
	}

	[Theory]
	[InlineData(0, 7)]
	[InlineData(-40, 7)]
	[InlineData(7, 7)]
	[InlineData(30, 30)]
	[InlineData(365, 365)]
	[InlineData(int.MaxValue, DecimationOptions.MaxMinAgeDays)]
	public void ResolveMinAgeDays_ClampsToSupportedRange(int input, int expected)
	{
		DecimationOptions options = new() { MinAgeDays = input };
		Assert.Equal(expected, options.ResolveMinAgeDays());
	}

	[Theory]
	[InlineData(0, 10)]
	[InlineData(-10, 10)]
	[InlineData(10, 10)]
	[InlineData(300, 300)]
	[InlineData(86_400, 86_400)]
	public void ResolveBurstGapSeconds_ClampsToFloor(int input, int expected)
	{
		DecimationOptions options = new() { BurstGapSeconds = input };
		Assert.Equal(expected, options.ResolveBurstGapSeconds());
	}

	[Theory]
	[InlineData(0, 10_000)]
	[InlineData(-7, 10_000)]
	[InlineData(10_000, 10_000)]
	[InlineData(100_000, 100_000)]
	[InlineData(5_000_000, 5_000_000)]
	public void ResolveCandidateMinRows_ClampsToFloor(int input, int expected)
	{
		DecimationOptions options = new() { CandidateMinRows = input };
		Assert.Equal(expected, options.ResolveCandidateMinRows());
	}

	[Theory]
	[InlineData(0, 1)]
	[InlineData(-99, 1)]
	[InlineData(1, 1)]
	[InlineData(100, 100)]
	[InlineData(100_000, 100_000)]
	[InlineData(100_001, 100_000)]
	public void ResolveHeadKeepPerBurst_ClampsToSupportedRange(int input, int expected)
	{
		DecimationOptions options = new() { HeadKeepPerBurst = input };
		Assert.Equal(expected, options.ResolveHeadKeepPerBurst());
	}

	[Theory]
	[InlineData(0, 1)]
	[InlineData(-5, 1)]
	[InlineData(1, 1)]
	[InlineData(250, 250)]
	[InlineData(100_000, 100_000)]
	[InlineData(999_999, 100_000)]
	public void ResolveTailKeepPerBurst_ClampsToSupportedRange(int input, int expected)
	{
		DecimationOptions options = new() { TailKeepPerBurst = input };
		Assert.Equal(expected, options.ResolveTailKeepPerBurst());
	}

	[Theory]
	[InlineData(0, 1)]
	[InlineData(-3, 1)]
	[InlineData(1, 1)]
	[InlineData(5, 5)]
	[InlineData(32, 32)]
	[InlineData(33, 32)]
	public void ResolveMaxCandidateEventIds_ClampsToSupportedRange(int input, int expected)
	{
		DecimationOptions options = new() { MaxCandidateEventIds = input };
		Assert.Equal(expected, options.ResolveMaxCandidateEventIds());
	}

	[Theory]
	[InlineData(0, 100)]
	[InlineData(-50, 100)]
	[InlineData(100, 100)]
	[InlineData(5_000, 5_000)]
	[InlineData(100_000, 100_000)]
	[InlineData(100_001, 100_000)]
	public void ResolveBatchSize_ClampsToSupportedRange(int input, int expected)
	{
		DecimationOptions options = new() { BatchSize = input };
		Assert.Equal(expected, options.ResolveBatchSize());
	}

	[Fact]
	public void Constants_ExposeSupportedBounds()
	{
		Assert.Equal(7, DecimationOptions.MinMinAgeDays);
		Assert.Equal(10, DecimationOptions.MinBurstGapSeconds);
		Assert.Equal(10_000, DecimationOptions.MinCandidateMinRows);
		Assert.Equal(1, DecimationOptions.MinKeepPerBurst);
		Assert.Equal(100_000, DecimationOptions.MaxKeepPerBurst);
		Assert.Equal(1, DecimationOptions.MinMaxCandidateEventIds);
		Assert.Equal(32, DecimationOptions.MaxMaxCandidateEventIds);
		Assert.Equal(100, DecimationOptions.MinBatchSize);
		Assert.Equal(100_000, DecimationOptions.MaxBatchSize);
	}

	[Fact]
	public void StorageOptions_ExposesDecimation_WithSafeDefaults()
	{
		StorageOptions storage = new();
		Assert.NotNull(storage.Decimation);
		Assert.False(storage.Decimation.Enabled);
	}
}
