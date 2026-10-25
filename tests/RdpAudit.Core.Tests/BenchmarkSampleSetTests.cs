// File:    tests/RdpAudit.Core.Tests/BenchmarkSampleSetTests.cs
// Module:  RdpAudit.Core.Tests
// Purpose: Locks the arithmetic that turns timed samples into the numbers a storage benchmark report
//          publishes. A wrong median or a wrong percentile would silently mis-size every recommendation
//          that consumes it, so the reduction is tested at its boundaries (one sample, even counts, the
//          percentile rank) rather than only on a comfortable input.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using RdpAudit.Core.Diagnostics;
using Xunit;

namespace RdpAudit.Core.Tests;

/// <summary>Sample reduction: median, nearest-rank p95, min/max and the degenerate inputs.</summary>
public class BenchmarkSampleSetTests
{
	[Fact]
	public void FromValues_OddCount_MedianIsTheMiddleSample()
	{
		BenchmarkSampleSet set = BenchmarkSampleSet.FromValues([5d, 1d, 3d]);

		Assert.Equal(3, set.SampleCount);
		Assert.Equal(3d, set.Median);
		Assert.Equal(1d, set.Min);
		Assert.Equal(5d, set.Max);
		Assert.Equal(3d, set.Mean);
	}

	[Fact]
	public void FromValues_EvenCount_MedianIsTheMeanOfTheTwoCentralSamples()
	{
		BenchmarkSampleSet set = BenchmarkSampleSet.FromValues([4d, 1d, 3d, 2d]);

		Assert.Equal(2.5d, set.Median);
		Assert.Equal(1d, set.Min);
		Assert.Equal(4d, set.Max);
	}

	[Fact]
	public void FromValues_IsOrderIndependent()
	{
		BenchmarkSampleSet ascending = BenchmarkSampleSet.FromValues([1d, 2d, 3d, 4d, 5d]);
		BenchmarkSampleSet descending = BenchmarkSampleSet.FromValues([5d, 4d, 3d, 2d, 1d]);

		Assert.Equal(ascending, descending);
	}

	[Fact]
	public void FromValues_SingleSample_EveryStatisticIsThatSample()
	{
		BenchmarkSampleSet set = BenchmarkSampleSet.FromValues([42.5d]);

		Assert.Equal(1, set.SampleCount);
		Assert.Equal(42.5d, set.Median);
		Assert.Equal(42.5d, set.P95);
		Assert.Equal(42.5d, set.Min);
		Assert.Equal(42.5d, set.Max);
	}

	[Fact]
	public void FromValues_SingleSample_UnchangedByWarmupCount()
	{
		BenchmarkSampleSet set = BenchmarkSampleSet.FromValues([7d], warmupCount: 3);

		Assert.Equal(3, set.WarmupCount);
		Assert.Equal(1, set.SampleCount);
		Assert.Equal(7d, set.Median);
	}

	[Theory]
	// Nearest rank: ceil(0.95 * n) - 1, clamped into the ascending sequence.
	[InlineData(1, 0)]
	[InlineData(2, 1)]
	[InlineData(10, 9)]
	[InlineData(19, 18)]
	[InlineData(20, 18)]
	[InlineData(100, 94)]
	public void FromValues_P95UsesTheNearestRankRule(int count, int expectedIndex)
	{
		List<double> values = [];
		for (int index = 0; index < count; index++)
		{
			values.Add(index + 1);
		}

		BenchmarkSampleSet set = BenchmarkSampleSet.FromValues(values);

		Assert.Equal(expectedIndex + 1, set.P95);
	}

	[Fact]
	public void FromValues_EmptySamplesAreRejected()
	{
		Assert.Throws<ArgumentException>(() => BenchmarkSampleSet.FromValues([]));
	}

	[Fact]
	public void FromValues_NegativeWarmupIsRejected()
	{
		Assert.Throws<ArgumentOutOfRangeException>(() => BenchmarkSampleSet.FromValues([1d], warmupCount: -1));
	}

	[Fact]
	public void FromValues_NullIsRejected()
	{
		Assert.Throws<ArgumentNullException>(() => BenchmarkSampleSet.FromValues(null!));
	}

	[Fact]
	public void FromValues_HugeValuesStayFinite()
	{
		BenchmarkSampleSet set = BenchmarkSampleSet.FromValues([1e308d]);

		Assert.Equal(1e308d, set.Median);
		Assert.True(double.IsFinite(set.Median));
		Assert.True(double.IsFinite(set.P95));
	}

	[Fact]
	public void FromValues_ZeroSamplesAreValidAndZero()
	{
		BenchmarkSampleSet set = BenchmarkSampleSet.FromValues([0d, 0d, 0d]);

		Assert.Equal(0d, set.Median);
		Assert.Equal(0d, set.Mean);
		Assert.Equal(0d, set.P95);
	}

	[Fact]
	public void Describe_MentionsEveryStatistic()
	{
		string described = BenchmarkSampleSet.FromValues([1d, 2d, 3d]).Describe();

		Assert.Contains("n=3", described, StringComparison.Ordinal);
		Assert.Contains("median=2", described, StringComparison.Ordinal);
		Assert.Contains("p95=", described, StringComparison.Ordinal);
		Assert.Contains("min=", described, StringComparison.Ordinal);
		Assert.Contains("max=", described, StringComparison.Ordinal);
	}
}
