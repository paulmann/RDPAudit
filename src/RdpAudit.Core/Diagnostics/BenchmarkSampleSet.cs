/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 2.0.2
// File   : BenchmarkSampleSet.cs
// Project: RdpAudit.Core (RdpAudit.Core.Diagnostics)
// Purpose: The sample statistics every storage benchmark metric is reported with. A single measured
//          number is not a measurement of a machine: the runner takes repeated timed samples and this
//          type reduces them to the median (the value a report quotes) plus p95, min and max (the
//          spread a sizing decision has to survive). The reduction is pure and deterministic, so the
//          arithmetic that turns samples into a published number is unit-testable without a machine.
// Depends: System.Globalization
// Extends: Add a statistic by adding a property here and computing it in FromValues; never compute a
//          percentile at a probe call site, or two metrics will disagree about what "p95" means.

using System.Globalization;

namespace RdpAudit.Core.Diagnostics;

/// <summary>
/// Reduced statistics of one metric's timed samples. <see cref="Median"/> is the value a report
/// quotes; <see cref="P95"/> is the value a budget has to accommodate.
/// </summary>
public sealed record BenchmarkSampleSet
{
	/// <summary>Number of samples that were timed (warm-up runs are not counted and not included).</summary>
	public required int SampleCount { get; init; }

	/// <summary>Number of warm-up runs performed before the timed samples.</summary>
	public required int WarmupCount { get; init; }

	/// <summary>Arithmetic mean of the samples. Reported for completeness; median is the quoted value.</summary>
	public required double Mean { get; init; }

	/// <summary>Median sample. For an even sample count this is the arithmetic mean of the two central
	/// values after sorting, so it is never one of the samples and never depends on ordering.</summary>
	public required double Median { get; init; }

	/// <summary>95th percentile by the nearest-rank rule: the sample at index
	/// <c>ceil(0.95 * n) - 1</c> of the ascending sequence, clamped into range.</summary>
	public required double P95 { get; init; }

	/// <summary>Smallest sample.</summary>
	public required double Min { get; init; }

	/// <summary>Largest sample.</summary>
	public required double Max { get; init; }

	/// <summary>
	/// Reduces timed samples to the reported statistics. Ordering of <paramref name="values"/> does not
	/// matter; the input is copied before sorting.
	/// </summary>
	/// <exception cref="ArgumentException">Thrown when <paramref name="values"/> is empty, because an
	/// empty sample set is not a measurement and must not be rendered as a zero.</exception>
	public static BenchmarkSampleSet FromValues(IReadOnlyList<double> values, int warmupCount = 0)
	{
		ArgumentNullException.ThrowIfNull(values);
		ArgumentOutOfRangeException.ThrowIfNegative(warmupCount);
		if (values.Count == 0)
		{
			throw new ArgumentException("A sample set needs at least one timed sample.", nameof(values));
		}

		double[] sorted = new double[values.Count];
		double sum = 0d;
		for (int index = 0; index < values.Count; index++)
		{
			sorted[index] = values[index];
			sum += values[index];
		}

		Array.Sort(sorted);
		return new BenchmarkSampleSet
		{
			SampleCount = sorted.Length,
			WarmupCount = warmupCount,
			Mean = sum / sorted.Length,
			Median = ComputeMedian(sorted),
			P95 = Percentile(sorted, 0.95d),
			Min = sorted[0],
			Max = sorted[^1],
		};
	}

	private static double ComputeMedian(double[] sorted)
	{
		int middle = sorted.Length / 2;
		return sorted.Length % 2 == 1
			? sorted[middle]
			: (sorted[middle - 1] + sorted[middle]) / 2d;
	}

	/// <summary>Nearest-rank percentile over an already ascending sequence.</summary>
	private static double Percentile(double[] ascending, double fraction)
	{
		int rank = (int)Math.Ceiling(fraction * ascending.Length);
		int index = Math.Clamp(rank - 1, 0, ascending.Length - 1);
		return ascending[index];
	}

	/// <summary>One-line rendering used by the human-readable report and the recommendation rationale.</summary>
	public string Describe()
		=> string.Format(
			CultureInfo.InvariantCulture,
			"n={0} median={1:0.###} p95={2:0.###} min={3:0.###} max={4:0.###}",
			SampleCount,
			Median,
			P95,
			Min,
			Max);
}
