/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 2.0.2
// File   : BenchmarkMeasurement.cs
// Project: RdpAudit.Core (RdpAudit.Core.Diagnostics)
// Purpose: One measured (or explicitly not measured, or failed) quantity in a storage benchmark run.
//          "Not measured" is a first-class state rather than a zero, because the whole point of this
//          report is that a number in it was measured on the machine that produced it: a metric the
//          run never reached, or a probe that threw, must read as absent with a reason and must never
//          be rendered as a plausible-looking value.
// Depends: BenchmarkSampleSet
// Extends: Add a state by extending MeasurementState and both consumers (the advisor's input lookup
//          and the Markdown writer); never overload a measured value to mean "absent".

namespace RdpAudit.Core.Diagnostics;

/// <summary>Why a metric has no number, or that it has one.</summary>
public enum MeasurementState
{
	/// <summary>At least one timed sample exists and <see cref="BenchmarkMeasurement.Value"/> is real.</summary>
	Measured = 0,

	/// <summary>The run deliberately did not reach this metric (for example a quick profile, or a
	/// precondition that was not met). <see cref="BenchmarkMeasurement.Note"/> says why.</summary>
	NotMeasured = 1,

	/// <summary>The probe ran and threw. No value exists; the exception text is in
	/// <see cref="BenchmarkMeasurement.Note"/> so a failure cannot masquerade as a small number.</summary>
	Failed = 2,
}

/// <summary>
/// One metric of a storage benchmark run: its stable identifier, its unit, its reduced samples and its
/// state.
/// </summary>
public sealed record BenchmarkMeasurement
{
	/// <summary>Stable metric identifier (see <see cref="StorageBenchmarkMetric"/>).</summary>
	public required string Metric { get; init; }

	/// <summary>Unit of <see cref="Value"/> and of the samples, e.g. <c>rows/s</c> or <c>ms</c>.</summary>
	public required string Unit { get; init; }

	/// <summary>Whether a value exists.</summary>
	public required MeasurementState State { get; init; }

	/// <summary>The quoted value: the median of the timed samples. Null unless
	/// <see cref="State"/> is <see cref="MeasurementState.Measured"/>.</summary>
	public double? Value { get; init; }

	/// <summary>Reduced samples; null unless <see cref="State"/> is <see cref="MeasurementState.Measured"/>.</summary>
	public BenchmarkSampleSet? Samples { get; init; }

	/// <summary>Why the metric is absent, or a qualification of the measured value. Null when the metric
	/// is measured and needs no qualification.</summary>
	public string? Note { get; init; }

	/// <summary>Builds a measured metric whose quoted value is the median of
	/// <paramref name="samples"/>.</summary>
	public static BenchmarkMeasurement FromSamples(
		string metric,
		string unit,
		BenchmarkSampleSet samples,
		string? note = null)
	{
		ArgumentNullException.ThrowIfNull(samples);
		return new BenchmarkMeasurement
		{
			Metric = metric,
			Unit = unit,
			State = MeasurementState.Measured,
			Value = samples.Median,
			Samples = samples,
			Note = note,
		};
	}

	/// <summary>Builds a measured metric from a single value that is not a sample statistic (for example a
	/// byte count read once). The sample set records one sample so the report can still state how many
	/// observations back the number.</summary>
	public static BenchmarkMeasurement Scalar(
		string metric,
		string unit,
		double value,
		int warmupCount = 0,
		string? note = null)
		=> FromSamples(
			metric,
			unit,
			BenchmarkSampleSet.FromValues([value], warmupCount),
			note);

	/// <summary>Builds a metric the run deliberately did not measure.</summary>
	public static BenchmarkMeasurement NotMeasured(string metric, string unit, string reason)
	{
		ArgumentException.ThrowIfNullOrWhiteSpace(reason);
		return new BenchmarkMeasurement
		{
			Metric = metric,
			Unit = unit,
			State = MeasurementState.NotMeasured,
			Note = reason,
		};
	}

	/// <summary>Builds a metric whose probe failed.</summary>
	public static BenchmarkMeasurement Failed(string metric, string unit, string reason)
	{
		ArgumentException.ThrowIfNullOrWhiteSpace(reason);
		return new BenchmarkMeasurement
		{
			Metric = metric,
			Unit = unit,
			State = MeasurementState.Failed,
			Note = reason,
		};
	}
}
