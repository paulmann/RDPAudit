/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 2.0.2
// File   : StorageBenchmarkReport.cs
// Project: RdpAudit.Core (RdpAudit.Core.Diagnostics)
// Purpose: The complete, versioned result of one storage benchmark run: the machine it ran on, how it
//          was measured, what was measured, what the measurements imply and what the run does NOT
//          cover. This is the single object both report writers render, and the object the JSON
//          round-trip test deserializes, so the machine-readable and human-readable reports can never
//          disagree about a number.
// Depends: MachineProfile, BenchmarkMeasurement, TuningRecommendation
// Extends: Bump CurrentSchemaVersion and append fields when the shape changes; never rename a field a
//          consumer may already be reading.

namespace RdpAudit.Core.Diagnostics;

/// <summary>How the run measured, so a reader can judge the numbers and reproduce them.</summary>
public sealed record BenchmarkMethodology
{
	/// <summary>Timed runs of each repeated measurement that were discarded before the timed samples.</summary>
	public required int WarmupRuns { get; init; }

	/// <summary>Timed runs of each repeated measurement that were kept.</summary>
	public required int TimedRuns { get; init; }

	/// <summary>How a metric's samples were reduced to the value the report quotes.</summary>
	public required string AggregationRule { get; init; }

	/// <summary>How the p95 in this report is computed.</summary>
	public required string PercentileRule { get; init; }

	/// <summary>How the per-batch writer-lock hold was obtained.</summary>
	public required string BatchLockRule { get; init; }

	/// <summary>How recommendations were produced from the measurements.</summary>
	public required string RecommendationRule { get; init; }

	/// <summary>Anything else a reader needs to reproduce the run.</summary>
	public required IReadOnlyList<string> Notes { get; init; }
}

/// <summary>Everything one storage benchmark run produced.</summary>
public sealed record StorageBenchmarkReport
{
	/// <summary>Schema version of the JSON document this report serializes to.</summary>
	public const string CurrentSchemaVersion = "1.0";

	/// <summary>Schema version of this document.</summary>
	public required string SchemaVersion { get; init; }

	/// <summary>Name of the tool that produced the report.</summary>
	public required string ToolName { get; init; }

	/// <summary>Version of the tool that produced the report.</summary>
	public required string ToolVersion { get; init; }

	/// <summary>Profile the run used (<c>quick</c> or <c>full</c>).</summary>
	public required string ProfileName { get; init; }

	/// <summary>What the profile means, in one sentence.</summary>
	public required string ProfileDescription { get; init; }

	/// <summary>When the run started, UTC.</summary>
	public required DateTime GeneratedUtc { get; init; }

	/// <summary>Directory the benchmark store was created in. A temporary directory the run removes.</summary>
	public required string StorePath { get; init; }

	/// <summary>Rows of synthetic raw events the store was seeded with.</summary>
	public required int SeedRowCount { get; init; }

	/// <summary>Distinct (event id, channel) codes the synthetic rows were spread over.</summary>
	public required int SeedCodeCount { get; init; }

	/// <summary>Wall-clock duration of the whole run.</summary>
	public required long TotalDurationMs { get; init; }

	/// <summary>The machine the measurements were taken on.</summary>
	public required MachineProfile Machine { get; init; }

	/// <summary>How the run measured.</summary>
	public required BenchmarkMethodology Methodology { get; init; }

	/// <summary>Every metric the run records, measured or not.</summary>
	public required IReadOnlyList<BenchmarkMeasurement> Measurements { get; init; }

	/// <summary>One entry per parameter the advisor has a rule for, recommended or not.</summary>
	public required IReadOnlyList<TuningRecommendation> Recommendations { get; init; }

	/// <summary>What the run does not cover, stated so a reader cannot over-read the numbers.</summary>
	public required IReadOnlyList<string> Limitations { get; init; }

	/// <summary>Finds a measurement by metric identifier; null when the run does not record it at all.</summary>
	public BenchmarkMeasurement? FindMeasurement(string metric)
	{
		ArgumentNullException.ThrowIfNull(metric);
		foreach (BenchmarkMeasurement measurement in Measurements)
		{
			if (string.Equals(measurement.Metric, metric, StringComparison.Ordinal))
			{
				return measurement;
			}
		}

		return null;
	}
}
