/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 2.0.2
// File   : StorageBenchmarkOptions.cs
// Project: RdpAudit.StorageBenchmarks
// Purpose: The validated shape of one benchmark invocation. Parsing produces this record and nothing
//          else touches the command line, so every probe reads its inputs from one typed object and the
//          bounds of the run (how many rows, how many codes, how many samples) are stated in one place
//          with the reason for each bound.
// Depends: StorageBenchmarkCli
// Extends: Add an option by adding a property here, parsing it in StorageBenchmarkCli and documenting
//          it in the help text; never read Environment.GetCommandLineArgs() from a probe.

namespace RdpAudit.StorageBenchmarks;

/// <summary>A validated benchmark invocation.</summary>
public sealed record StorageBenchmarkOptions
{
	/// <summary>Synthetic rows the quick profile seeds.</summary>
	public const int QuickRows = 200_000;

	/// <summary>Synthetic rows the full profile seeds. One million is the first size at which a
	/// million-row timing is measured rather than extrapolated.</summary>
	public const int FullRows = 1_000_000;

	/// <summary>Distinct codes the quick profile spreads its rows over.</summary>
	public const int QuickCodes = 16;

	/// <summary>Distinct codes the full profile spreads its rows over.</summary>
	public const int FullCodes = 64;

	/// <summary>Timed samples the quick profile takes.</summary>
	public const int QuickSamples = 2;

	/// <summary>Timed samples the full profile takes.</summary>
	public const int FullSamples = 5;

	/// <summary>Fewest rows a run may seed: below this the retention rules have too little interior to
	/// delete and every throughput number is dominated by fixed costs.</summary>
	public const int MinRows = 5_000;

	/// <summary>Most rows a run may seed, so a mistyped option cannot fill a volume.</summary>
	public const int MaxRows = 5_000_000;

	/// <summary>Fewest codes a run may use.</summary>
	public const int MinCodes = 1;

	/// <summary>Most codes a run may use. The retention engine examines at most 256 distinct codes per
	/// evaluation (<c>InformationDensityRetentionEngine.MaxCodesExaminedPerPass</c>), so above this the
	/// extra codes would never reach a plan.</summary>
	public const int MaxCodes = 256;

	/// <summary>Fewest timed samples a run may take.</summary>
	public const int MinSamples = 1;

	/// <summary>Most timed samples a run may take, so a run stays inside a sensible time budget.</summary>
	public const int MaxSamples = 25;

	/// <summary>True when the quick profile was selected.</summary>
	public required bool Quick { get; init; }

	/// <summary>Synthetic raw-event rows to seed.</summary>
	public required int Rows { get; init; }

	/// <summary>Distinct (event id, channel) codes to spread the rows over.</summary>
	public required int Codes { get; init; }

	/// <summary>Timed samples per repeated measurement.</summary>
	public required int Samples { get; init; }

	/// <summary>Warm-up runs per repeated measurement, discarded before the timed samples.</summary>
	public required int WarmupRuns { get; init; }

	/// <summary>Directory the caller pointed at with <c>--store</c>, or null when the run invents a
	/// temporary one.</summary>
	public string? StoreDirectory { get; init; }

	/// <summary>Parent directory for the run's temporary working directories.</summary>
	public required string WorkRoot { get; init; }

	/// <summary>Directory the report is written to, or null for the default under the work root.</summary>
	public string? OutputDirectory { get; init; }

	/// <summary>True when the caller explicitly accepted a <c>--store</c> directory that already holds a
	/// database. The run then works on a copy of it and never writes to the original.</summary>
	public required bool AllowExistingStore { get; init; }

	/// <summary>True when the shard-inclusive snapshot probe runs.</summary>
	public required bool IncludeShards { get; init; }

	/// <summary>Name of the selected profile.</summary>
	public string ProfileName => Quick ? "quick" : "full";

	/// <summary>What the selected profile means.</summary>
	public string ProfileDescription => Quick
		? "small synthetic store, few samples: a fast check that the machinery runs and a first read on the hardware"
		: "full-size synthetic store with repeated samples: the profile recommendations should be based on";

	/// <summary>True when the configured row count is large enough to measure a million-row timing
	/// rather than extrapolate it.</summary>
	public bool ReachesMillionRows => Rows >= FullRows;
}
