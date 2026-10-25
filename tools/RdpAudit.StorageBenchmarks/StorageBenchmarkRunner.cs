/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 2.0.2
// File   : StorageBenchmarkRunner.cs
// Project: RdpAudit.StorageBenchmarks
// Purpose: Runs the probes in a fixed order and assembles the one report both writers render. The order
//          is deliberate and load-bearing: the store is seeded first, the retention samples each copy the
//          seeded store so they all start from identical state, the probes that consume or dirty a store
//          (ledger, snapshots, compaction) run after the retention samples have taken their copies, and
//          the two probes that only read (integrity) come last so a long read cannot disturb a timing that
//          matters more.
//          This class is also where the tool's honesty rules are enforced: a probe that fails contributes a
//          FAILED metric with its exception text and drags the process exit code to a distinct non-zero
//          value, and a probe that was not reached contributes a NOT MEASURED metric with the reason. No
//          code path here substitutes a default for a measurement.
// Depends: all probes, StorageTuningAdvisor, StorageBenchmarkReportWriter
// Extends: Add a probe by adding its call here and its limitation to BuildLimitations; never reorder the
//          retention probe after a probe that modifies the seeded store.

using System.Globalization;
using RdpAudit.Core.Config;
using RdpAudit.Core.Diagnostics;

namespace RdpAudit.StorageBenchmarks;

/// <summary>Runs the storage benchmark and writes its report.</summary>
public static class StorageBenchmarkRunner
{
	/// <summary>Version of the report this tool writes, independent of the assembly version.</summary>
	public const string ToolVersion = "1.0.0";

	/// <summary>Name of the tool, as it appears in a report.</summary>
	public const string ToolName = "RdpAudit.StorageBenchmarks";

	/// <summary>Parses the command line, prepares a workspace and runs the benchmark.</summary>
	/// <param name="args">Command-line arguments.</param>
	/// <param name="output">Sink for progress and the final summary.</param>
	/// <param name="cancellationToken">Cancellation.</param>
	/// <returns>A <see cref="StorageBenchmarkExitCode"/> value.</returns>
	public static async Task<int> RunAsync(string[] args, TextWriter output, CancellationToken cancellationToken)
	{
		ArgumentNullException.ThrowIfNull(args);
		ArgumentNullException.ThrowIfNull(output);

		StorageBenchmarkCliResult parsed = StorageBenchmarkCli.Parse(args);
		if (parsed.ShowHelp)
		{
			output.WriteLine(StorageBenchmarkCli.HelpText);
			return StorageBenchmarkExitCode.Success;
		}

		if (parsed.Error is { } error)
		{
			output.WriteLine("error: " + error);
			output.WriteLine();
			output.WriteLine(StorageBenchmarkCli.HelpText);
			return StorageBenchmarkExitCode.UsageError;
		}

		StorageBenchmarkOptions options = parsed.Options!;
		BenchmarkWorkspaceResult prepared = BenchmarkWorkspace.Prepare(options);
		if (prepared.Refusal is { } refusal)
		{
			output.WriteLine(refusal);
			return StorageBenchmarkExitCode.Refused;
		}

		using BenchmarkWorkspace workspace = prepared.Workspace!;
		return await ExecuteAsync(options, workspace, output, cancellationToken).ConfigureAwait(false);
	}

	private static async Task<int> ExecuteAsync(
		StorageBenchmarkOptions options,
		BenchmarkWorkspace workspace,
		TextWriter output,
		CancellationToken cancellationToken)
	{
		DateTime startedUtc = DateTime.UtcNow;
		System.Diagnostics.Stopwatch runWatch = System.Diagnostics.Stopwatch.StartNew();
		Action<string> log = output.WriteLine;

		log("RdpAudit storage benchmark " + ToolVersion);
		log(string.Format(CultureInfo.InvariantCulture, "  profile        : {0} ({1})", options.ProfileName, options.ProfileDescription));
		log(string.Format(CultureInfo.InvariantCulture, "  store          : {0}", workspace.StoreDirectory));
		log(string.Format(CultureInfo.InvariantCulture, "  report         : {0}", workspace.ReportDirectory));
		log(string.Format(CultureInfo.InvariantCulture, "  runs           : {0} warm-up + {1} timed sample(s)", options.WarmupRuns, options.Samples));
		log("  this tool applies nothing it recommends and never reads or writes %ProgramData%\\RdpAudit");
		log(string.Empty);

		BenchmarkSampleRecorder recorder = new(options.WarmupRuns, options.Samples, log);
		List<BenchmarkMeasurement> measurements = [];

		// ── Machine profile and the store volume ─────────────────────────────────
		log("[1/8] machine profile and store volume");
		MachineProfile profile = MachineProfileProbe.BuildProfile(workspace.DatabasePath);
		BenchmarkSampleRecorder volumeRecorder = new(options.WarmupRuns, Math.Max(options.Samples, 2), log);
		VolumeProbeResult volume = await MachineProfileProbe
			.MeasureVolumeAsync(workspace.DatabasePath, profile, volumeRecorder, cancellationToken)
			.ConfigureAwait(false);
		profile = profile with
		{
			StoreVolume = volume.Volume,
			Unknowns = [.. profile.Unknowns, .. volume.Unknowns],
		};

		measurements.Add(volume.WriteLatency);
		measurements.Add(volume.WriteIops);
		log(string.Format(
			CultureInfo.InvariantCulture,
			"  {0} / {1} cores / {2} / volume {3} {4} free of {5} bytes / media: {6}",
			profile.OperatingSystem,
			profile.ProcessorCount,
			profile.ProcessorName,
			profile.StoreVolume.RootPath,
			profile.StoreVolume.FreeBytes,
			profile.StoreVolume.TotalBytes,
			profile.StoreVolume.Ssd.IsSolidState is { } solid ? (solid ? "solid state" : "rotational") : "unknown"));
		log(string.Empty);

		// ── Store ────────────────────────────────────────────────────────────────
		log("[2/8] synthetic store");
		bool measuringExistingCopy = workspace.CopiedFrom is not null;
		BenchmarkStore draft = BenchmarkStore.Create(workspace.StoreDirectory, BuildBlueprint(workspace, options, maxRawEventRows: long.MaxValue));
		SeedOutcome seed;
		if (measuringExistingCopy)
		{
			log(string.Format(CultureInfo.InvariantCulture, "  measuring the COPY of the store at {0} (--allow-existing-store); the original is not opened", workspace.CopiedFrom));
			seed = ValidateExistingStore(draft);
			measurements.AddRange(seed.Measurements);
		}
		else
		{
			seed = await SeedProbe.RunAsync(draft, options.Rows, options.Codes, startedUtc, log, cancellationToken).ConfigureAwait(false);
			measurements.AddRange(seed.Measurements);
		}

		if (seed.Error is { } seedError)
		{
			log("  the store could not be prepared: " + seedError);
			log(string.Empty);
			return Finish(options, workspace, profile, measurements, startedUtc, runWatch, log);
		}

		long rowCount = await draft.CountRawEventsAsync(cancellationToken).ConfigureAwait(false);
		log(string.Format(
			CultureInfo.InvariantCulture,
			"  store holds {0} raw events across {1} codes",
			rowCount,
			seed.CodesUsed));

		// The free-space numbers the recommendations divide into are read once the store exists at its
		// size, not before it was created: a report that sized a snapshot count against the space a store
		// had not yet consumed would overstate the answer.
		profile = profile with { StoreVolume = MachineProfileProbe.RefreshFreeSpace(profile.StoreVolume) };
		measurements.Add(BenchmarkMeasurement.Scalar(StorageBenchmarkMetric.VolumeFreeBytes, StorageBenchmarkUnit.Bytes, profile.StoreVolume.FreeBytes));
		measurements.Add(BenchmarkMeasurement.Scalar(StorageBenchmarkMetric.VolumeTotalBytes, StorageBenchmarkUnit.Bytes, profile.StoreVolume.TotalBytes));
		log(string.Format(
			CultureInfo.InvariantCulture,
			"  volume free space with the store in place: {0} of {1} bytes",
			profile.StoreVolume.FreeBytes,
			profile.StoreVolume.TotalBytes));
		log(string.Empty);

		StoreBlueprint blueprint = BuildBlueprint(workspace, options, maxRawEventRows: Math.Max(1L, rowCount / 2L));
		BenchmarkStore store = BenchmarkStore.Create(workspace.StoreDirectory, blueprint);

		// ── Retention ────────────────────────────────────────────────────────────
		log("[3/8] information-density retention (real engine)");
		measurements.AddRange(await RetentionProbe
			.RunAsync(store, blueprint, workspace, options.Codes, recorder, log, cancellationToken)
			.ConfigureAwait(false));
		log(string.Empty);

		// ── Ledger ───────────────────────────────────────────────────────────────
		log("[4/8] deletion ledger (real writer)");
		string ledgerDirectory = Path.Combine(workspace.RunDirectory, "ledger-store");
		BenchmarkStore ledgerStore = store.CloneTo(ledgerDirectory, blueprint);
		measurements.AddRange(await LedgerProbe.RunAsync(ledgerStore, recorder, log, cancellationToken).ConfigureAwait(false));
		log(string.Empty);

		// ── Snapshots ────────────────────────────────────────────────────────────
		log("[5/8] snapshot, verification and shard-inclusive snapshot (real backup service)");
		int shardFiles = options.Quick ? BackupProbe.QuickShardFiles : BackupProbe.FullShardFiles;
		measurements.AddRange(await BackupProbe
			.RunAsync(store, workspace, options.IncludeShards, shardFiles, recorder, log, cancellationToken)
			.ConfigureAwait(false));
		log(string.Empty);

		// ── Integrity ────────────────────────────────────────────────────────────
		log("[6/8] integrity checks");
		measurements.AddRange(await IntegrityProbe.RunAsync(store, recorder, log, cancellationToken).ConfigureAwait(false));
		log(string.Empty);

		// ── Reclaim ──────────────────────────────────────────────────────────────
		log("[7/8] WAL checkpoint, incremental vacuum and offline compaction");
		measurements.AddRange(await ReclaimProbe
			.RunAsync(store, blueprint, workspace, recorder, log, cancellationToken)
			.ConfigureAwait(false));
		measurements.AddRange(await ReclaimProbe
			.RunCompactionAsync(store, blueprint, workspace, recorder, log, cancellationToken)
			.ConfigureAwait(false));
		log(string.Empty);

		return Finish(options, workspace, profile, measurements, startedUtc, runWatch, log);
	}

	private static int Finish(
		StorageBenchmarkOptions options,
		BenchmarkWorkspace workspace,
		MachineProfile profile,
		List<BenchmarkMeasurement> measurements,
		DateTime startedUtc,
		System.Diagnostics.Stopwatch runWatch,
		Action<string> log)
	{
		runWatch.Stop();
		log("[8/8] report");

		IReadOnlyList<TuningRecommendation> recommendations = StorageTuningAdvisor.Advise(profile, measurements);
		StorageBenchmarkReport report = new()
		{
			SchemaVersion = StorageBenchmarkReport.CurrentSchemaVersion,
			ToolName = ToolName,
			ToolVersion = ToolVersion,
			ProfileName = options.ProfileName,
			ProfileDescription = options.ProfileDescription,
			GeneratedUtc = startedUtc,
			StorePath = workspace.StoreDirectory,
			SeedRowCount = options.Rows,
			SeedCodeCount = options.Codes,
			TotalDurationMs = (long)runWatch.Elapsed.TotalMilliseconds,
			Machine = profile,
			Methodology = BuildMethodology(options, workspace),
			Measurements = measurements,
			Recommendations = recommendations,
			Limitations = BuildLimitations(options, workspace),
		};

		IReadOnlyList<string> paths = StorageBenchmarkReportWriter.WriteAll(report, workspace.ReportDirectory);
		foreach (string path in paths)
		{
			log("  wrote " + path);
		}

		int failed = 0;
		int notMeasured = 0;
		foreach (BenchmarkMeasurement measurement in measurements)
		{
			if (measurement.State == MeasurementState.Failed)
			{
				failed++;
			}
			else if (measurement.State == MeasurementState.NotMeasured)
			{
				notMeasured++;
			}
		}

		int recommended = 0;
		int declined = 0;
		int insufficient = 0;
		foreach (TuningRecommendation recommendation in recommendations)
		{
			switch (recommendation.State)
			{
				case RecommendationState.Recommended:
					recommended++;
					break;
				case RecommendationState.Declined:
					declined++;
					break;
				default:
					insufficient++;
					break;
			}
		}

		log(string.Empty);
		log(string.Format(
			CultureInfo.InvariantCulture,
			"  {0} metrics measured, {1} not measured, {2} failed",
			measurements.Count - failed - notMeasured,
			notMeasured,
			failed));
		log(string.Format(
			CultureInfo.InvariantCulture,
			"  {0} recommendations, {1} declined on the measured evidence, {2} without enough data",
			recommended,
			declined,
			insufficient));
		log(string.Format(CultureInfo.InvariantCulture, "  total run time {0:0.###} s", runWatch.Elapsed.TotalSeconds));
		log(string.Empty);
		log("  Nothing was applied. To use a recommendation, edit appsettings.json yourself and watch the");
		log("  retention and backup telemetry afterwards.");
		log(string.Empty);
		log(string.Format(CultureInfo.InvariantCulture, "  Markdown report : {0}", paths[0]));
		log(string.Format(CultureInfo.InvariantCulture, "  JSON report     : {0}", paths[1]));
		log(string.Format(CultureInfo.InvariantCulture, "  Settings fragment: {0}", paths[2]));
		if (!workspace.OwnsStoreDirectory)
		{
			log(string.Format(
				CultureInfo.InvariantCulture,
				"  The benchmark store was left in place at {0} because --store named it; delete it when you are done.",
				workspace.StoreDirectory));
		}

		return failed > 0 ? StorageBenchmarkExitCode.ProbeFailures : StorageBenchmarkExitCode.Success;
	}

	private static SeedOutcome ValidateExistingStore(BenchmarkStore store)
	{
		// The run was pointed at a directory that already held a store, and the operator allowed it. The
		// benchmark then measures what is there rather than seeding over it, so nothing about the original
		// store's contents is invented.
		bool hasSchema;
		using (Microsoft.Data.Sqlite.SqliteConnection connection = SqliteBenchmarkFacts.Open(store.DatabasePath))
		{
			hasSchema = string.Equals(
				SqliteBenchmarkFacts.ReadText(connection, "SELECT name FROM sqlite_master WHERE type='table' AND name='RawEvents';"),
				"RawEvents",
				StringComparison.Ordinal);
		}

		if (!hasSchema)
		{
			return new SeedOutcome
			{
				Measurements =
				[
					BenchmarkMeasurement.Failed(
						StorageBenchmarkMetric.SeedRowsPerSecond,
						StorageBenchmarkUnit.RowsPerSecond,
						"the copied database has no RawEvents table, so it is not an RdpAudit store"),
				],
				RowsWritten = 0,
				CodesUsed = 0,
				DatabaseBytes = SqliteBenchmarkFacts.DatabaseFileBytes(store.DatabasePath),
				Error = "the copied database has no RawEvents table, so it is not an RdpAudit store",
			};
		}

		string reason = "the run measured a copy of an existing store (--allow-existing-store) instead of seeding a synthetic one, so no fill was measured";
		return new SeedOutcome
		{
			Measurements =
			[
				BenchmarkMeasurement.NotMeasured(StorageBenchmarkMetric.SeedRowsPerSecond, StorageBenchmarkUnit.RowsPerSecond, reason),
				BenchmarkMeasurement.NotMeasured(StorageBenchmarkMetric.SeedSecondsPer100kRows, StorageBenchmarkUnit.Seconds, reason),
				BenchmarkMeasurement.NotMeasured(StorageBenchmarkMetric.SeedSecondsPerMillionRows, StorageBenchmarkUnit.Seconds, reason),
				BenchmarkMeasurement.Scalar(StorageBenchmarkMetric.SeedStoreBytes, StorageBenchmarkUnit.Bytes, SqliteBenchmarkFacts.DatabaseFileBytes(store.DatabasePath)),
				BenchmarkMeasurement.Scalar(StorageBenchmarkMetric.SeedStoreFamilyBytes, StorageBenchmarkUnit.Bytes, SqliteBenchmarkFacts.FamilyBytes(store.DatabasePath)),
			],
			RowsWritten = 0,
			CodesUsed = 0,
			DatabaseBytes = SqliteBenchmarkFacts.DatabaseFileBytes(store.DatabasePath),
		};
	}

	private static StoreBlueprint BuildBlueprint(BenchmarkWorkspace workspace, StorageBenchmarkOptions options, long maxRawEventRows)
	{
		int rowsPerPass = Math.Min(
			options.Codes * RetentionProbe.ProbeDeleteBatchRows * RetentionProbe.BatchesPerCode,
			RetentionPolicyOptions.MaxMaxRowsPerPass);

		return new StoreBlueprint
		{
			Retention = new RetentionPolicyOptions
			{
				Enabled = true,
				LegalHold = false,
				AnchorScope = RetentionAnchorScope.PerCode,
				ProtectedEventIds = [.. RetentionPolicyOptions.DefaultProtectedEventIds],
				TailKeepPerCode = 512,
				CandidateMinRows = 1_000,
				MinAgeDays = 7,
				MaxRowsPerPass = rowsPerPass,

				// The probe runs the pass with the writer-lock budget at its supported maximum so a pass
				// runs to completion: the budget decides only WHEN the engine yields, never what a batch
				// costs, so raising it makes the measured pass duration describe the whole plan instead of
				// its first slice. The recommended budget is derived from the measured batch cost, not from
				// this setting.
				MaxWriterLockMs = RetentionPolicyOptions.MaxMaxWriterLockMs,
				DeleteBatchRows = RetentionProbe.ProbeDeleteBatchRows,
				MaxDatabaseBytes = 0,

				// The trigger the benchmark depends on: a store holding more rows than half its seeded size
				// makes the row-count ceiling fire deterministically, so the pass always has a reason to run.
				MaxRawEventRows = maxRawEventRows,
				MinFreeDiskBytes = 0,
			},
			Backup = new BackupOptions
			{
				Enabled = true,
				RetentionCopies = BackupProbe.ProbeRetentionCopies,
				MinFreeDiskBytesBeforeBackup = 0,
				IncludeShards = false,
				PreMigrationBackupEnabled = true,
				BackupDirectory = workspace.SnapshotRoot,
			},
			Sharding = new ShardingOptions
			{
				Enabled = true,
				ActionsRoot = workspace.ActionsRoot,
				ShardCapacityRecords = BackupProbe.ShardCapacityRecords,
				MaxOpenWriters = 128,
				MaxShardFiles = 4096,
				MaxShardBytes = 0,
				MaxTotalShardBytes = 0,
				MinFreeDiskBytes = 0,
				OrphanGraceDays = 14,
			},
		};
	}

	private static BenchmarkMethodology BuildMethodology(StorageBenchmarkOptions options, BenchmarkWorkspace workspace)
		=> new()
		{
			WarmupRuns = options.WarmupRuns,
			TimedRuns = options.Samples,
			AggregationRule = "the value column is the MEDIAN of the timed samples; mean, min and max are in report.json",
			PercentileRule = "p95 by the nearest-rank rule over the sample set: the sample at index ceil(0.95 * n) - 1 of the ascending sequence",
			BatchLockRule = "the elapsed span of each committed delete-plus-ledger batch, reported by the retention engine's own per-batch observation hook; batches from every timed pass are pooled into one sample set and the warm-up pass's batches are counted as warm-up",
			RecommendationRule = "pure rules over the measured metrics, implemented in RdpAudit.Core.Diagnostics.StorageTuningAdvisor; a rule whose input is missing proposes nothing",
			Notes =
			[
				string.Format(
					CultureInfo.InvariantCulture,
					"every repeated measurement ran {0} warm-up run(s) (discarded) and {1} timed run(s) (kept)",
					options.WarmupRuns,
					options.Samples),
				"each retention sample ran against its own copy of the seeded store, so every sample started from byte-identical state",
				"the retention dry run was evaluated and timed before the pass, against the same instant and the same store",
				"the retention pass ran with the writer-lock budget at its supported maximum so it ran to completion; the budget decides only when the engine yields",
				"the store was filled by one bulk-load transaction, which is not the service's per-event ingestion path",
				"the snapshot duration is the backup service's own reported duration; the verification duration is a stopwatch around the call, because that result type carries no duration of its own",
				"the integrity checks ran the same PRAGMA statements the maintenance service emits, but on a read-only connection, because that service reports TimedOut instead of a duration once a step passes its 30-second limit",
			],
		};

	private static IReadOnlyList<string> BuildLimitations(StorageBenchmarkOptions options, BenchmarkWorkspace workspace) =>
	[
		"The store is synthetic and was empty before this run: what the retention machinery costs on the machine is measured, but what it costs on a store with a different row shape, a different code population or a different index state is not.",
		"No ingestion ran concurrently with any measurement, so every number here is a quiet-store number. A production store taking live events will show higher batch costs and lower pass throughput.",
		"The retention policy the probe evaluated is not a recommendation: it was configured (age floor, tail keep, batch size, per-pass budget) to make the pass do a measurable amount of work. The recommendations in section 4 are about the settings, not about this policy.",
		"The bulk-load seed is not the service's ingestion path: it measures how fast this volume can absorb rows in one transaction, not how fast the service records events.",
		"The volume write probe is a proxy: a 4 KiB flushed write through the filesystem is evidence about the device, not a measurement of SQLite's commit path.",
		"Snapshot and compaction measurements include the bytes they wrote, so a volume that is nearly full, fragmented or shared with other load will move these numbers.",
		string.Format(
			CultureInfo.InvariantCulture,
			"The benchmark store lived at {0} and was created by this run. Nothing outside that directory and the report directory was written; %ProgramData%\\RdpAudit was neither read nor written.",
			workspace.StoreDirectory),
		string.Format(
			CultureInfo.InvariantCulture,
			"This was a '{0}' profile run. A quick run seeds fewer rows and takes fewer samples, so its throughput numbers carry more fixed-cost noise and it cannot report a measured million-row timing.",
			options.ProfileName),
		"Parameters that are evidence-value decisions rather than performance results (TailKeepPerCode, CandidateMinRows, MinAgeDays, ProtectedEventIds, Sharding shard caps) get no recommendation from this tool at all: no measurement available here can decide them.",
	];
}
