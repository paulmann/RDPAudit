/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 2.0.2
// File   : StorageTuningAdvisor.cs
// Project: RdpAudit.Core (RdpAudit.Core.Diagnostics)
// Purpose: Turns a machine profile and a set of MEASURED quantities into parameter recommendations.
//          Every rule here is a pure function of its inputs: no I/O, no clock, no configuration file,
//          no knowledge of where the numbers came from. That is deliberate and load-bearing - a
//          recommendation an operator is asked to apply to a production service has to be reproducible
//          from the published measurement table, and it has to be testable at its boundaries without a
//          machine. Nothing in this class writes a setting anywhere: it returns advice.
//
//          Three rules of construction hold for every rule below:
//            1. A parameter with a missing input produces NO number. It produces an
//               InsufficientData recommendation naming the missing metric. A plausible-looking default
//               dressed up as a measurement is the one failure mode this whole feature exists to avoid.
//            2. The rationale states the rule with this run's numbers substituted in, so the arithmetic
//               can be redone by hand from the report's measurement table.
//            3. The supported bounds of a setting are applied by clamping against the constants declared
//               on the options type, never restated here.
// Depends: RdpAudit.Core.Config (RetentionPolicyOptions, BackupOptions, ShardingOptions bounds)
// Extends: Add a parameter by adding a rule method and calling it from Advise; never emit a value that
//          was not produced by a rule that names its inputs.

using System.Globalization;
using RdpAudit.Core.Config;

namespace RdpAudit.Core.Diagnostics;

/// <summary>
/// Pure recommendation engine for RdpAudit storage parameters.
/// </summary>
public static class StorageTuningAdvisor
{
	/// <summary>Free-space floor for the retention policy.</summary>
	public const string RetentionMinFreeDiskBytesParameter = "RdpAudit:Storage:RetentionPolicy:MinFreeDiskBytes";

	/// <summary>Per-batch delete size for the retention policy.</summary>
	public const string DeleteBatchRowsParameter = "RdpAudit:Storage:RetentionPolicy:DeleteBatchRows";

	/// <summary>Writer-lock budget for a retention batch.</summary>
	public const string MaxWriterLockMsParameter = "RdpAudit:Storage:RetentionPolicy:MaxWriterLockMs";

	/// <summary>Per-pass row budget for the retention policy.</summary>
	public const string MaxRowsPerPassParameter = "RdpAudit:Storage:RetentionPolicy:MaxRowsPerPass";

	/// <summary>Free-space floor that must remain before a snapshot is taken.</summary>
	public const string BackupMinFreeDiskBytesParameter = "RdpAudit:Storage:Backup:MinFreeDiskBytesBeforeBackup";

	/// <summary>How many snapshots are kept.</summary>
	public const string BackupRetentionCopiesParameter = "RdpAudit:Storage:Backup:RetentionCopies";

	/// <summary>Free-space floor for the shard tree.</summary>
	public const string ShardingMinFreeDiskBytesParameter = "RdpAudit:Sharding:MinFreeDiskBytes";

	/// <summary>Operating practice, not a setting: how often to run a full integrity check.</summary>
	public const string FullIntegrityScheduleParameter = "Operations:FullIntegrityCheckSchedule";

	/// <summary>
	/// Produces one recommendation per parameter this engine has a rule for. The returned list is stable
	/// in order, and every rule is present even when it proposes nothing, so a report can show "not
	/// enough data" instead of silently omitting a parameter an operator is looking for.
	/// </summary>
	/// <param name="machine">The machine the measurements were taken on.</param>
	/// <param name="measurements">The measured quantities of the run.</param>
	/// <param name="targets">The goals the rules optimize for; the documented defaults when null.</param>
	public static IReadOnlyList<TuningRecommendation> Advise(
		MachineProfile machine,
		IReadOnlyList<BenchmarkMeasurement> measurements,
		StorageTuningTargets? targets = null)
	{
		ArgumentNullException.ThrowIfNull(machine);
		ArgumentNullException.ThrowIfNull(measurements);

		StorageTuningTargets goals = targets ?? StorageTuningTargets.Default;
		MeasurementIndex index = new(measurements);
		List<TuningRecommendation> advice = [];

		long? writerLockMs = AdviseWriterLockMs(index, goals, advice);
		AdviseDeleteBatchRows(index, goals, writerLockMs, advice);
		AdviseMaxRowsPerPass(index, goals, advice);
		AdviseRetentionFreeSpaceFloor(machine, index, goals, advice);
		long? backupFloor = AdviseBackupFreeSpaceFloor(machine, index, goals, advice);
		AdviseBackupRetentionCopies(machine, index, goals, backupFloor, advice);
		AdviseShardingFreeSpaceFloor(machine, index, goals, advice);
		AdviseFullIntegritySchedule(index, goals, advice);

		return advice;
	}

	// ── Retention: writer-lock budget ────────────────────────────────────────────

	private static long? AdviseWriterLockMs(
		MeasurementIndex index,
		StorageTuningTargets goals,
		List<TuningRecommendation> advice)
	{
		const string Rule = "ceil(p95 batch writer-lock hold x headroom factor), clamped to the supported range";
		if (index.P95(StorageBenchmarkMetric.RetentionBatchLockMs) is not { } p95)
		{
			advice.Add(TuningRecommendation.Insufficient(
				MaxWriterLockMsParameter,
				Rule,
				"The engine's per-batch writer-lock budget can only be sized from a measured batch hold, and this run did not measure one.",
				[Missing(StorageBenchmarkMetric.RetentionBatchLockMs)]));
			return null;
		}

		double scaled = Math.Ceiling(p95 * goals.WriterLockHeadroomFactor);
		long value = (long)Math.Clamp(
			scaled,
			RetentionPolicyOptions.MinMaxWriterLockMs,
			RetentionPolicyOptions.MaxMaxWriterLockMs);

		advice.Add(TuningRecommendation.Recommended(
			MaxWriterLockMsParameter,
			value,
			"ms",
			Rule,
			string.Format(
				CultureInfo.InvariantCulture,
				"A retention batch held the writer for a median of {0:0.###} ms and a p95 of {1:0.###} ms. The budget is {2:0.##}x the p95 ({3:0.###} ms), which is the room for a batch slower than nineteen in twenty, clamped to the supported range [{4}, {5}] ms.",
				index.Median(StorageBenchmarkMetric.RetentionBatchLockMs) ?? 0d,
				p95,
				goals.WriterLockHeadroomFactor,
				scaled,
				RetentionPolicyOptions.MinMaxWriterLockMs,
				RetentionPolicyOptions.MaxMaxWriterLockMs),
			[
				Input(StorageBenchmarkMetric.RetentionBatchLockMs, p95, StorageBenchmarkUnit.Milliseconds, "p95"),
				Input(StorageBenchmarkMetric.RetentionBatchLockMs, index.Median(StorageBenchmarkMetric.RetentionBatchLockMs) ?? 0d, StorageBenchmarkUnit.Milliseconds, "median"),
				"goal: writer-lock headroom factor = " + goals.WriterLockHeadroomFactor.ToString("0.##", CultureInfo.InvariantCulture),
			],
			"The batch hold was measured on this benchmark store with no concurrent ingestion and no concurrent snapshot or compaction. Exceeding the budget does not lose data: the engine stops the pass and defers the remaining rows to its next tick, so a budget that is too small costs throughput rather than correctness. Re-measure on a store that is taking live ingestion before treating this as final."));

		return value;
	}

	// ── Retention: batch size ───────────────────────────────────────────────────

	private static void AdviseDeleteBatchRows(
		MeasurementIndex index,
		StorageTuningTargets goals,
		long? recommendedWriterLockMs,
		List<TuningRecommendation> advice)
	{
		const string Rule = "floor((recommended writer-lock budget x batch budget share) / measured ms per row), rounded down to the batch step";
		double? p95 = index.P95(StorageBenchmarkMetric.RetentionBatchLockMs);
		double? batchRows = index.Median(StorageBenchmarkMetric.RetentionBatchRows);
		if (p95 is null || batchRows is null || recommendedWriterLockMs is null)
		{
			List<string> missing = [];
			if (p95 is null)
			{
				missing.Add(Missing(StorageBenchmarkMetric.RetentionBatchLockMs));
			}

			if (batchRows is null)
			{
				missing.Add(Missing(StorageBenchmarkMetric.RetentionBatchRows));
			}

			if (recommendedWriterLockMs is null)
			{
				missing.Add(Missing(MaxWriterLockMsParameter));
			}

			advice.Add(TuningRecommendation.Insufficient(
				DeleteBatchRowsParameter,
				Rule,
				"The batch size is sized from the measured cost of a batch, which this run could not establish.",
				missing));
			return;
		}

		if (batchRows.Value <= 0d || p95.Value <= 0d)
		{
			advice.Add(TuningRecommendation.Insufficient(
				DeleteBatchRowsParameter,
				Rule,
				string.Format(
					CultureInfo.InvariantCulture,
					"The measured batch of {0:0.###} rows took {1:0.###} ms, which is not a positive cost per row and cannot be extrapolated.",
					batchRows.Value,
					p95.Value),
				[Missing(StorageBenchmarkMetric.RetentionBatchLockMs)]));
			return;
		}

		double msPerRow = p95.Value / batchRows.Value;
		double budgetForOneBatch = recommendedWriterLockMs.Value * goals.BatchBudgetShare;
		double affordableRows = budgetForOneBatch / msPerRow;
		long rounded = RoundDown((long)Math.Floor(affordableRows), goals.BatchRoundStep);
		long value = Math.Clamp(
			rounded,
			RetentionPolicyOptions.MinDeleteBatchRows,
			RetentionPolicyOptions.MaxDeleteBatchRows);

		advice.Add(TuningRecommendation.Recommended(
			DeleteBatchRowsParameter,
			value,
			"rows",
			Rule,
			string.Format(
				CultureInfo.InvariantCulture,
				"The measured batch of {0:0.###} rows held the writer for {1:0.###} ms at p95, i.e. {2:0.#####} ms per row. Half of the recommended {3} ms budget is {4:0.###} ms, which at that cost covers {5:0.###} rows; rounded down to the {6}-row step that is {7} rows.",
				batchRows.Value,
				p95.Value,
				msPerRow,
				recommendedWriterLockMs.Value,
				budgetForOneBatch,
				affordableRows,
				goals.BatchRoundStep,
				value),
			[
				Input(StorageBenchmarkMetric.RetentionBatchLockMs, p95.Value, StorageBenchmarkUnit.Milliseconds, "p95"),
				Input(StorageBenchmarkMetric.RetentionBatchRows, batchRows.Value, StorageBenchmarkUnit.Rows, "median"),
				"recommended " + MaxWriterLockMsParameter + " = " + recommendedWriterLockMs.Value.ToString(CultureInfo.InvariantCulture) + " ms",
				"goal: batch budget share = " + goals.BatchBudgetShare.ToString("0.##", CultureInfo.InvariantCulture),
			],
			"The per-row cost is derived from one measured batch size and charges that batch's fixed cost - transaction open, ledger chain hash, commit - to every row, so the estimate is conservative: a larger batch is cheaper per row than this implies. Re-measure after changing the batch size, because the real curve is not linear."));
	}

	// ── Retention: per-pass row budget ──────────────────────────────────────────

	private static void AdviseMaxRowsPerPass(
		MeasurementIndex index,
		StorageTuningTargets goals,
		List<TuningRecommendation> advice)
	{
		const string Rule = "measured retention rows/s x target pass seconds, rounded down to the row step";
		if (index.Median(StorageBenchmarkMetric.RetentionRowsPerSecond) is not { } rowsPerSecond)
		{
			advice.Add(TuningRecommendation.Insufficient(
				MaxRowsPerPassParameter,
				Rule,
				"The per-pass row budget is sized from the measured retention throughput, which this run did not measure.",
				[Missing(StorageBenchmarkMetric.RetentionRowsPerSecond)]));
			return;
		}

		if (rowsPerSecond <= 0d)
		{
			advice.Add(TuningRecommendation.Insufficient(
				MaxRowsPerPassParameter,
				Rule,
				"The measured retention throughput was zero rows per second, so no per-pass budget can be derived from it.",
				[Missing(StorageBenchmarkMetric.RetentionRowsPerSecond)]));
			return;
		}

		double rows = rowsPerSecond * goals.TargetRetentionPassSeconds;
		long rounded = RoundDown((long)Math.Floor(rows), goals.RowRoundStep);
		long value = Math.Clamp(rounded, RetentionPolicyOptions.MinMaxRowsPerPass, RetentionPolicyOptions.MaxMaxRowsPerPass);

		advice.Add(TuningRecommendation.Recommended(
			MaxRowsPerPassParameter,
			value,
			"rows",
			Rule,
			string.Format(
				CultureInfo.InvariantCulture,
				"The pass removed rows at a measured {0:0.###} rows/s. A pass targeted at {1} s - half the retention worker's one-minute tick - therefore covers {2:0.###} rows; rounded down to the {3}-row step that is {4} rows.",
				rowsPerSecond,
				goals.TargetRetentionPassSeconds,
				rows,
				goals.RowRoundStep,
				value),
			[
				Input(StorageBenchmarkMetric.RetentionRowsPerSecond, rowsPerSecond, StorageBenchmarkUnit.RowsPerSecond, "median"),
				"goal: target retention pass = " + goals.TargetRetentionPassSeconds.ToString(CultureInfo.InvariantCulture) + " s",
			],
			"The budget caps how many rows one pass may remove; it does not promise the pass completes in the target time. The measured throughput is the delete-plus-ledger path on an idle store, so on a store taking live ingestion the same budget takes longer in wall-clock terms. A larger budget is not free either: it widens the window in which a single pass holds the writer repeatedly."));
	}

	// ── Retention: free-space floor ─────────────────────────────────────────────

	private static void AdviseRetentionFreeSpaceFloor(
		MachineProfile machine,
		MeasurementIndex index,
		StorageTuningTargets goals,
		List<TuningRecommendation> advice)
	{
		const string Rule = "measured store bytes + measured snapshot bytes + free-space headroom, refused when it exceeds the share of the volume a floor may claim";
		double? storeBytes = index.Median(StorageBenchmarkMetric.RetentionStoreBytesBefore)
			?? index.Median(StorageBenchmarkMetric.SeedStoreBytes);
		double? snapshotBytes = index.Median(StorageBenchmarkMetric.BackupSnapshotBytes);

		if (storeBytes is null || snapshotBytes is null || machine.StoreVolume.TotalBytes <= 0)
		{
			List<string> missing = [];
			if (storeBytes is null)
			{
				missing.Add(Missing(StorageBenchmarkMetric.RetentionStoreBytesBefore));
			}

			if (snapshotBytes is null)
			{
				missing.Add(Missing(StorageBenchmarkMetric.BackupSnapshotBytes));
			}

			if (machine.StoreVolume.TotalBytes <= 0)
			{
				missing.Add("machine profile: store volume total bytes (not collected)");
			}

			advice.Add(TuningRecommendation.Insufficient(
				RetentionMinFreeDiskBytesParameter,
				Rule,
				"The floor has to cover the store, one snapshot of it and working headroom; this run is missing at least one of those sizes.",
				missing));
			return;
		}

		double required = storeBytes.Value + snapshotBytes.Value + goals.FreeSpaceHeadroomBytes;
		long cap = (long)(machine.StoreVolume.TotalBytes * goals.MaxFreeSpaceFloorVolumeShare);

		advice.Add(BuildByteFloorAdvice(
			RetentionMinFreeDiskBytesParameter,
			Rule,
			required,
			cap,
			goals,
			string.Format(
				CultureInfo.InvariantCulture,
				"the store is {0:0} bytes, a snapshot of it is {1:0} bytes and {2:0} bytes of working headroom are reserved",
				storeBytes.Value,
				snapshotBytes.Value,
				goals.FreeSpaceHeadroomBytes),
			[
				Input(StorageBenchmarkMetric.RetentionStoreBytesBefore, storeBytes.Value, StorageBenchmarkUnit.Bytes, "median"),
				Input(StorageBenchmarkMetric.BackupSnapshotBytes, snapshotBytes.Value, StorageBenchmarkUnit.Bytes, "median"),
				"machine profile: store volume total = " + machine.StoreVolume.TotalBytes.ToString(CultureInfo.InvariantCulture) + " bytes",
				"goal: free-space headroom = " + goals.FreeSpaceHeadroomBytes.ToString(CultureInfo.InvariantCulture) + " bytes",
				"goal: floor may claim at most " + (goals.MaxFreeSpaceFloorVolumeShare * 100d).ToString("0.#", CultureInfo.InvariantCulture) + "% of the volume",
			],
			"The floor is a deletion trigger, not a reservation: it makes the retention policy start deleting when free space falls below it. The store size measured here is the synthetic benchmark store, so re-measure on the real store before adopting the number. Zero is also a defensible setting when the store volume has ample free space and the row budget alone governs retention."));
	}

	// ── Backup: free-space floor ────────────────────────────────────────────────

	private static long? AdviseBackupFreeSpaceFloor(
		MachineProfile machine,
		MeasurementIndex index,
		StorageTuningTargets goals,
		List<TuningRecommendation> advice)
	{
		const string Rule = "measured snapshot bytes + free-space headroom, refused when it exceeds the share of the volume a floor may claim";
		if (index.Median(StorageBenchmarkMetric.BackupSnapshotBytes) is not { } snapshotBytes
			|| machine.StoreVolume.TotalBytes <= 0)
		{
			List<string> missing = [];
			if (index.Median(StorageBenchmarkMetric.BackupSnapshotBytes) is null)
			{
				missing.Add(Missing(StorageBenchmarkMetric.BackupSnapshotBytes));
			}

			if (machine.StoreVolume.TotalBytes <= 0)
			{
				missing.Add("machine profile: store volume total bytes (not collected)");
			}

			advice.Add(TuningRecommendation.Insufficient(
				BackupMinFreeDiskBytesParameter,
				Rule,
				"The snapshot free-space floor is sized from the measured size of a snapshot, which this run is missing.",
				missing));
			return null;
		}

		double required = snapshotBytes + goals.FreeSpaceHeadroomBytes;
		long cap = (long)(machine.StoreVolume.TotalBytes * goals.MaxFreeSpaceFloorVolumeShare);

		TuningRecommendation floorAdvice = BuildByteFloorAdvice(
			BackupMinFreeDiskBytesParameter,
			Rule,
			required,
			cap,
			goals,
			string.Format(
				CultureInfo.InvariantCulture,
				"a snapshot of the measured store is {0:0} bytes and {1:0} bytes of working headroom are reserved",
				snapshotBytes,
				goals.FreeSpaceHeadroomBytes),
			[
				Input(StorageBenchmarkMetric.BackupSnapshotBytes, snapshotBytes, StorageBenchmarkUnit.Bytes, "median"),
				"machine profile: store volume total = " + machine.StoreVolume.TotalBytes.ToString(CultureInfo.InvariantCulture) + " bytes",
				"goal: free-space headroom = " + goals.FreeSpaceHeadroomBytes.ToString(CultureInfo.InvariantCulture) + " bytes",
			],
			"The floor is checked before a snapshot is written, so it must exceed the size of the copy about to be made plus the room the service needs afterwards. Snapshot size grows with the store; re-measure after the retention policy has been running long enough to reach its steady state.");

		advice.Add(floorAdvice);

		// A declined floor proposes nothing, so the snapshot-count rule below has to fall back to
		// "no floor reserved" rather than reuse a number the floor rule refused to stand behind.
		return floorAdvice.Value;
	}

	// ── Backup: how many snapshots to keep ──────────────────────────────────────

	private static void AdviseBackupRetentionCopies(
		MachineProfile machine,
		MeasurementIndex index,
		StorageTuningTargets goals,
		long? recommendedBackupFloor,
		List<TuningRecommendation> advice)
	{
		const string Rule = "floor((volume free bytes - backup free-space floor) / measured snapshot bytes), clamped to the supported range";
		double? snapshotBytes = index.Median(StorageBenchmarkMetric.BackupSnapshotBytes);
		if (snapshotBytes is null || machine.StoreVolume.FreeBytes <= 0)
		{
			List<string> missing = [];
			if (snapshotBytes is null)
			{
				missing.Add(Missing(StorageBenchmarkMetric.BackupSnapshotBytes));
			}

			if (machine.StoreVolume.FreeBytes <= 0)
			{
				missing.Add("machine profile: store volume free bytes (not collected)");
			}

			advice.Add(TuningRecommendation.Insufficient(
				BackupRetentionCopiesParameter,
				Rule,
				"How many snapshots the volume can hold is a division of the measured snapshot size into the measured free space, and this run is missing one of the two.",
				missing));
			return;
		}

		if (snapshotBytes.Value <= 0d)
		{
			advice.Add(TuningRecommendation.Insufficient(
				BackupRetentionCopiesParameter,
				Rule,
				"The measured snapshot size was zero bytes, so the volume's capacity in snapshots cannot be computed.",
				[Missing(StorageBenchmarkMetric.BackupSnapshotBytes)]));
			return;
		}

		long floor = recommendedBackupFloor ?? 0L;
		double usable = machine.StoreVolume.FreeBytes - floor;
		double affordable = usable / snapshotBytes.Value;
		long value = Math.Clamp(
			(long)Math.Floor(affordable),
			BackupOptions.MinRetentionCopies,
			BackupOptions.MaxRetentionCopies);

		string floorNote = recommendedBackupFloor is null
			? " no backup free-space floor is recommended, so the whole free space counts"
			: string.Format(
				CultureInfo.InvariantCulture,
				" after reserving the recommended {0} byte backup free-space floor",
				floor);

		string shortfall = usable <= 0
			? " The free space is already at or below that floor, so the volume cannot hold a further snapshot and the recommendation is the minimum that still keeps one recovery point."
			: string.Empty;

		advice.Add(TuningRecommendation.Recommended(
			BackupRetentionCopiesParameter,
			value,
			"copies",
			Rule,
			string.Format(
				CultureInfo.InvariantCulture,
				"The volume has {0:0} bytes free;{1}, {2:0} bytes are usable, which at the measured {3:0} bytes per snapshot covers {4:0.###} snapshots, clamped to the supported range [{5}, {6}] to {7}.{8}",
				machine.StoreVolume.FreeBytes,
				floorNote,
				usable,
				snapshotBytes.Value,
				affordable,
				BackupOptions.MinRetentionCopies,
				BackupOptions.MaxRetentionCopies,
				value,
				shortfall),
			[
				Input(StorageBenchmarkMetric.BackupSnapshotBytes, snapshotBytes.Value, StorageBenchmarkUnit.Bytes, "median"),
				"machine profile: store volume free = " + machine.StoreVolume.FreeBytes.ToString(CultureInfo.InvariantCulture) + " bytes",
				"recommended " + BackupMinFreeDiskBytesParameter + " = " + floor.ToString(CultureInfo.InvariantCulture) + " bytes",
			],
			"Free space is a snapshot of this run, not a forecast, and each snapshot is the size of the store at the time it was taken - a growing store makes this count fall. Snapshots of the settings scope are not counted by this retention and are never deleted by it."));
	}

	// ── Sharding: free-space floor ──────────────────────────────────────────────

	private static void AdviseShardingFreeSpaceFloor(
		MachineProfile machine,
		MeasurementIndex index,
		StorageTuningTargets goals,
		List<TuningRecommendation> advice)
	{
		const string Rule = "measured shard tree bytes + free-space headroom, refused when it exceeds the share of the volume a floor may claim";
		if (index.Median(StorageBenchmarkMetric.BackupShardBytes) is not { } shardBytes
			|| machine.StoreVolume.TotalBytes <= 0)
		{
			List<string> missing = [];
			if (index.Median(StorageBenchmarkMetric.BackupShardBytes) is null)
			{
				missing.Add(Missing(StorageBenchmarkMetric.BackupShardBytes));
			}

			if (machine.StoreVolume.TotalBytes <= 0)
			{
				missing.Add("machine profile: store volume total bytes (not collected)");
			}

			advice.Add(TuningRecommendation.Insufficient(
				ShardingMinFreeDiskBytesParameter,
				Rule,
				"The shard disk floor is sized from the measured size of the shard tree, which this run is missing. The shard tree is only measured when the run is asked to include shards in a snapshot.",
				missing));
			return;
		}

		double required = shardBytes + goals.FreeSpaceHeadroomBytes;
		long cap = (long)(machine.StoreVolume.TotalBytes * goals.MaxFreeSpaceFloorVolumeShare);

		advice.Add(BuildByteFloorAdvice(
			ShardingMinFreeDiskBytesParameter,
			Rule,
			required,
			cap,
			goals,
			string.Format(
				CultureInfo.InvariantCulture,
				"the measured shard tree is {0:0} bytes and {1:0} bytes of working headroom are reserved",
				shardBytes,
				goals.FreeSpaceHeadroomBytes),
			[
				Input(StorageBenchmarkMetric.BackupShardBytes, shardBytes, StorageBenchmarkUnit.Bytes, "median"),
				"machine profile: store volume total = " + machine.StoreVolume.TotalBytes.ToString(CultureInfo.InvariantCulture) + " bytes",
				"goal: free-space headroom = " + goals.FreeSpaceHeadroomBytes.ToString(CultureInfo.InvariantCulture) + " bytes",
			],
			"The measured shard tree is the synthetic tree this run created, not the production actions tree. When the floor is breached the shard sink refuses new shard files and reports the refusal rather than writing; that is a governance brake, not data loss. Scale the number by the ratio of the real tree to the measured one before adopting it."));
	}

	// ── Maintenance: full integrity-check schedule ───────────────────────────────

	private static void AdviseFullIntegritySchedule(
		MeasurementIndex index,
		StorageTuningTargets goals,
		List<TuningRecommendation> advice)
	{
		const string Rule = "measured full integrity_check duration mapped to an interval: at most 60 s weekly, at most 300 s monthly, longer than that not on a schedule";
		if (index.Median(StorageBenchmarkMetric.IntegrityFullCheckSeconds) is not { } seconds)
		{
			advice.Add(TuningRecommendation.Insufficient(
				FullIntegrityScheduleParameter,
				Rule,
				"A maintenance schedule can only be chosen from the measured cost of the operation, which this run did not measure.",
				[Missing(StorageBenchmarkMetric.IntegrityFullCheckSeconds)],
				isConfigurationSetting: false));
			return;
		}

		string stepTimeoutNote = seconds * 1000d > goals.MaintenanceStepTimeoutMs
			? string.Format(
				CultureInfo.InvariantCulture,
				" Measured cost {0:0.###} s exceeds the service's {1} ms per-step timeout on database maintenance, so a full integrity check started through that command reports TimedOut instead of a result; run it out of band (for example with the sqlite3 tool against a stopped service) rather than expecting the maintenance command to carry it.",
				seconds,
				goals.MaintenanceStepTimeoutMs)
			: string.Format(
				CultureInfo.InvariantCulture,
				" Measured cost {0:0.###} s is inside the service's {1} ms per-step timeout on database maintenance, so the maintenance command can carry it.",
				seconds,
				goals.MaintenanceStepTimeoutMs);

		string[] inputs =
		[
			Input(StorageBenchmarkMetric.IntegrityFullCheckSeconds, seconds, StorageBenchmarkUnit.Seconds, "median"),
			Input(StorageBenchmarkMetric.IntegrityQuickCheckSeconds, index.Median(StorageBenchmarkMetric.IntegrityQuickCheckSeconds), StorageBenchmarkUnit.Seconds, "median"),
			"goal: weekly at most " + goals.WeeklyIntegrityMaxSeconds.ToString(CultureInfo.InvariantCulture) + " s, monthly at most " + goals.MonthlyIntegrityMaxSeconds.ToString(CultureInfo.InvariantCulture) + " s",
		];

		if (seconds <= goals.WeeklyIntegrityMaxSeconds)
		{
			advice.Add(TuningRecommendation.Recommended(
				FullIntegrityScheduleParameter,
				7,
				"days between full checks",
				Rule,
				string.Format(
					CultureInfo.InvariantCulture,
					"A full integrity check of the measured store took {0:0.###} s, which is inside the {1} s a weekly schedule tolerates.{2}",
					seconds,
					goals.WeeklyIntegrityMaxSeconds,
					stepTimeoutNote),
				inputs,
				"This is an operating practice, not a setting: RdpAudit has no configuration key for a full integrity schedule and triggers maintenance only when an operator asks for it. The cost was measured on the benchmark store; a production store with more rows costs proportionally more, so re-measure before committing to the interval.",
				isConfigurationSetting: false));
			return;
		}

		if (seconds <= goals.MonthlyIntegrityMaxSeconds)
		{
			advice.Add(TuningRecommendation.Recommended(
				FullIntegrityScheduleParameter,
				30,
				"days between full checks",
				Rule,
				string.Format(
					CultureInfo.InvariantCulture,
					"A full integrity check of the measured store took {0:0.###} s, which is past the {1} s a weekly schedule tolerates but inside the {2} s a monthly schedule tolerates.{3}",
					seconds,
					goals.WeeklyIntegrityMaxSeconds,
					goals.MonthlyIntegrityMaxSeconds,
					stepTimeoutNote),
				inputs,
				"This is an operating practice, not a setting. At this cost a weekly check competes with the service for the store for a noticeable period, so run it monthly, out of hours, and keep the cheap quick_check for routine confirmation.",
				isConfigurationSetting: false));
			return;
		}

		advice.Add(TuningRecommendation.Declined(
			FullIntegrityScheduleParameter,
			Rule,
			string.Format(
				CultureInfo.InvariantCulture,
				"A full integrity check of the measured store took {0:0.###} s, past the {1} s a monthly schedule tolerates. Do not put it on a recurring schedule at this store size; run it only when a specific incident justifies it. Keep PRAGMA quick_check as the routine check, which measured {2}.{3}",
				seconds,
				goals.MonthlyIntegrityMaxSeconds,
				index.Median(StorageBenchmarkMetric.IntegrityQuickCheckSeconds) is { } quick
					? string.Format(CultureInfo.InvariantCulture, "{0:0.###} s on the same store", quick)
					: "not measured by this run",
				stepTimeoutNote),
			inputs,
			"This is an operating practice, not a setting, and this is a refusal rather than a value. A store whose full check has grown this long is usually a store whose retention policy is not keeping up; treat the retention numbers in this same report as the first thing to fix.",
			isConfigurationSetting: false));
	}

	// ── Shared rule bodies ──────────────────────────────────────────────────────

	private static TuningRecommendation BuildByteFloorAdvice(
		string parameter,
		string rule,
		double required,
		long cap,
		StorageTuningTargets goals,
		string artifactDescription,
		List<string> inputs,
		string caveat)
	{
		if (required > cap)
		{
			return TuningRecommendation.Declined(
				parameter,
				rule,
				string.Format(
					CultureInfo.InvariantCulture,
					"{0}, so the floor would have to be {1:0} bytes - more than the {2:0} byte ceiling a floor may claim ({3:0.#}% of the {4:0} byte volume). Do not set this floor: a floor that large would have the retention policy deleting to protect against a volume that cannot hold the store in the first place. Reduce what the volume has to hold instead - a shorter retention window or a smaller snapshot count - and leave the floor at zero.",
					artifactDescription,
					required,
					cap,
					goals.MaxFreeSpaceFloorVolumeShare * 100d,
					cap / goals.MaxFreeSpaceFloorVolumeShare),
				inputs,
				caveat);
		}

		long value = RoundUp((long)required, goals.ByteRoundStep);
		return TuningRecommendation.Recommended(
			parameter,
			value,
			"bytes",
			rule,
			string.Format(
				CultureInfo.InvariantCulture,
				"{0}, i.e. {1:0} bytes exactly, rounded up to the {2}-byte step = {3} bytes. That is inside the {4:0} byte ceiling a floor may claim on this volume.",
				artifactDescription,
				required,
				goals.ByteRoundStep,
				value,
				cap),
			inputs,
			caveat);
	}

	private static long RoundDown(long value, int step)
	{
		if (step <= 1)
		{
			return value;
		}

		long remainder = value % step;
		return value - remainder;
	}

	private static long RoundUp(long value, long step)
	{
		if (step <= 1 || value <= 0)
		{
			return value;
		}

		long remainder = value % step;
		return remainder == 0 ? value : value + (step - remainder);
	}

	private static string Input(string metric, double? value, string unit, string statistic)
		=> value is { } number
			? string.Format(CultureInfo.InvariantCulture, "{0} ({1}) = {2:0.###} {3}", metric, statistic, number, unit)
			: string.Format(CultureInfo.InvariantCulture, "{0} ({1}) = not measured", metric, statistic);

	private static string Missing(string metric)
		=> metric + " not measured by this run";

	/// <summary>
	/// Read-only lookup over a run's measurements. Only <see cref="MeasurementState.Measured"/> entries
	/// answer, so a rule can never read a value out of a metric the run failed to measure.
	/// </summary>
	private sealed class MeasurementIndex
	{
		private readonly Dictionary<string, BenchmarkMeasurement> _byMetric = new(StringComparer.Ordinal);

		public MeasurementIndex(IReadOnlyList<BenchmarkMeasurement> measurements)
		{
			foreach (BenchmarkMeasurement measurement in measurements)
			{
				if (measurement.State == MeasurementState.Measured)
				{
					_byMetric.TryAdd(measurement.Metric, measurement);
				}
			}
		}

		public double? Median(string metric)
		{
			if (!_byMetric.TryGetValue(metric, out BenchmarkMeasurement? measurement))
			{
				return null;
			}

			return measurement.Value;
		}

		public double? P95(string metric)
		{
			if (!_byMetric.TryGetValue(metric, out BenchmarkMeasurement? measurement)
				|| measurement.Samples is not { } samples)
			{
				return null;
			}

			return samples.P95;
		}
	}
}
