/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 2.0.2
// File   : ReclaimProbe.cs
// Project: RdpAudit.StorageBenchmarks
// Purpose: Measures the three operations that give deleted pages back: PRAGMA wal_checkpoint(TRUNCATE),
//          PRAGMA incremental_vacuum(N) and the offline compaction. All three are one-shot against a
//          particular state - a checkpoint on a settled log is a no-op, an incremental vacuum on a store
//          with no freelist does nothing, and a compaction replaces the file it ran on - so measuring them
//          the way a throughput metric is measured would report the cost of doing nothing. Each sample
//          therefore prepares its OWN dirty state: a fresh copy of the seeded store with a bounded slice of
//          rows deleted, which produces real freelist pages and real log frames.
//          The compaction runs through the REAL DatabaseCompactService from the Configurator assembly with a
//          service name that cannot exist, so no Windows service is stopped or started and no privilege is
//          required. That result reports Compacted separately from Success precisely because the service
//          cannot be restarted here, and the report states which of the two the run observed rather than
//          blurring them.
// Depends: DatabaseCompactService (RdpAudit.Configurator), BenchmarkStore
// Extends: Add a reclaim operation by preparing its own state inside the sample loop; never measure a
//          one-shot operation against a state an earlier sample already consumed.

using System.Diagnostics;
using System.Globalization;
using Microsoft.Data.Sqlite;
using RdpAudit.Configurator.Services;
using RdpAudit.Core.Diagnostics;

namespace RdpAudit.StorageBenchmarks;

/// <summary>What one reclaim run produced.</summary>
internal sealed record ReclaimRunResult
{
	/// <summary>Seconds the WAL checkpoint took.</summary>
	public required double CheckpointSeconds { get; init; }

	/// <summary>Bytes the log held before the checkpoint.</summary>
	public required long WalBytesBefore { get; init; }

	/// <summary>Bytes the log holds after the checkpoint.</summary>
	public required long WalBytesAfter { get; init; }

	/// <summary>Seconds the bounded incremental vacuum took.</summary>
	public required double VacuumSeconds { get; init; }

	/// <summary>Freelist pages before the incremental vacuum.</summary>
	public required long FreelistPagesBefore { get; init; }

	/// <summary>Freelist pages after the incremental vacuum.</summary>
	public required long FreelistPagesAfter { get; init; }

	/// <summary><c>PRAGMA auto_vacuum</c> mode of the store, as reported.</summary>
	public required string AutoVacuumMode { get; init; }

	/// <summary>Main-file bytes after the incremental vacuum.</summary>
	public required long DatabaseBytesAfterVacuum { get; init; }
}

/// <summary>What one offline-compaction run produced.</summary>
internal sealed record CompactionRunResult
{
	/// <summary>Wall-clock seconds the offline compaction took.</summary>
	public required double Seconds { get; init; }

	/// <summary>The product service's own result.</summary>
	public required DatabaseCompactResult Compaction { get; init; }
}

/// <summary>Measures the WAL checkpoint, the incremental vacuum and the offline compaction.</summary>
internal static class ReclaimProbe
{
	/// <summary>Rows the probe deletes from a copy to create freelist pages and log frames. Bounded so the
	/// preparation cost stays small next to the measurement it enables.</summary>
	public const int DirtyRows = 20_000;

	/// <summary>Pages the incremental vacuum is asked to release, matching the product's own cap.</summary>
	public const int IncrementalVacuumPages = 5_000;

	/// <summary>Service name the compaction probe passes. Chosen so it cannot exist on any host: the offline
	/// compaction stops and restarts the service it is given, and this name makes both steps no-ops.</summary>
	public const string ProbeServiceName = "RdpAuditStorageBenchmarkProbe";

	/// <summary>Runs the WAL checkpoint and incremental vacuum measurements.</summary>
	public static async Task<List<BenchmarkMeasurement>> RunAsync(
		BenchmarkStore seedStore,
		StoreBlueprint blueprint,
		BenchmarkWorkspace workspace,
		BenchmarkSampleRecorder recorder,
		Action<string> log,
		CancellationToken cancellationToken)
	{
		ArgumentNullException.ThrowIfNull(seedStore);
		ArgumentNullException.ThrowIfNull(blueprint);
		ArgumentNullException.ThrowIfNull(workspace);
		ArgumentNullException.ThrowIfNull(recorder);
		ArgumentNullException.ThrowIfNull(log);

		BenchmarkSampleRun<ReclaimRunResult> run = await recorder.MeasureAsync(
			StorageBenchmarkMetric.CheckpointTruncateSeconds,
			StorageBenchmarkUnit.Seconds,
			async (index, token) =>
			{
				string directory = Path.Combine(
					workspace.RunDirectory,
					string.Format(CultureInfo.InvariantCulture, "reclaim-{0:00}", index));
				BenchmarkStore victim = seedStore.CloneTo(directory, blueprint);
				try
				{
					return await MeasureOnDirtyStoreAsync(victim, token).ConfigureAwait(false);
				}
				finally
				{
					TryDeleteTree(directory);
				}
			},
			static result => result.CheckpointSeconds,
			note: "each sample checkpoints a freshly prepared copy whose log holds real frames; a checkpoint against a settled log would measure nothing",
			cancellationToken).ConfigureAwait(false);

		List<BenchmarkMeasurement> measurements =
		[
			run.Measurement,
			BuildIncrementalVacuumMeasurement(run.Runs),
			Derive(run.Runs, StorageBenchmarkMetric.VacuumIncrementalPages, StorageBenchmarkUnit.Count, static _ => IncrementalVacuumPages),
		];

		if (run.Runs.Count > 0)
		{
			ReclaimRunResult first = run.Runs[0];
			log(string.Format(
				CultureInfo.InvariantCulture,
				"  checkpoint: {0:0.###} s (log {1} -> {2} bytes); incremental vacuum: {3:0.###} s, freelist pages {4} -> {5} ({6} pages), auto_vacuum={7}",
				first.CheckpointSeconds,
				first.WalBytesBefore,
				first.WalBytesAfter,
				first.VacuumSeconds,
				first.FreelistPagesBefore,
				first.FreelistPagesAfter,
				first.FreelistPagesBefore - first.FreelistPagesAfter,
				first.AutoVacuumMode));

			measurements[^1] = measurements[^1] with
			{
				Note = string.Format(
					CultureInfo.InvariantCulture,
					"pages the probe asked to release; the store's PRAGMA auto_vacuum reads {0} (2 = incremental, which is what lets this operation release anything at all)",
					first.AutoVacuumMode),
			};
		}

		return measurements;
	}

	/// <summary>
	/// Reports the incremental vacuum honestly: <c>PRAGMA incremental_vacuum</c> is a documented no-op
	/// unless the store is in incremental auto-vacuum mode, so a store whose mode is not 2 has not been
	/// measured for this operation at all and reporting the (near-zero) elapsed time would look like a
	/// result. The mode is a fact about the store the product created, not a property of this probe.
	/// </summary>
	private static BenchmarkMeasurement BuildIncrementalVacuumMeasurement(List<ReclaimRunResult> runs)
	{
		if (runs.Count == 0)
		{
			return BenchmarkMeasurement.NotMeasured(
				StorageBenchmarkMetric.VacuumIncrementalSeconds,
				StorageBenchmarkUnit.Seconds,
				"no reclaim run completed");
		}

		ReclaimRunResult first = runs[0];
		if (!string.Equals(first.AutoVacuumMode, "2", StringComparison.Ordinal))
		{
			return BenchmarkMeasurement.NotMeasured(
				StorageBenchmarkMetric.VacuumIncrementalSeconds,
				StorageBenchmarkUnit.Seconds,
				string.Format(
					CultureInfo.InvariantCulture,
					"PRAGMA incremental_vacuum is a no-op unless the store is in incremental auto-vacuum mode, and this store reports PRAGMA auto_vacuum = {0} (not 2). The product sets auto_vacuum = INCREMENTAL on every connection open, so on a store the product created this operation releases nothing; the elapsed time would have been {1:0.###} s and would have measured no work at all",
					first.AutoVacuumMode,
					first.VacuumSeconds));
		}

		return Derive(runs, StorageBenchmarkMetric.VacuumIncrementalSeconds, StorageBenchmarkUnit.Seconds, static result => result.VacuumSeconds);
	}

	/// <summary>Runs the offline compaction measurements, one fresh copy per sample.</summary>
	public static async Task<List<BenchmarkMeasurement>> RunCompactionAsync(
		BenchmarkStore seedStore,
		StoreBlueprint blueprint,
		BenchmarkWorkspace workspace,
		BenchmarkSampleRecorder recorder,
		Action<string> log,
		CancellationToken cancellationToken)
	{
		ArgumentNullException.ThrowIfNull(seedStore);
		ArgumentNullException.ThrowIfNull(blueprint);
		ArgumentNullException.ThrowIfNull(workspace);
		ArgumentNullException.ThrowIfNull(recorder);
		ArgumentNullException.ThrowIfNull(log);

		DatabaseCompactService compactor = new(
			ProbeServiceName,
			"RdpAudit Storage Benchmark Probe (never installed; not required)");

		BenchmarkSampleRun<CompactionRunResult> run = await recorder.MeasureAsync(
			StorageBenchmarkMetric.CompactionSeconds,
			StorageBenchmarkUnit.Seconds,
			async (index, token) =>
			{
				string directory = Path.Combine(
					workspace.RunDirectory,
					string.Format(CultureInfo.InvariantCulture, "compaction-{0:00}", index));
				BenchmarkStore victim = seedStore.CloneTo(directory, blueprint);
				try
				{
					// An untouched copy has an empty freelist, so VACUUM INTO would have nothing to shrink.
					using (SqliteConnection connection = SqliteBenchmarkFacts.Open(victim.DatabasePath))
					{
						await DeleteSliceAsync(connection, token).ConfigureAwait(false);
					}

					Stopwatch watch = Stopwatch.StartNew();
					DatabaseCompactResult result = await compactor
						.ExecuteAsync(victim.DatabasePath, token)
						.ConfigureAwait(false);
					watch.Stop();

					return new CompactionRunResult
					{
						Seconds = watch.Elapsed.TotalSeconds,
						Compaction = result,
					};
				}
				finally
				{
					TryDeleteTree(directory);
				}
			},
			static result => result.Seconds,
			note: "VACUUM INTO plus the validated atomic swap, driven through the product's offline compaction service with a service name that cannot exist, so no service was stopped or started",
			cancellationToken).ConfigureAwait(false);

		if (run.Runs.Count > 0)
		{
			CompactionRunResult first = run.Runs[0];
			log(string.Format(
				CultureInfo.InvariantCulture,
				"  compaction: {0:0.###} s, {1} -> {2} bytes (reclaimed {3}), compacted={4}",
				first.Seconds,
				first.Compaction.BytesBefore,
				first.Compaction.BytesAfter,
				first.Compaction.BytesReclaimed,
				first.Compaction.Compacted));
		}

		List<BenchmarkMeasurement> measurements =
		[
			run.Measurement,
			DeriveCompaction(run.Runs, StorageBenchmarkMetric.CompactionBytesBefore, StorageBenchmarkUnit.Bytes, static result => result.Compaction.BytesBefore),
			DeriveCompaction(run.Runs, StorageBenchmarkMetric.CompactionBytesAfter, StorageBenchmarkUnit.Bytes, static result => result.Compaction.BytesAfter),
			DeriveCompaction(run.Runs, StorageBenchmarkMetric.CompactionBytesReclaimed, StorageBenchmarkUnit.Bytes, static result => result.Compaction.BytesReclaimed),
			DeriveCompaction(run.Runs, StorageBenchmarkMetric.CompactionSucceeded, StorageBenchmarkUnit.Count, static result => result.Compaction.Compacted ? 1d : 0d),
		];

		measurements[^1] = measurements[^1] with
		{
			Note = run.Runs.Count == 0
				? "the compaction probe produced no run"
				: string.Format(
					CultureInfo.InvariantCulture,
					"1 means the store was rewritten and swapped in. The service's Success flag is false by design here: it also reports that the Windows service was restarted, and this run deliberately points the service at a name that does not exist ({0}), so nothing was stopped or started. reported={1}",
					ProbeServiceName,
					run.Runs[0].Compaction.Success),
		};

		return measurements;
	}

	/// <summary>Runs the checkpoint and incremental vacuum against one freshly dirtied store copy. The
	/// whole sequence runs on ONE open connection on purpose: closing the last connection makes SQLite
	/// checkpoint and truncate the log itself, so a probe that dirtied the store, closed the connection and
	/// then timed a checkpoint would be timing a log that no longer holds anything.</summary>
	private static async Task<ReclaimRunResult> MeasureOnDirtyStoreAsync(BenchmarkStore store, CancellationToken cancellationToken)
	{
		using SqliteConnection connection = SqliteBenchmarkFacts.Open(store.DatabasePath);
		await DeleteSliceAsync(connection, cancellationToken).ConfigureAwait(false);

		long walBefore = SqliteBenchmarkFacts.DatabaseFileBytes(store.DatabasePath + "-wal");
		double checkpointMs = SqliteBenchmarkFacts.Timed(() =>
		{
			using SqliteCommand command = connection.CreateCommand();
			command.CommandText = "PRAGMA wal_checkpoint(TRUNCATE);";
			command.ExecuteNonQuery();
		});

		long walAfter = SqliteBenchmarkFacts.DatabaseFileBytes(store.DatabasePath + "-wal");
		long freelistPagesBefore = SqliteBenchmarkFacts.ReadLong(connection, "PRAGMA freelist_count;");
		string autoVacuumMode = SqliteBenchmarkFacts.ReadText(connection, "PRAGMA auto_vacuum;");
		double vacuumMs = SqliteBenchmarkFacts.Timed(() =>
		{
			using SqliteCommand command = connection.CreateCommand();
			command.CommandText = string.Format(
				CultureInfo.InvariantCulture,
				"PRAGMA incremental_vacuum({0});",
				IncrementalVacuumPages);
			command.ExecuteNonQuery();
		});
		long freelistPagesAfter = SqliteBenchmarkFacts.ReadLong(connection, "PRAGMA freelist_count;");
		long databaseBytesAfter = SqliteBenchmarkFacts.DatabaseFileBytes(store.DatabasePath);

		return new ReclaimRunResult
		{
			CheckpointSeconds = SqliteBenchmarkFacts.ToSeconds(checkpointMs),
			WalBytesBefore = walBefore,
			WalBytesAfter = walAfter,
			VacuumSeconds = SqliteBenchmarkFacts.ToSeconds(vacuumMs),
			FreelistPagesBefore = freelistPagesBefore,
			FreelistPagesAfter = freelistPagesAfter,
			AutoVacuumMode = autoVacuumMode,
			DatabaseBytesAfterVacuum = databaseBytesAfter,
		};
	}

	/// <summary>Deletes a bounded slice of the oldest rows so the store carries a real freelist and its log
	/// carries real frames. Plain SQL on purpose: this is state preparation, not a measurement of the
	/// retention path, which is measured separately through the real engine. The slice is a quarter of the
	/// store, so the copy still holds rows afterwards and the freelist is a slice rather than the whole
	/// file.</summary>
	private static async Task DeleteSliceAsync(SqliteConnection connection, CancellationToken cancellationToken)
	{
		long highestId = SqliteBenchmarkFacts.ReadLong(connection, "SELECT COALESCE(MAX(\"Id\"), 0) FROM \"RawEvents\";");
		long slice = Math.Max(1L, Math.Min(DirtyRows, highestId / 4L));
		using SqliteCommand command = connection.CreateCommand();
		command.CommandText = string.Format(
			CultureInfo.InvariantCulture,
			"DELETE FROM \"RawEvents\" WHERE \"Id\" <= {0};",
			slice);
		await command.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
	}

	private static BenchmarkMeasurement Derive(
		List<ReclaimRunResult> runs,
		string metric,
		string unit,
		Func<ReclaimRunResult, double> selector)
	{
		if (runs.Count == 0)
		{
			return BenchmarkMeasurement.NotMeasured(metric, unit, "no reclaim run completed");
		}

		List<double> values = new(runs.Count);
		foreach (ReclaimRunResult run in runs)
		{
			values.Add(selector(run));
		}

		return BenchmarkMeasurement.FromSamples(metric, unit, BenchmarkSampleSet.FromValues(values));
	}

	private static BenchmarkMeasurement DeriveCompaction(
		List<CompactionRunResult> runs,
		string metric,
		string unit,
		Func<CompactionRunResult, double> selector)
	{
		if (runs.Count == 0)
		{
			return BenchmarkMeasurement.NotMeasured(metric, unit, "no compaction run completed");
		}

		List<double> values = new(runs.Count);
		foreach (CompactionRunResult run in runs)
		{
			values.Add(selector(run));
		}

		return BenchmarkMeasurement.FromSamples(metric, unit, BenchmarkSampleSet.FromValues(values));
	}

	private static void TryDeleteTree(string directory)
	{
		// EF pools its SQLite connections, and a pooled connection still holds the file.
		SqliteBenchmarkFacts.ClearPools();
		try
		{
			if (Directory.Exists(directory))
			{
				Directory.Delete(directory, recursive: true);
			}
		}
		catch (IOException)
		{
			// Leftovers live under this run's own directory and are removed with it.
		}
		catch (UnauthorizedAccessException)
		{
			// Same rationale as above.
		}
	}
}
