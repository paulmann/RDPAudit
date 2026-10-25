/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 2.0.2
// File   : BackupProbe.cs
// Project: RdpAudit.StorageBenchmarks
// Purpose: Measures database snapshots, snapshot verification and the shard-inclusive snapshot through
//          the REAL DatabaseBackupService and the REAL DatabaseSnapshotVerifier - the same code an
//          operator's Backup button drives. The probe never computes a snapshot path itself and never
//          copies a file itself, so what it times is the product's own sequence: copy, hash, manifest,
//          quick_check, migration and row-count comparison.
//          Two conventions are stated rather than hidden: the snapshot duration is the service's OWN
//          reported duration (not a stopwatch around the call), while the verification duration is a
//          stopwatch around the call because the verification DTO carries no duration - the report says
//          which is which.
//          Disk discipline: a snapshot is the size of the store, so each measured snapshot except the one
//          the verification probe needs is deleted AFTER its timing has been taken, and that deletion is
//          outside the timed delegate by construction.
// Depends: DatabaseBackupService, DatabaseSnapshotVerifier, ShardWriter, ShardPath
// Extends: Add a snapshot metric by extending SnapshotRunResult and the reduction at the end.

using System.Diagnostics;
using System.Globalization;
using System.Net;
using Microsoft.Extensions.Logging.Abstractions;
using RdpAudit.Core.Backup;
using RdpAudit.Core.Diagnostics;
using RdpAudit.Core.Ipc.Contracts;
using RdpAudit.Core.Storage.Sharding;
using RdpAudit.Core.Util;
using RdpAudit.Service.Services;

namespace RdpAudit.StorageBenchmarks;

/// <summary>What one snapshot run produced.</summary>
internal sealed record SnapshotRunResult
{
	/// <summary>Snapshot directory name the service chose.</summary>
	public required string SnapshotName { get; init; }

	/// <summary>Absolute snapshot directory.</summary>
	public required string SnapshotDirectory { get; init; }

	/// <summary>Bytes of the copied database.</summary>
	public required long DatabaseBytes { get; init; }

	/// <summary>Seconds the service reported for the snapshot.</summary>
	public required double Seconds { get; init; }

	/// <summary>Shard files copied; zero when shards were not requested.</summary>
	public required int ShardFiles { get; init; }

	/// <summary>Bytes of shard data copied; zero when shards were not requested.</summary>
	public required long ShardBytes { get; init; }

	/// <summary>Mebibytes per second across the database copy and any shard data.</summary>
	public double MebibytesPerSecond
		=> Seconds > 0d ? (DatabaseBytes + ShardBytes) / 1048576d / Seconds : 0d;
}

/// <summary>What one verification run produced.</summary>
internal sealed record VerifyRunResult
{
	/// <summary>Wall-clock seconds the verification took.</summary>
	public required double Seconds { get; init; }

	/// <summary>The verdict the verifier reached, as text.</summary>
	public required string Verdict { get; init; }
}

/// <summary>Measures snapshots, verification and the shard-inclusive snapshot.</summary>
internal static class BackupProbe
{
	/// <summary>Shard files the quick profile writes into the synthetic shard tree.</summary>
	public const int QuickShardFiles = 128;

	/// <summary>Shard files the full profile writes into the synthetic shard tree.</summary>
	public const int FullShardFiles = 512;

	/// <summary>Shard records written into each synthetic shard file, so the tree holds real shard files
	/// rather than bare allocations of the expected length.</summary>
	public const int ShardRecordsPerFile = 16;

	/// <summary>Shard capacity the synthetic tree is written with: the product default.</summary>
	public const int ShardCapacityRecords = 1024;

	/// <summary>Snapshot retention the probe's backup settings keep, so the service's own snapshot
	/// retention never deletes a snapshot inside a timed interval.</summary>
	public const int ProbeRetentionCopies = 100;

	/// <summary>Runs the snapshot and verification measurements.</summary>
	public static async Task<List<BenchmarkMeasurement>> RunAsync(
		BenchmarkStore store,
		BenchmarkWorkspace workspace,
		bool includeShards,
		int shardFileCount,
		BenchmarkSampleRecorder recorder,
		Action<string> log,
		CancellationToken cancellationToken)
	{
		ArgumentNullException.ThrowIfNull(store);
		ArgumentNullException.ThrowIfNull(workspace);
		ArgumentNullException.ThrowIfNull(recorder);
		ArgumentNullException.ThrowIfNull(log);

		List<BenchmarkMeasurement> measurements = [];
		DatabaseBackupService service = new(
			store.OptionsMonitor,
			NullLogger<DatabaseBackupService>.Instance,
			new FixedPathsProvider(workspace.RunDirectory));

		string? directoryToVerify = null;
		BenchmarkSampleRun<SnapshotRunResult> plain = await recorder.MeasureAsync(
			StorageBenchmarkMetric.BackupSnapshotSeconds,
			StorageBenchmarkUnit.Seconds,
			async (_, token) =>
			{
				SnapshotRunResult result = await CreateSnapshotAsync(service, store, includeShards: false, token).ConfigureAwait(false);

				// Keep the last one for the verification probe; drop the earlier ones so the run does not
				// fill the volume with copies of the same store. Untimed by construction.
				if (directoryToVerify is not null)
				{
					TryDeleteTree(directoryToVerify);
				}

				directoryToVerify = result.SnapshotDirectory;
				return result;
			},
			static result => result.Seconds,
			note: "the service's own reported duration, which already covers the copy, the SHA-256, the manifest, quick_check and the migration and row-count comparison",
			cancellationToken).ConfigureAwait(false);

		measurements.Add(plain.Measurement);
		measurements.Add(Derive(plain.Runs, StorageBenchmarkMetric.BackupSnapshotBytes, StorageBenchmarkUnit.Bytes, static result => result.DatabaseBytes));
		measurements.Add(Derive(plain.Runs, StorageBenchmarkMetric.BackupSnapshotMebibytesPerSecond, StorageBenchmarkUnit.MebibytesPerSecond, static result => result.MebibytesPerSecond));

		if (plain.Runs.Count > 0)
		{
			log(string.Format(
				CultureInfo.InvariantCulture,
				"  snapshot: {0:0.###} s for {1} bytes ({2:0.###} MiB/s)",
				plain.Measurement.Value ?? 0d,
				plain.Runs[0].DatabaseBytes,
				plain.Runs[0].MebibytesPerSecond));
		}

		measurements.AddRange(await VerifyAsync(store, service, directoryToVerify, recorder, log, cancellationToken).ConfigureAwait(false));

		if (includeShards)
		{
			measurements.AddRange(await SnapshotWithShardsAsync(store, service, workspace, shardFileCount, recorder, log, cancellationToken).ConfigureAwait(false));
		}
		else
		{
			measurements.Add(BenchmarkMeasurement.NotMeasured(
				StorageBenchmarkMetric.BackupShardSnapshotSeconds,
				StorageBenchmarkUnit.Seconds,
				"the shard-inclusive snapshot probe was skipped (--no-shards)"));
			measurements.Add(BenchmarkMeasurement.NotMeasured(
				StorageBenchmarkMetric.BackupShardBytes,
				StorageBenchmarkUnit.Bytes,
				"the shard-inclusive snapshot probe was skipped (--no-shards)"));
			measurements.Add(BenchmarkMeasurement.NotMeasured(
				StorageBenchmarkMetric.BackupShardFiles,
				StorageBenchmarkUnit.Count,
				"the shard-inclusive snapshot probe was skipped (--no-shards)"));
		}

		if (directoryToVerify is not null)
		{
			TryDeleteTree(directoryToVerify);
		}

		return measurements;
	}

	private static async Task<List<BenchmarkMeasurement>> VerifyAsync(
		BenchmarkStore store,
		DatabaseBackupService service,
		string? snapshotDirectory,
		BenchmarkSampleRecorder recorder,
		Action<string> log,
		CancellationToken cancellationToken)
	{
		if (snapshotDirectory is null)
		{
			return
			[
				BenchmarkMeasurement.NotMeasured(
					StorageBenchmarkMetric.BackupVerifySeconds,
					StorageBenchmarkUnit.Seconds,
					"no snapshot was produced, so there was nothing to verify"),
			];
		}

		string snapshotName = Path.GetFileName(snapshotDirectory);
		IReadOnlyList<string> knownMigrations = DatabaseSnapshotVerifier.ReadAppliedMigrations(store.DatabasePath, cancellationToken);

		BenchmarkSampleRun<VerifyRunResult> run = await recorder.MeasureAsync(
			StorageBenchmarkMetric.BackupVerifySeconds,
			StorageBenchmarkUnit.Seconds,
			async (_, token) =>
			{
				Stopwatch watch = Stopwatch.StartNew();
				DatabaseBackupVerificationDto dto = await service
					.VerifyAsync(snapshotName, knownMigrations, token)
					.ConfigureAwait(false);
				watch.Stop();

				if (dto.Status != IpcResultStatus.Success)
				{
					throw new InvalidOperationException(string.Format(
						CultureInfo.InvariantCulture,
						"the verification could not be performed: {0} {1}",
						dto.Status,
						dto.Message ?? string.Empty));
				}

				return new VerifyRunResult
				{
					Seconds = watch.Elapsed.TotalSeconds,
					Verdict = string.Format(
						CultureInfo.InvariantCulture,
						"{0} (usable={1}, quick_check={2})",
						dto.VerdictName,
						dto.IsUsable,
						dto.QuickCheckResult ?? "not reported"),
				};
			},
			static result => result.Seconds,
			note: "wall-clock stopwatch around the service call: the verification DTO carries no duration of its own",
			cancellationToken).ConfigureAwait(false);

		string verdict = run.Runs.Count > 0 ? run.Runs[0].Verdict : "not reached";
		log(string.Format(CultureInfo.InvariantCulture, "  verification: verdict {0}", verdict));

		BenchmarkMeasurement measurement = run.Measurement.State == MeasurementState.Measured
			? run.Measurement with { Note = run.Measurement.Note + "; verdict " + verdict }
			: run.Measurement;

		return [measurement];
	}

	private static async Task<List<BenchmarkMeasurement>> SnapshotWithShardsAsync(
		BenchmarkStore store,
		DatabaseBackupService service,
		BenchmarkWorkspace workspace,
		int shardFileCount,
		BenchmarkSampleRecorder recorder,
		Action<string> log,
		CancellationToken cancellationToken)
	{
		(int files, long bytes) = await Task.Run(
			() => CreateShardTree(workspace.ActionsRoot, shardFileCount),
			cancellationToken).ConfigureAwait(false);

		log(string.Format(
			CultureInfo.InvariantCulture,
			"  shard tree: {0} files, {1} bytes prepared under {2}",
			files,
			bytes,
			workspace.ActionsRoot));

		string? lastDirectory = null;
		BenchmarkSampleRun<SnapshotRunResult> run = await recorder.MeasureAsync(
			StorageBenchmarkMetric.BackupShardSnapshotSeconds,
			StorageBenchmarkUnit.Seconds,
			async (_, token) =>
			{
				SnapshotRunResult result = await CreateSnapshotAsync(service, store, includeShards: true, token).ConfigureAwait(false);
				if (lastDirectory is not null)
				{
					TryDeleteTree(lastDirectory);
				}

				lastDirectory = result.SnapshotDirectory;
				return result;
			},
			static result => result.Seconds,
			note: "the shard tree is copied file by file while shard writers would be appending, so the product documents this snapshot as best effort rather than transactional",
			cancellationToken).ConfigureAwait(false);

		List<BenchmarkMeasurement> measurements =
		[
			run.Measurement,
			Derive(run.Runs, StorageBenchmarkMetric.BackupShardBytes, StorageBenchmarkUnit.Bytes, static result => result.ShardBytes),
			Derive(run.Runs, StorageBenchmarkMetric.BackupShardFiles, StorageBenchmarkUnit.Count, static result => result.ShardFiles),
			Derive(run.Runs, StorageBenchmarkMetric.BackupShardSnapshotMebibytesPerSecond, StorageBenchmarkUnit.MebibytesPerSecond, static result => result.MebibytesPerSecond),
		];

		if (lastDirectory is not null)
		{
			TryDeleteTree(lastDirectory);
		}

		return measurements;
	}

	private static async Task<SnapshotRunResult> CreateSnapshotAsync(
		DatabaseBackupService service,
		BenchmarkStore store,
		bool includeShards,
		CancellationToken cancellationToken)
	{
		DatabaseBackupCreationDto dto = await service
			.CreateSnapshotAsync(store.DatabasePath, includeShards, DatabaseBackupKind.Manual, cancellationToken)
			.ConfigureAwait(false);

		if (dto.Status != IpcResultStatus.Success)
		{
			throw new InvalidOperationException(string.Format(
				CultureInfo.InvariantCulture,
				"the snapshot was refused: {0} {1}",
				dto.Status,
				dto.Message ?? string.Empty));
		}

		return new SnapshotRunResult
		{
			SnapshotName = dto.SnapshotName,
			SnapshotDirectory = dto.SnapshotDirectory,
			DatabaseBytes = dto.DatabaseBytes,
			Seconds = dto.DurationMs / 1000d,
			ShardFiles = dto.ShardFileCount,
			ShardBytes = dto.ShardBytes,
		};
	}

	/// <summary>
	/// Writes a synthetic shard tree using the product's own <see cref="ShardWriter"/> and
	/// <see cref="ShardPath"/>, so what the snapshot has to copy is a real shard tree in the production
	/// layout rather than files of the right length.
	/// </summary>
	private static (int Files, long Bytes) CreateShardTree(string actionsRoot, int fileCount)
	{
		long bytes = 0;
		int files = 0;
		Span<char> pathBuffer = stackalloc char[512];
		for (int index = 0; index < fileCount; index++)
		{
			IPAddress address = IPAddress.Parse(string.Format(
				CultureInfo.InvariantCulture,
				"10.{0}.{1}.{2}",
				index / 256 % 256,
				index % 256,
				(index % 251) + 1));

			if (!ShardPath.TryComposeShardPath(address, pathBuffer, out int written))
			{
				continue;
			}

			// The ingestion sink strips the leading "actions/" before combining with the configured root;
			// mirror that instead of re-deriving the layout here.
			string relative = new string(pathBuffer[..written]);
			string underActions = relative[(ShardPath.ActionsRootFolder.Length + 1)..]
				.Replace('/', Path.DirectorySeparatorChar);
			string fullPath = Path.Combine(actionsRoot, underActions);
			string? directory = Path.GetDirectoryName(fullPath);
			if (directory is null)
			{
				continue;
			}

			Directory.CreateDirectory(directory);
			using (ShardWriter writer = ShardWriter.OpenOrCreate(fullPath, ShardCapacityRecords))
			{
				for (int record = 0; record < ShardRecordsPerFile; record++)
				{
					writer.Append(
						ShardRecord.Create(
							sequence: (index * ShardRecordsPerFile) + record,
							timeUtcTicks: DateTime.UtcNow.Ticks,
							eventId: 4625,
							channelCode: 1,
							eventLayer: 1,
							sourceIpConfidence: 255,
							logonType: 3,
							subStatusLow: 0,
							statusHigh: 0,
							sessionId: -1,
							logonId: 0,
							userNameHeapOffset: -1,
							workstationNameHeapOffset: -1,
							processNameHeapOffset: -1,
							domainNameHeapOffset: -1,
							activityIdHeapOffset: -1,
							flags: 0),
						out bool _);
				}

				writer.Commit();
			}

			bytes += SqliteBenchmarkFacts.DatabaseFileBytes(fullPath);
			files++;
		}

		return (files, bytes);
	}

	private static BenchmarkMeasurement Derive(
		List<SnapshotRunResult> runs,
		string metric,
		string unit,
		Func<SnapshotRunResult, double> selector)
	{
		if (runs.Count == 0)
		{
			return BenchmarkMeasurement.NotMeasured(metric, unit, "no snapshot run completed");
		}

		List<double> values = new(runs.Count);
		foreach (SnapshotRunResult run in runs)
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

	/// <summary>Paths provider rooted at this run's directory, so no path the product resolves can land
	/// in the production data directory.</summary>
	private sealed class FixedPathsProvider : IRdpAuditPathsProvider
	{
		public FixedPathsProvider(string runDirectory)
		{
			Paths = new RdpAuditPaths(Path.Combine(runDirectory, "programdata"));
		}

		public RdpAuditPaths Paths { get; }
	}
}
