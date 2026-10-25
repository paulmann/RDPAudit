/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 2.0.0
// File   : DatabaseBackupService.cs
// Project: RdpAudit.Service (RdpAudit.Service.Services)
// Purpose: Consistent online snapshots of the live SQLite evidence store, without stopping the service.
//          A snapshot is the database copy plus a SHA-256 manifest describing what was copied, from
//          where, in which schema state and with which row counts, written into
//          Backups\<yyyyMMdd-HHmmss>\db\rdpaudit.db + manifest.json.
//
//          MECHANISM CHOICE - the SQLite online backup API (SqliteConnection.BackupDatabase over
//          sqlite3_backup_*), not VACUUM INTO:
//          1. Consistency under an active writer. sqlite3_backup_step copies pages inside a read
//             transaction on the source. If the live writer commits while the copy runs, SQLite
//             automatically restarts the copy from the beginning, so the artifact is always a
//             transactionally consistent image of one committed state - never a torn mix of two. That
//             restart-on-write behaviour is the property VACUUM INTO does not document and the reason
//             this file uses the backup API.
//          2. Committed WAL content is included. The backup reads through the write-ahead log, so Rows
//             acked to the writer but not yet checkpointed are in the snapshot; no checkpoint is forced
//             on the live database and no writer is paused.
//          3. Space and time. The destination needs room for the database image only (about the source
//             size), and the cost is one page copy - not a full defragmentation rewrite.
//          VACUUM INTO was rejected: it produces a defragmented rewrite (more I/O and more transient
//          space for the same recovery value), requires the destination file to not pre-exist, and it
//          gives no documented writer-restart guarantee. A full VACUUM on the live database is never
//          issued here - that is the behaviour this feature replaces, not one it performs.
//
//          After the copy the snapshot is normalised to journal_mode = DELETE so it is a self-contained
//          artifact that a read-only connection can verify, then hashed, counted and manifested. The
//          snapshot is assembled in a sibling <timestamp>.partial directory and only renamed to its
//          final name after the manifest is durable, so a snapshot directory that exists is a snapshot
//          that completed.
// Depends: AuditDbContext options, IOptionsMonitor<RdpAuditOptions>, IRdpAuditPathsProvider,
//          DatabaseBackupLayout, DatabaseBackupManifest, DatabaseSnapshotVerifier, IpcException
// Extends: Add a snapshot artifact by extending DatabaseBackupLayout and the manifest; add a
//          verification step in DatabaseSnapshotVerifier, not here.

using System.Diagnostics;
using System.Globalization;
using System.Reflection;
using Microsoft.Data.Sqlite;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using RdpAudit.Core.Backup;
using RdpAudit.Core.Config;
using RdpAudit.Core.Ipc.Contracts;
using RdpAudit.Core.Util;

namespace RdpAudit.Service.Services;

/// <summary>Lightweight snapshot inventory used by the Overview section and the pre-migration guard.</summary>
public sealed record DatabaseBackupStatus(
	bool Enabled,
	bool PreMigrationBackupEnabled,
	string BackupDirectory,
	int RetentionCopies,
	int SnapshotCount,
	DateTime? LastCreatedUtc,
	string? LastSnapshotDirectory,
	string? LastSnapshotSha256);

/// <summary>Creates, lists, verifies, restores and prunes database snapshots.</summary>
public sealed class DatabaseBackupService : IPreMigrationBackupProvider
{
	// ── Fields & DI ──────────────────────────────────────────────────────────────

	/// <summary>Bounded number of snapshots one inventory read will describe. The backup folder cannot
	/// grow past <c>RetentionCopies</c> under normal operation, so this is a runaway guard, not a
	/// paging mechanism.</summary>
	internal const int MaxSnapshotsListed = 1000;

	/// <summary>Bounded number of files one snapshot may contain before the inventory stops walking its
	/// directory. Keeps a pathological directory from turning a list into an unbounded enumeration.</summary>
	internal const int MaxSnapshotFilesScanned = 100_000;

	/// <summary>Hard ceiling on the shard files one snapshot may copy. Exceeding it fails the snapshot
	/// instead of writing a manifest that under-reports the shard tree.</summary>
	internal const long MaxShardFilesCopied = 500_000;

	/// <summary>A leftover <c>.partial</c> working directory older than this is removed by retention:
	/// it can only come from a snapshot that was interrupted before it was published.</summary>
	private static readonly TimeSpan StalePartialAge = TimeSpan.FromHours(1);

	private readonly IOptionsMonitor<RdpAuditOptions> _options;
	private readonly ILogger<DatabaseBackupService> _logger;
	private readonly IRdpAuditPathsProvider? _paths;

	// ── Construction ─────────────────────────────────────────────────────────────

	/// <summary>Creates the service over the live options monitor and the path layout.</summary>
	public DatabaseBackupService(
		IOptionsMonitor<RdpAuditOptions> options,
		ILogger<DatabaseBackupService> logger,
		IRdpAuditPathsProvider? paths = null)
	{
		ArgumentNullException.ThrowIfNull(options);
		ArgumentNullException.ThrowIfNull(logger);
		_options = options;
		_logger = logger;
		_paths = paths;
	}

	// ── IPreMigrationBackupProvider ──────────────────────────────────────────────

	/// <summary>True when the operator requires a snapshot before EF migrations are applied. This is
	/// governed by <c>BackupOptions.PreMigrationBackupEnabled</c> alone, not by
	/// <c>BackupOptions.Enabled</c>: protecting an upgrade is not the same opt-in as growing a backup
	/// folder on demand.</summary>
	public bool IsEnabled => CurrentBackupOptions().PreMigrationBackupEnabled;

	/// <summary>Absolute directory the pre-migration snapshot is expected in.</summary>
	public string ExpectedDirectory => ResolveBackupRoot(CurrentBackupOptions());

	/// <summary>
	/// Takes the mandatory pre-migration snapshot. Never throws: the initializer needs a describable
	/// failure so it can write a marker and refuse to migrate.
	/// </summary>
	public async Task<PreMigrationBackupResult> CreateAsync(string databasePath, CancellationToken cancellationToken)
	{
		string expectedDirectory = ExpectedDirectory;
		try
		{
			DatabaseBackupCreationDto creation = await CreateSnapshotAsync(
				databasePath,
				includeShards: false,
				DatabaseBackupKind.PreMigration,
				cancellationToken).ConfigureAwait(false);

			if (creation.Status != IpcResultStatus.Success)
			{
				return PreMigrationBackupResult.Failed(expectedDirectory, creation.Message ?? "The snapshot could not be taken.");
			}

			_logger.LogInformation(
				"Pre-migration database snapshot written to {SnapshotDirectory} ({Bytes} bytes, sha256={Sha256}).",
				creation.SnapshotDirectory,
				creation.DatabaseBytes,
				creation.DatabaseSha256);
			return PreMigrationBackupResult.Created(expectedDirectory, creation.SnapshotDirectory);
		}
		catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
		{
			throw;
		}
		catch (Exception ex)
		{
			_logger.LogError(ex, "Pre-migration database snapshot failed");
			return PreMigrationBackupResult.Failed(
				expectedDirectory,
				ex.GetType().Name + ": " + ex.Message);
		}
	}

	// ── Public API ───────────────────────────────────────────────────────────────

	/// <summary>
	/// Creates one consistent snapshot of <paramref name="databasePath"/> and applies the snapshot
	/// retention afterwards. A refused snapshot (no database yet, not enough free space, too many shard
	/// files) writes nothing and returns the reason.
	/// </summary>
	public async Task<DatabaseBackupCreationDto> CreateSnapshotAsync(
		string databasePath,
		bool includeShards,
		string kind,
		CancellationToken cancellationToken)
	{
		ArgumentException.ThrowIfNullOrWhiteSpace(databasePath);
		Stopwatch stopwatch = Stopwatch.StartNew();
		DateTime nowUtc = DateTime.UtcNow;
		BackupOptions backup = CurrentBackupOptions();
		string root = ResolveBackupRoot(backup);

		DatabaseBackupCreationDto dto = new()
		{
			Status = IpcResultStatus.Success,
			QueriedUtc = nowUtc,
			Kind = kind,
		};

		if (!File.Exists(databasePath))
		{
			return Refuse(
				dto,
				"There is no database file to snapshot yet at '" + databasePath + "'. Start the service once so it creates the store, then snapshot again.");
		}

		long databaseBytes = ReadFileSize(databasePath);
		long walBytes = ReadFileSize(databasePath + "-wal");
		long expectedBytes = Math.Max(0, databaseBytes) + Math.Max(0, walBytes);

		string actionsRoot = includeShards ? ResolveActionsRoot() : string.Empty;
		long shardEstimate = 0;
		if (includeShards && actionsRoot.Length > 0 && Directory.Exists(actionsRoot))
		{
			shardEstimate = MeasureDirectory(actionsRoot, cancellationToken);
		}

		string? spaceProblem = CheckFreeSpace(
			root,
			expectedBytes + shardEstimate,
			backup.ResolveMinFreeDiskBytesBeforeBackup());
		if (spaceProblem is not null)
		{
			return Refuse(dto, spaceProblem);
		}

		string timestamp;
		DatabaseSnapshotPaths paths;
		string partialDirectory;
		try
		{
			Directory.CreateDirectory(root);
			timestamp = DatabaseBackupLayout.ResolveUniqueTimestamp(
				EnumerateChildDirectoryNames(root),
				nowUtc.ToString(DatabaseBackupLayout.TimestampFormat, CultureInfo.InvariantCulture));
			paths = DatabaseBackupLayout.ForTimestamp(root, timestamp);
			partialDirectory = DatabaseBackupLayout.GetPartialDirectory(root, timestamp);
			RemoveDirectoryIfPresent(partialDirectory);
			Directory.CreateDirectory(Path.Combine(partialDirectory, DatabaseBackupLayout.DatabaseFolderName));
		}
		catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
		{
			throw;
		}
		catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidOperationException or ArgumentException)
		{
			return Refuse(
				dto,
				"The snapshot working directory under '" + root + "' could not be created: " + ex.GetType().Name + ": " + ex.Message);
		}

		dto.SnapshotName = timestamp;
		dto.SnapshotDirectory = paths.SnapshotDirectory;
		string partialDatabasePath = Path.Combine(
			partialDirectory,
			DatabaseBackupLayout.DatabaseFolderName,
			DatabaseBackupLayout.DatabaseFileName);

		try
		{
			int snapshotCountBefore = CountSnapshots(root);
			dto.SnapshotCountBefore = snapshotCountBefore;

			await CopyLiveDatabaseAsync(databasePath, partialDatabasePath, cancellationToken).ConfigureAwait(false);
			dto.DatabaseBytes = ReadFileSize(partialDatabasePath);
			dto.DatabaseSha256 = DatabaseSnapshotVerifier.ComputeSha256(partialDatabasePath, cancellationToken);

			Dictionary<string, long> rowCounts = DatabaseSnapshotVerifier.CountKeyTables(partialDatabasePath, cancellationToken);
			IReadOnlyList<string> appliedMigrations = DatabaseSnapshotVerifier.ReadAppliedMigrations(partialDatabasePath, cancellationToken);

			int shardFileCount = 0;
			long shardBytes = 0;
			if (includeShards && actionsRoot.Length > 0 && Directory.Exists(actionsRoot))
			{
				(shardFileCount, shardBytes) = await CopyShardTreeAsync(
					actionsRoot,
					Path.Combine(partialDirectory, DatabaseBackupLayout.ShardsFolderName),
					cancellationToken).ConfigureAwait(false);
			}

			DatabaseBackupManifest manifest = new()
			{
				Kind = kind,
				CreatedUtc = nowUtc,
				DatabasePath = Path.GetFullPath(databasePath),
				DatabaseBytes = dto.DatabaseBytes,
				DatabaseSha256 = dto.DatabaseSha256,
				LastAppliedMigration = appliedMigrations.Count > 0 ? appliedMigrations[^1] : null,
				AppliedMigrationCount = appliedMigrations.Count,
				ProductVersion = ResolveProductVersion(),
				ShardsIncluded = includeShards && shardFileCount > 0,
				ShardsDirectory = includeShards && shardFileCount > 0
					? Path.Combine(paths.SnapshotDirectory, DatabaseBackupLayout.ShardsFolderName)
					: null,
				ShardFileCount = shardFileCount,
				ShardBytes = shardBytes,
				RowCounts = rowCounts,
			};

			// The manifest is written last and atomically: its presence is what makes the directory a
			// snapshot, so a crash before this point leaves a .partial directory that is never listed.
			DatabaseBackupManifestCodec.WriteAtomic(
				Path.Combine(partialDirectory, DatabaseBackupLayout.ManifestFileName),
				manifest);

			dto.ShardsIncluded = manifest.ShardsIncluded;
			dto.ShardFileCount = shardFileCount;
			dto.ShardBytes = shardBytes;

			// Publish: same volume, so this rename is atomic and a snapshot directory that exists is
			// complete.
			Directory.Move(partialDirectory, paths.SnapshotDirectory);

			stopwatch.Stop();
			dto.DurationMs = stopwatch.ElapsedMilliseconds;

			(RetentionOutcome retention, int snapshotCountAfter) = await ApplyRetentionAsync(
				root,
				backup.ResolveRetentionCopies(),
				paths.SnapshotDirectory,
				cancellationToken).ConfigureAwait(false);
			dto.RetentionDeleted.AddRange(retention.Deleted);
			dto.RetentionSkipped.AddRange(retention.Skipped);
			dto.SnapshotCountAfter = snapshotCountAfter;

			dto.Message = string.Format(
				CultureInfo.InvariantCulture,
				"Snapshot '{0}' written to {1}: {2} bytes, sha256={3}, {4} applied migration(s), quick_check ok{5}; snapshots {6} -> {7}; retention removed {8} and kept {9} foreign snapshot(s).",
				timestamp,
				paths.SnapshotDirectory,
				dto.DatabaseBytes,
				dto.DatabaseSha256,
				manifest.AppliedMigrationCount,
				manifest.ShardsIncluded
					? ", " + shardFileCount.ToString(CultureInfo.InvariantCulture) + " shard file(s)"
					: string.Empty,
				dto.SnapshotCountBefore,
				dto.SnapshotCountAfter,
				retention.Deleted.Count,
				retention.Skipped.Count);

			_logger.LogInformation(
				"Database snapshot {Snapshot} written to {Directory} ({Bytes} bytes, kind={Kind}); {Deleted} older snapshot(s) removed by retention.",
				timestamp,
				paths.SnapshotDirectory,
				dto.DatabaseBytes,
				kind,
				retention.Deleted.Count);

			return dto;
		}
		catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
		{
			RemoveDirectoryIfPresent(partialDirectory);
			throw;
		}
		catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or SqliteException or InvalidOperationException)
		{
			RemoveDirectoryIfPresent(partialDirectory);
			string expected = ResolveVolumeFreeDescription(root);
			_logger.LogError(ex, "Database snapshot into {Directory} failed", root);
			return Refuse(
				dto,
				"The snapshot into '" + root + "' failed and nothing was published: " + ex.GetType().Name + ": " + ex.Message
					+ " Expected the snapshot at '" + paths.SnapshotDirectory + "'. Free space on the destination volume: " + expected + ".");
		}
	}

	/// <summary>Lists the database snapshots under the backup root, newest first.</summary>
	public Task<DatabaseBackupListDto> ListAsync(CancellationToken cancellationToken)
	{
		BackupOptions backup = CurrentBackupOptions();
		string root = ResolveBackupRoot(backup);
		DateTime nowUtc = DateTime.UtcNow;
		DatabaseBackupListDto dto = new()
		{
			Status = IpcResultStatus.Success,
			QueriedUtc = nowUtc,
			BackupDirectory = root,
			Enabled = backup.Enabled,
			PreMigrationBackupEnabled = backup.PreMigrationBackupEnabled,
			RetentionCopies = backup.ResolveRetentionCopies(),
		};

		try
		{
			if (!Directory.Exists(root))
			{
				dto.Message = "No database snapshots exist yet; the backup root '" + root + "' has not been created.";
				return Task.FromResult(dto);
			}

			List<string> names = [.. DatabaseBackupLayout.SortNewestFirst(EnumerateChildDirectoryNames(root))];
			if (names.Count > MaxSnapshotsListed)
			{
				dto.Truncated = true;
				names = names.GetRange(0, MaxSnapshotsListed);
			}

			foreach (string name in names)
			{
				cancellationToken.ThrowIfCancellationRequested();
				string directory = Path.Combine(root, name);
				if (!IsDatabaseSnapshotDirectory(directory))
				{
					dto.SkippedDirectoryCount++;
					continue;
				}

				dto.Entries.Add(DescribeSnapshot(directory, name, cancellationToken));
			}

			dto.TotalCount = dto.Entries.Count;
			dto.Message = string.Format(
				CultureInfo.InvariantCulture,
				"snapshots={0} retentionCopies={1} skippedForeignDirectories={2} truncated={3}",
				dto.TotalCount,
				dto.RetentionCopies,
				dto.SkippedDirectoryCount,
				dto.Truncated);
			return Task.FromResult(dto);
		}
		catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
		{
			throw;
		}
		catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
		{
			return Task.FromResult(new DatabaseBackupListDto
			{
				Status = IpcResultStatus.Unavailable,
				QueriedUtc = nowUtc,
				BackupDirectory = root,
				Enabled = backup.Enabled,
				PreMigrationBackupEnabled = backup.PreMigrationBackupEnabled,
				RetentionCopies = backup.ResolveRetentionCopies(),
				Message = "The backup root '" + root + "' could not be read: " + ex.GetType().Name + ": " + ex.Message,
			});
		}
	}

	/// <summary>
	/// Verifies one snapshot, or the newest one when <paramref name="snapshotName"/> is null. Read-only:
	/// nothing under the snapshot is written, moved or deleted.
	/// </summary>
	/// <param name="snapshotName">Snapshot directory name; null or empty selects the newest.</param>
	/// <param name="knownMigrations">Migrations of the running binaries, used for the downgrade check.
	/// Null skips that check (integrity-only verification).</param>
	/// <param name="cancellationToken">Cancellation token.</param>
	public Task<DatabaseBackupVerificationDto> VerifyAsync(
		string? snapshotName,
		IReadOnlyList<string>? knownMigrations,
		CancellationToken cancellationToken)
	{
		BackupOptions backup = CurrentBackupOptions();
		string root = ResolveBackupRoot(backup);
		string? directory = ResolveSnapshotDirectory(root, snapshotName);
		if (directory is null)
		{
			return Task.FromResult(new DatabaseBackupVerificationDto
			{
				Status = IpcResultStatus.NotFound,
				QueriedUtc = DateTime.UtcNow,
				SnapshotName = snapshotName ?? string.Empty,
				Message = string.IsNullOrWhiteSpace(snapshotName)
					? "There is no database snapshot to verify under '" + root + "'."
					: "No database snapshot named '" + snapshotName + "' exists under '" + root + "'.",
			});
		}

		DatabaseSnapshotVerification verification = DatabaseSnapshotVerifier.Verify(directory, knownMigrations, cancellationToken);
		return Task.FromResult(ToDto(verification));
	}

	/// <summary>
	/// Restores a snapshot into a scratch directory. The snapshot is verified before a byte is written;
	/// a snapshot that does not verify is refused and the target is left untouched. The copy is written
	/// to a temporary name and moved into place, so a half-written target file is never visible under
	/// the final name.
	/// </summary>
	public async Task<DatabaseBackupRestoreReportDto> RestoreToDirectoryAsync(
		string snapshotName,
		string targetDirectory,
		IReadOnlyList<string>? knownMigrations,
		CancellationToken cancellationToken)
	{
		ArgumentException.ThrowIfNullOrWhiteSpace(snapshotName);
		ArgumentException.ThrowIfNullOrWhiteSpace(targetDirectory);

		DateTime nowUtc = DateTime.UtcNow;
		string root = ResolveBackupRoot(CurrentBackupOptions());
		string? directory = ResolveSnapshotDirectory(root, snapshotName);
		DatabaseBackupRestoreReportDto report = new()
		{
			Status = IpcResultStatus.Refused,
			QueriedUtc = nowUtc,
			SnapshotName = snapshotName,
			TargetDirectory = targetDirectory,
		};

		if (directory is null)
		{
			report.Message = "No database snapshot named '" + snapshotName + "' exists under '" + root + "'.";
			return report;
		}

		DatabaseSnapshotVerification verification = DatabaseSnapshotVerifier.Verify(directory, knownMigrations, cancellationToken);
		report.Verification = ToDto(verification);
		if (!verification.IsUsable || verification.DatabasePath is null)
		{
			report.Message = "The restore was refused: the snapshot did not pass verification. " + verification.Message;
			return report;
		}

		string target = Path.GetFullPath(targetDirectory);
		string targetDatabasePath = Path.Combine(target, DatabaseBackupLayout.DatabaseFileName);
		string stagingPath = targetDatabasePath + ".restoring";
		try
		{
			Directory.CreateDirectory(target);
			await CopyFileAsync(verification.DatabasePath, stagingPath, cancellationToken).ConfigureAwait(false);
			File.Move(stagingPath, targetDatabasePath, overwrite: true);
			report.TargetDatabasePath = targetDatabasePath;
			report.DatabaseBytesCopied = ReadFileSize(targetDatabasePath);

			DatabaseBackupManifest? manifest = verification.Manifest;
			if (manifest is { ShardsIncluded: true, ShardFileCount: > 0 })
			{
				string snapshotShards = Path.Combine(directory, DatabaseBackupLayout.ShardsFolderName);
				if (Directory.Exists(snapshotShards))
				{
					(int files, long bytes) = await CopyShardTreeAsync(
						snapshotShards,
						Path.Combine(target, DatabaseBackupLayout.ShardsFolderName),
						cancellationToken).ConfigureAwait(false);
					report.ShardsRestored = files > 0;
					report.ShardFilesRestored = files;
					report.ShardBytesRestored = bytes;
				}
			}

			report.Status = IpcResultStatus.Success;
			report.Message = string.Format(
				CultureInfo.InvariantCulture,
				"Restored snapshot '{0}' into {1} ({2} bytes){3}. The live store was not touched; point the service at the restored copy to use it.",
				snapshotName,
				targetDatabasePath,
				report.DatabaseBytesCopied,
				report.ShardsRestored
					? " plus " + report.ShardFilesRestored.ToString(CultureInfo.InvariantCulture) + " shard file(s)"
					: string.Empty);
			return report;
		}
		catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
		{
			TryDeleteFile(stagingPath);
			throw;
		}
		catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException)
		{
			TryDeleteFile(stagingPath);
			report.Message = "The restore into '" + target + "' failed: " + ex.GetType().Name + ": " + ex.Message;
			return report;
		}
	}

	/// <summary>
	/// Light inventory for the Overview section and the pre-migration guard: how many database
	/// snapshots exist, which is newest, and the effective backup switches. Synchronous by design - it
	/// is a bounded directory read, not an I/O wait - so callers can use it inside a section body
	/// without pretending it is asynchronous work.
	/// </summary>
	public DatabaseBackupStatus GetStatus(CancellationToken cancellationToken)
	{
		BackupOptions backup = CurrentBackupOptions();
		string root = ResolveBackupRoot(backup);
		int count = 0;
		DateTime? lastCreatedUtc = null;
		string? lastDirectory = null;
		string? lastSha256 = null;
		try
		{
			List<string> names = [.. DatabaseBackupLayout.SortNewestFirst(EnumerateChildDirectoryNames(root))];
			foreach (string name in names)
			{
				cancellationToken.ThrowIfCancellationRequested();
				string directory = Path.Combine(root, name);
				if (!IsDatabaseSnapshotDirectory(directory))
				{
					continue;
				}

				count++;
				if (lastDirectory is not null)
				{
					continue;
				}

				lastDirectory = directory;
				if (DatabaseBackupManifestCodec.TryRead(
					Path.Combine(directory, DatabaseBackupLayout.ManifestFileName),
					out DatabaseBackupManifest? manifest,
					out _)
					&& manifest is not null)
				{
					lastCreatedUtc = manifest.CreatedUtc;
					lastSha256 = manifest.DatabaseSha256;
				}
				else if (DatabaseBackupLayout.TryParseTimestamp(name, out DateTime parsedUtc, out _))
				{
					lastCreatedUtc = parsedUtc;
				}
			}
		}
		catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
		{
			throw;
		}
		catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
		{
			_logger.LogWarning(ex, "Database snapshot inventory under {Directory} could not be read", root);
		}

		return new DatabaseBackupStatus(
			Enabled: backup.Enabled,
			PreMigrationBackupEnabled: backup.PreMigrationBackupEnabled,
			BackupDirectory: root,
			RetentionCopies: backup.ResolveRetentionCopies(),
			SnapshotCount: count,
			LastCreatedUtc: lastCreatedUtc,
			LastSnapshotDirectory: lastDirectory,
			LastSnapshotSha256: lastSha256);
	}

	// ── The live copy ────────────────────────────────────────────────────────────

	/// <summary>
	/// Copies the live database into <paramref name="destinationPath"/> with the SQLite online backup
	/// API. The source connection is opened read-write with a private cache: read-write because a
	/// write-ahead log may need recovery before it can be read at all, and a private cache so the
	/// backup never joins or perturbs the shared cache the service's own connections use.
	///
	/// Pooling is disabled on both connections on purpose. Microsoft.Data.Sqlite returns a closed
	/// connection to a pool while keeping the underlying file handle open, which would leave the freshly
	/// written snapshot locked and make publishing it (a directory rename inside the backup root) fail
	/// with "the file is being used by another process". A snapshot is a cold, one-shot operation, so the
	/// cost of a fresh handle is irrelevant against a guaranteed release of the destination file.
	///
	/// The page copy itself is a single native call and is therefore not cancellable mid-flight -
	/// SQLite exposes no progress callback through Microsoft.Data.Sqlite - but the token is honoured at
	/// every boundary around it and before the artifact is published, and the caller is a background
	/// worker or an IPC thread, never a UI thread.
	/// </summary>
	private static async Task CopyLiveDatabaseAsync(string sourcePath, string destinationPath, CancellationToken cancellationToken)
	{
		cancellationToken.ThrowIfCancellationRequested();
		await using SqliteConnection source = new(new SqliteConnectionStringBuilder
		{
			DataSource = Path.GetFullPath(sourcePath),
			Mode = SqliteOpenMode.ReadWrite,
			Cache = SqliteCacheMode.Private,
			Pooling = false,
		}.ToString());
		await source.OpenAsync(cancellationToken).ConfigureAwait(false);

		await using SqliteConnection destination = new(new SqliteConnectionStringBuilder
		{
			DataSource = Path.GetFullPath(destinationPath),
			Mode = SqliteOpenMode.ReadWriteCreate,
			Cache = SqliteCacheMode.Private,
			Pooling = false,
		}.ToString());
		await destination.OpenAsync(cancellationToken).ConfigureAwait(false);

		// The single consistent copy. sqlite3_backup_step restarts the copy if the live writer commits
		// while it runs, which is what makes the artifact one committed state rather than a mixture.
		source.BackupDatabase(destination);

		// Normalise the copy to a single self-contained file. sqlite3_backup copies page 1 verbatim,
		// which carries the source's WAL header, so without this the artifact would advertise WAL mode
		// while having no -wal file: readable by this process, but not openable read-only by the
		// verifier or by any other tool. journal_mode = DELETE makes the snapshot a plain, complete,
		// read-only-openable database.
		await using (SqliteCommand normalise = destination.CreateCommand())
		{
			normalise.CommandText = "PRAGMA journal_mode = DELETE;";
			await normalise.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
		}

		await destination.CloseAsync().ConfigureAwait(false);
		await source.CloseAsync().ConfigureAwait(false);

		string quickCheck = DatabaseSnapshotVerifier.RunQuickCheck(destinationPath, cancellationToken);
		if (!string.Equals(quickCheck, "ok", StringComparison.OrdinalIgnoreCase))
		{
			throw new InvalidOperationException(
				"The database copy did not pass PRAGMA quick_check (" + quickCheck + "), so it was discarded instead of published.");
		}

		cancellationToken.ThrowIfCancellationRequested();
	}

	// ── Retention ────────────────────────────────────────────────────────────────

	/// <summary>What a retention pass did, for the report and the operation log.</summary>
	private readonly record struct RetentionOutcome(List<string> Deleted, List<string> Skipped);

	/// <summary>
	/// Enforces <c>RetentionCopies</c> over the database snapshots only. A directory is eligible for
	/// removal only when it is a database snapshot: its name is a snapshot timestamp, it carries a
	/// readable database manifest, and it does not carry the settings scope (metadata.json /
	/// appsettings.json). Settings, shadow-policy and any other snapshot, plus every
	/// <c>rdpaudit.db.*.bak</c> file, are outside the reach of this pass by construction - it only ever
	/// removes directories from the eligible list. Stale <c>.partial</c> working directories are removed
	/// as well, because they can only come from a snapshot that was interrupted before it was published.
	/// </summary>
	private Task<(RetentionOutcome Outcome, int SnapshotCount)> ApplyRetentionAsync(
		string root,
		int keepCopies,
		string justCreatedDirectory,
		CancellationToken cancellationToken)
	{
		RetentionOutcome outcome = new([], []);
		int kept = 0;
		int remaining = 0;
		try
		{
			foreach (string name in DatabaseBackupLayout.SortNewestFirst(EnumerateChildDirectoryNames(root)))
			{
				cancellationToken.ThrowIfCancellationRequested();
				string directory = Path.Combine(root, name);
				if (!IsDatabaseSnapshotDirectory(directory))
				{
					continue;
				}

				remaining++;
				bool isNewest = string.Equals(directory, justCreatedDirectory, StringComparison.OrdinalIgnoreCase);
				if (isNewest || kept < keepCopies)
				{
					kept++;
					continue;
				}

				string? protectedReason = ProtectedSnapshotReason(directory);
				if (protectedReason is not null)
				{
					outcome.Skipped.Add(name + " (" + protectedReason + ")");
					kept++;
					continue;
				}

				try
				{
					Directory.Delete(directory, recursive: true);
					outcome.Deleted.Add(name);
					remaining--;
				}
				catch (IOException ex)
				{
					outcome.Skipped.Add(name + " (could not be removed: " + ex.Message + ")");
					kept++;
				}
				catch (UnauthorizedAccessException ex)
				{
					outcome.Skipped.Add(name + " (could not be removed: " + ex.Message + ")");
					kept++;
				}
			}

			RemoveStalePartialDirectories(root, outcome, cancellationToken);
		}
		catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
		{
			throw;
		}
		catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
		{
			// Retention is a housekeeping step: it must never turn a written, verified snapshot into a
			// reported failure.
			_logger.LogWarning(ex, "Database snapshot retention under {Directory} could not complete", root);
			outcome.Skipped.Add("retention could not complete: " + ex.Message);
		}

		return Task.FromResult((outcome, remaining));
	}

	private void RemoveStalePartialDirectories(string root, RetentionOutcome outcome, CancellationToken cancellationToken)
	{
		DateTime cutoffUtc = DateTime.UtcNow - StalePartialAge;
		foreach (string candidate in EnumerateChildDirectoryNames(root))
		{
			cancellationToken.ThrowIfCancellationRequested();
			if (!DatabaseBackupLayout.IsPartialDirectoryName(candidate))
			{
				continue;
			}

			string directory = Path.Combine(root, candidate);
			try
			{
				DirectoryInfo info = new(directory);
				if (info.LastWriteTimeUtc > cutoffUtc)
				{
					continue;
				}

				Directory.Delete(directory, recursive: true);
				outcome.Skipped.Add(candidate + " (incomplete snapshot working directory removed)");
			}
			catch (IOException ex)
			{
				outcome.Skipped.Add(candidate + " (incomplete snapshot working directory kept: " + ex.Message + ")");
			}
			catch (UnauthorizedAccessException ex)
			{
				outcome.Skipped.Add(candidate + " (incomplete snapshot working directory kept: " + ex.Message + ")");
			}
		}
	}

	/// <summary>
	/// Why this database snapshot must not be deleted by database retention. A snapshot that also
	/// carries the settings scope belongs to the settings feature, which owns its own lifecycle; the
	/// database retention leaves it alone and says so instead of deleting it.
	/// </summary>
	private static string? ProtectedSnapshotReason(string directory)
	{
		if (File.Exists(Path.Combine(directory, BackupLayout.MetadataFileName)))
		{
			return "also contains settings metadata.json; the settings backup owns it";
		}

		if (File.Exists(Path.Combine(directory, BackupLayout.AppSettingsFileName)))
		{
			return "also contains appsettings.json; the settings backup owns it";
		}

		return null;
	}

	// ── Inventory helpers ────────────────────────────────────────────────────────

	/// <summary>
	/// True when a directory is a database snapshot: it carries a readable database manifest, or a
	/// db\rdpaudit.db copy. A directory that only carries the settings scope is not one.
	/// </summary>
	private static bool IsDatabaseSnapshotDirectory(string directory)
	{
		try
		{
			if (DatabaseBackupLayout.IsPartialDirectoryName(Path.GetFileName(directory)))
			{
				// A working directory that was never published carries no manifest or only a partial one.
				return false;
			}

			if (DatabaseBackupManifestCodec.TryRead(
				Path.Combine(directory, DatabaseBackupLayout.ManifestFileName),
				out DatabaseBackupManifest? manifest,
				out _)
				&& manifest is not null)
			{
				return true;
			}

			return File.Exists(Path.Combine(
				directory,
				DatabaseBackupLayout.DatabaseFolderName,
				DatabaseBackupLayout.DatabaseFileName));
		}
		catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
		{
			return false;
		}
	}

	private DatabaseBackupEntryDto DescribeSnapshot(string directory, string name, CancellationToken cancellationToken)
	{
		DatabaseBackupEntryDto entry = new()
		{
			Name = name,
			Directory = directory,
			DatabaseBytes = -1,
			SnapshotBytes = -1,
		};

		string databasePath = Path.Combine(
			directory,
			DatabaseBackupLayout.DatabaseFolderName,
			DatabaseBackupLayout.DatabaseFileName);
		if (File.Exists(databasePath))
		{
			entry.DatabaseBytes = ReadFileSize(databasePath);
		}

		if (DatabaseBackupManifestCodec.TryRead(
			Path.Combine(directory, DatabaseBackupLayout.ManifestFileName),
			out DatabaseBackupManifest? manifest,
			out string? manifestError)
			&& manifest is not null)
		{
			entry.ManifestValid = true;
			entry.CreatedUtc = manifest.CreatedUtc;
			entry.DatabaseSha256 = manifest.DatabaseSha256;
			entry.LastAppliedMigration = manifest.LastAppliedMigration;
			entry.AppliedMigrationCount = manifest.AppliedMigrationCount;
			entry.Kind = manifest.Kind;
			entry.ShardsIncluded = manifest.ShardsIncluded;
			entry.ShardFileCount = manifest.ShardFileCount;
			entry.ShardBytes = manifest.ShardBytes;
			entry.ProductVersion = manifest.ProductVersion;
			foreach (KeyValuePair<string, long> row in manifest.RowCounts)
			{
				entry.RowCounts[row.Key] = row.Value;
			}
		}
		else
		{
			entry.ManifestValid = false;
			entry.ManifestError = manifestError;
			if (DatabaseBackupLayout.TryParseTimestamp(name, out DateTime parsedUtc, out _))
			{
				entry.CreatedUtc = parsedUtc;
			}
		}

		entry.SnapshotBytes = MeasureDirectory(directory, cancellationToken);
		return entry;
	}

	private static DatabaseBackupVerificationDto ToDto(DatabaseSnapshotVerification verification)
		=> new()
		{
			Status = IpcResultStatus.Success,
			QueriedUtc = DateTime.UtcNow,
			SnapshotName = Path.GetFileName(verification.SnapshotDirectory.TrimEnd(Path.DirectorySeparatorChar)),
			SnapshotDirectory = verification.SnapshotDirectory,
			Verdict = verification.Verdict,
			VerdictName = verification.Verdict.ToString(),
			IsUsable = verification.IsUsable,
			ExpectedSha256 = verification.ExpectedSha256,
			ActualSha256 = verification.ActualSha256,
			QuickCheckResult = verification.QuickCheckResult,
			SchemaVerdict = verification.Schema?.Verdict,
			SchemaMessage = verification.Schema?.Message,
			Message = verification.Message,
		};

	/// <summary>Resolves the directory of a named snapshot, or of the newest one when no name is given.
	/// A name that is not a snapshot timestamp resolves to nothing, so a request can never address a
	/// directory outside the backup root.</summary>
	private static string? ResolveSnapshotDirectory(string root, string? snapshotName)
	{
		if (!Directory.Exists(root))
		{
			return null;
		}

		IReadOnlyList<string> names = DatabaseBackupLayout.SortNewestFirst(EnumerateChildDirectoryNames(root));
		if (!string.IsNullOrWhiteSpace(snapshotName))
		{
			string requested = snapshotName.Trim();
			foreach (string name in names)
			{
				if (string.Equals(name, requested, StringComparison.OrdinalIgnoreCase))
				{
					string candidate = Path.Combine(root, name);
					return IsDatabaseSnapshotDirectory(candidate) ? candidate : null;
				}
			}

			return null;
		}

		foreach (string name in names)
		{
			string candidate = Path.Combine(root, name);
			if (IsDatabaseSnapshotDirectory(candidate))
			{
				return candidate;
			}
		}

		return null;
	}

	/// <summary>Number of database snapshots currently present under the backup root. Directories of
	/// other scopes and abandoned working directories are not snapshots and are not counted.</summary>
	private int CountSnapshots(string root)
	{
		int count = 0;
		foreach (string name in DatabaseBackupLayout.SortNewestFirst(EnumerateChildDirectoryNames(root)))
		{
			if (IsDatabaseSnapshotDirectory(Path.Combine(root, name)))
			{
				count++;
			}
		}

		return count;
	}

	private static IEnumerable<string> EnumerateChildDirectoryNames(string root)
	{
		if (!Directory.Exists(root))
		{
			return Array.Empty<string>();
		}

		List<string> names = [];
		EnumerationOptions options = new()
		{
			RecurseSubdirectories = false,
			IgnoreInaccessible = true,
			AttributesToSkip = FileAttributes.ReparsePoint,
		};
		foreach (string path in Directory.EnumerateDirectories(root, "*", options))
		{
			names.Add(Path.GetFileName(path));
		}

		return names;
	}

	// ── Copying and measuring ────────────────────────────────────────────────────

	/// <summary>
	/// Copies the shard tree. This is a best-effort file copy, not a transactional snapshot: shards are
	/// appended by the live service while the copy runs, so a shard written during the copy may be
	/// captured truncated. The database copy in the same snapshot is transactionally consistent, and the
	/// documentation says a restored pair may need the shard tree re-checked. Reparse points are
	/// skipped, so a junction cannot pull data from outside the tree, and exceeding
	/// <see cref="MaxShardFilesCopied"/> fails the snapshot instead of under-reporting it.
	/// </summary>
	private static async Task<(int Files, long Bytes)> CopyShardTreeAsync(
		string sourceRoot,
		string targetRoot,
		CancellationToken cancellationToken)
	{
		int files = 0;
		long bytes = 0;
		EnumerationOptions options = new()
		{
			RecurseSubdirectories = true,
			IgnoreInaccessible = true,
			AttributesToSkip = FileAttributes.ReparsePoint,
		};

		foreach (string source in Directory.EnumerateFiles(sourceRoot, "*", options))
		{
			cancellationToken.ThrowIfCancellationRequested();
			if (files >= MaxShardFilesCopied)
			{
				throw new InvalidOperationException(
					"The shard tree holds more than " + MaxShardFilesCopied.ToString(CultureInfo.InvariantCulture)
						+ " files; refusing to write a snapshot whose manifest would under-report the shard tree.");
			}

			string relative = Path.GetRelativePath(sourceRoot, source);
			string target = Path.Combine(targetRoot, relative);
			string? targetDirectory = Path.GetDirectoryName(target);
			if (!string.IsNullOrEmpty(targetDirectory))
			{
				Directory.CreateDirectory(targetDirectory);
			}

			await CopyFileAsync(source, target, cancellationToken).ConfigureAwait(false);
			files++;
			bytes += ReadFileSize(target);
		}

		return (files, bytes);
	}

	/// <summary>Streamed copy of one file. Genuinely asynchronous and cancellable between chunks, so a
	/// multi-gigabyte shard copy does not pin a thread for its whole duration.</summary>
	private static async Task CopyFileAsync(string source, string target, CancellationToken cancellationToken)
	{
		await using FileStream input = new(source, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete, 1024 * 1024, FileOptions.Asynchronous | FileOptions.SequentialScan);
		await using FileStream output = new(target, FileMode.Create, FileAccess.Write, FileShare.None, 1024 * 1024, FileOptions.Asynchronous);
		await input.CopyToAsync(output, 1024 * 1024, cancellationToken).ConfigureAwait(false);
	}

	private static long MeasureDirectory(string directory, CancellationToken cancellationToken)
	{
		long total = 0;
		int scanned = 0;
		EnumerationOptions options = new()
		{
			RecurseSubdirectories = true,
			IgnoreInaccessible = true,
			AttributesToSkip = FileAttributes.ReparsePoint,
		};
		try
		{
			foreach (string file in Directory.EnumerateFiles(directory, "*", options))
			{
				cancellationToken.ThrowIfCancellationRequested();
				if (++scanned > MaxSnapshotFilesScanned)
				{
					return total;
				}

				total += ReadFileSize(file);
			}
		}
		catch (IOException)
		{
			return -1;
		}
		catch (UnauthorizedAccessException)
		{
			return -1;
		}

		return total;
	}

	// ── Free space ───────────────────────────────────────────────────────────────

	/// <summary>
	/// Early refusal when the destination volume cannot hold the snapshot plus the configured floor.
	/// The check runs before a byte is written, because failing halfway through a multi-gigabyte copy
	/// leaves the operator with a slow failure and a full disk instead of a clear message.
	/// </summary>
	private static string? CheckFreeSpace(string destinationRoot, long requiredBytes, long floorBytes)
	{
		long? free = ResolveVolumeFreeBytes(destinationRoot);
		if (free is null)
		{
			// The volume could not be inspected. Reporting "not enough space" would be a guess; the copy
			// itself will fail with a real error if the disk is full, so proceed.
			return null;
		}

		// Saturating addition: a hand-edited MinFreeDiskBytesBeforeBackup of long.MaxValue must refuse the
		// snapshot, not wrap around into a negative requirement that silently disables the check.
		long needed = requiredBytes > long.MaxValue - floorBytes
			? long.MaxValue
			: requiredBytes + floorBytes;
		if (free.Value >= needed)
		{
			return null;
		}

		return string.Format(
			CultureInfo.InvariantCulture,
			"Refusing to snapshot: the destination volume of '{0}' has {1} bytes free but the snapshot needs about {2} bytes{3}. Free disk space, lower Backup.MinFreeDiskBytesBeforeBackup, or point Backup.BackupDirectory at another volume.",
			destinationRoot,
			free.Value,
			needed,
			floorBytes > 0
				? " (" + requiredBytes.ToString(CultureInfo.InvariantCulture) + " bytes of data plus a "
					+ floorBytes.ToString(CultureInfo.InvariantCulture) + "-byte floor)"
				: string.Empty);
	}

	private static long? ResolveVolumeFreeBytes(string path)
	{
		try
		{
			string candidate = Path.GetFullPath(path);
			while (!string.IsNullOrEmpty(candidate) && !Directory.Exists(candidate))
			{
				string? parent = Path.GetDirectoryName(candidate);
				if (string.IsNullOrEmpty(parent) || string.Equals(parent, candidate, StringComparison.OrdinalIgnoreCase))
				{
					break;
				}

				candidate = parent;
			}

			string? root = Path.GetPathRoot(candidate);
			if (string.IsNullOrEmpty(root))
			{
				return null;
			}

			DriveInfo drive = new(root);
			return drive.IsReady ? drive.AvailableFreeSpace : null;
		}
		catch (IOException)
		{
			return null;
		}
		catch (UnauthorizedAccessException)
		{
			return null;
		}
		catch (ArgumentException)
		{
			return null;
		}
	}

	private static string ResolveVolumeFreeDescription(string path)
	{
		long? free = ResolveVolumeFreeBytes(path);
		return free is null
			? "(could not be measured)"
			: free.Value.ToString(CultureInfo.InvariantCulture) + " bytes";
	}

	// ── Error Handling & Retry ───────────────────────────────────────────────────

	/// <summary>Marks a result as refused and records the reason, so a client cannot read a failure as
	/// a success with zero bytes copied.</summary>
	private static DatabaseBackupCreationDto Refuse(DatabaseBackupCreationDto dto, string reason)
	{
		dto.Status = IpcResultStatus.Refused;
		dto.Message = reason;
		return dto;
	}

	private BackupOptions CurrentBackupOptions() => _options.CurrentValue.Storage.Backup;

	private string ResolveBackupRoot(BackupOptions backup)
		=> Path.GetFullPath(backup.ResolveBackupDirectory(ProgramDataDirectory));

	private string ResolveActionsRoot()
		=> Path.GetFullPath(_options.CurrentValue.Sharding.ResolveActionsRoot());

	private string ProgramDataDirectory
		=> (_paths?.Paths ?? RdpAuditPaths.Default).ProgramDataDirectory;

	/// <summary>Assembly informational version, or the assembly version when it is absent.</summary>
	private static string? ResolveProductVersion()
	{
		try
		{
			Assembly assembly = typeof(DatabaseBackupService).Assembly;
			return assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion
				?? assembly.GetName().Version?.ToString();
		}
		catch (Exception ex) when (ex is InvalidOperationException or NotSupportedException)
		{
			return null;
		}
	}

	/// <summary>Reads a file size; a missing or unreadable file is zero rather than an exception, because
	/// the WAL sidecar is legitimately absent on an idle database.</summary>
	private static long ReadFileSize(string path)
	{
		try
		{
			FileInfo info = new(path);
			return info.Exists ? info.Length : 0L;
		}
		catch (IOException)
		{
			return 0L;
		}
		catch (UnauthorizedAccessException)
		{
			return 0L;
		}
		catch (ArgumentException)
		{
			return 0L;
		}
	}

	private static void RemoveDirectoryIfPresent(string directory)
	{
		try
		{
			if (Directory.Exists(directory))
			{
				Directory.Delete(directory, recursive: true);
			}
		}
		catch (IOException)
		{
			// Best effort: a leftover .partial directory is inert (never listed, never restored) and the
			// next snapshot into the same second removes it.
		}
		catch (UnauthorizedAccessException)
		{
		}
	}

	private static void TryDeleteFile(string path)
	{
		try
		{
			if (File.Exists(path))
			{
				File.Delete(path);
			}
		}
		catch (IOException)
		{
		}
		catch (UnauthorizedAccessException)
		{
		}
	}
}
