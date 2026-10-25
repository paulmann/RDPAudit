/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 2.0.0
// File   : DatabaseBackupServiceTests.cs
// Project: RdpAudit.Service.Tests (RdpAudit.Service.Tests)
// Purpose: Exercises the database snapshot engine against a real SQLite file in WAL mode, including a
//          snapshot taken while a writer is committing rows. The central claim being tested is the one
//          the whole feature rests on: the artifact is a transactionally consistent copy of one
//          committed state (it passes PRAGMA quick_check, it is self-contained, its manifest records the
//          schema state of the source, and its row count lies between the counts observed before and
//          after the copy). Around that, the tests cover the failure modes an operator meets: a flipped
//          byte in the artifact, a manifest that no longer parses, retention that must touch only the
//          snapshots this feature owns, a restore into a scratch directory, and the shard-tree copy.
// Depends: DatabaseBackupService, DatabaseSnapshotVerifier, AuditDbContext, xUnit
// Extends: Add a scenario here whenever the snapshot engine gains a step that can fail.

using System.Text;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using RdpAudit.Core.Backup;
using RdpAudit.Core.Config;
using RdpAudit.Core.Data;
using RdpAudit.Core.Ipc.Contracts;
using RdpAudit.Core.Models;
using RdpAudit.Core.Util;
using RdpAudit.Service.Services;
using Xunit;

namespace RdpAudit.Service.Tests;

public sealed class DatabaseBackupServiceTests : IDisposable
{
	// ── Fields & DI ──────────────────────────────────────────────────────────────

	private readonly string _root;
	private readonly string _backupRoot;
	private readonly string _databasePath;
	private readonly RdpAuditOptions _options;
	private readonly DbContextOptions<AuditDbContext> _dbOptions;
	private readonly DatabaseBackupService _service;

	public DatabaseBackupServiceTests()
	{
		_root = Path.Combine(Path.GetTempPath(), "rdpaudit-snapshot-" + Guid.NewGuid().ToString("N"));
		_backupRoot = Path.Combine(_root, "Backups");
		string storeDirectory = Path.Combine(_root, "store");
		Directory.CreateDirectory(storeDirectory);
		_databasePath = Path.Combine(storeDirectory, "rdpaudit.db");

		_dbOptions = new DbContextOptionsBuilder<AuditDbContext>()
			.UseSqlite($"Data Source={_databasePath};Cache=Shared")
			.AddInterceptors(new SqlitePragmaInterceptor())
			.Options;

		_options = new RdpAuditOptions();
		_options.Storage.DatabasePath = _databasePath;
		_options.Storage.Backup.Enabled = true;
		_options.Storage.Backup.BackupDirectory = _backupRoot;
		_options.Storage.Backup.RetentionCopies = 5;

		_service = new DatabaseBackupService(
			new StubOptionsMonitor(_options),
			NullLogger<DatabaseBackupService>.Instance,
			new FakePathsProvider(new RdpAuditPaths(_root)));
	}

	public void Dispose()
	{
		try
		{
			SqliteConnection.ClearAllPools();
			if (Directory.Exists(_root))
			{
				Directory.Delete(_root, recursive: true);
			}
		}
		catch (IOException)
		{
			// A leftover temp directory is not a test failure.
		}
		catch (UnauthorizedAccessException)
		{
		}
	}

	// ── Snapshot of a live database ──────────────────────────────────────────────

	/// <summary>
	/// Given a WAL database that a writer is actively appending to, when a snapshot is taken, then the
	/// artifact is a consistent, self-contained copy of one committed state: quick_check reports ok, the
	/// copy stands alone without a WAL sidecar, the manifest carries the source's schema state, and the
	/// copied row count lies between the counts observed before and after the copy - the signature of a
	/// point-in-time image rather than a torn read.
	/// </summary>
	[Fact]
	public async Task CreateSnapshotAsync_UnderAnActiveWriter_ProducesAConsistentSelfContainedCopy()
	{
		int migrationsApplied = await MigrateAllAsync();
		await using (AuditDbContext db = new(_dbOptions))
		{
			SeedRawEvents(db, 200);
		}

		using CancellationTokenSource writer = new();
		Task writerTask = WriteInBackgroundAsync(writer.Token);

		long countBefore = CountSourceRawEvents();
		DatabaseBackupCreationDto creation = await _service.CreateSnapshotAsync(
			_databasePath,
			includeShards: false,
			DatabaseBackupKind.Manual,
			CancellationToken.None);
		long countAfter = CountSourceRawEvents();

		writer.Cancel();
		try
		{
			await writerTask;
		}
		catch (OperationCanceledException)
		{
		}
		catch (DbUpdateException)
		{
			// The writer losing a race with cancellation is not part of what this test asserts.
		}

		Assert.Equal(IpcResultStatus.Success, creation.Status);
		Assert.True(File.Exists(Path.Combine(creation.SnapshotDirectory, "db", "rdpaudit.db")));
		Assert.Equal(DatabaseBackupKind.Manual, creation.Kind);
		Assert.False(string.IsNullOrWhiteSpace(creation.DatabaseSha256));

		// Self-contained: the copy is a plain DELETE-journal database with no sidecars, so any tool can
		// open it read-only. This is what makes the artifact portable.
		Assert.Equal("delete", ReadJournalMode(Path.Combine(creation.SnapshotDirectory, "db", "rdpaudit.db")));
		Assert.False(File.Exists(Path.Combine(creation.SnapshotDirectory, "db", "rdpaudit.db-wal")));
		Assert.False(File.Exists(Path.Combine(creation.SnapshotDirectory, "db", "rdpaudit.db-shm")));

		DatabaseBackupManifest? manifest = ReadManifestOf(creation.SnapshotDirectory);
		Assert.NotNull(manifest);

		// The manifest describes the source's schema state exactly: migrations never change during a copy.
		Assert.Equal(migrationsApplied, manifest!.AppliedMigrationCount);
		Assert.Equal(LastKnownMigration(), manifest.LastAppliedMigration);
		Assert.Equal(creation.DatabaseBytes, manifest.DatabaseBytes);
		Assert.Equal(creation.DatabaseSha256, manifest.DatabaseSha256);

		// The copied row count is the count of one committed instant, so it must sit inside the window
		// the live writer moved through while the copy ran.
		long copiedRows = manifest.RowCounts["RawEvents"];
		Assert.InRange(copiedRows, countBefore, countAfter);
		Assert.Equal(copiedRows, DatabaseSnapshotVerifier.CountKeyTables(
			Path.Combine(creation.SnapshotDirectory, "db", "rdpaudit.db"),
			CancellationToken.None)["RawEvents"]);

		// Verification of the published artifact passes end to end, including the schema comparison.
		DatabaseBackupVerificationDto verification = await _service.VerifyAsync(
			creation.SnapshotName,
			KnownMigrations(),
			CancellationToken.None);
		Assert.Equal(DatabaseSnapshotVerdict.Ok, verification.Verdict);
		Assert.True(verification.IsUsable);
		Assert.Equal("ok", verification.QuickCheckResult);
	}

	/// <summary>Given a database file that does not exist yet, when a snapshot is requested, then it is
	/// refused with an explanation instead of publishing an empty artifact.</summary>
	[Fact]
	public async Task CreateSnapshotAsync_WithoutADatabaseFile_Refuses()
	{
		DatabaseBackupCreationDto creation = await _service.CreateSnapshotAsync(
			Path.Combine(_root, "missing", "rdpaudit.db"),
			includeShards: false,
			DatabaseBackupKind.Manual,
			CancellationToken.None);

		Assert.Equal(IpcResultStatus.Refused, creation.Status);
		Assert.Contains("no database file", creation.Message!, StringComparison.OrdinalIgnoreCase);
		Assert.False(Directory.Exists(_backupRoot));
	}

	/// <summary>Given a destination volume that cannot hold the copy or leaves too little free space,
	/// when a snapshot is requested, then it is refused before a byte is written and the message names
	/// the numbers and the setting that controls the floor.</summary>
	[Fact]
	public async Task CreateSnapshotAsync_WhenTheFreeSpaceFloorCannotBeMet_RefusesEarly()
	{
		await MigrateAllAsync();
		_options.Storage.Backup.MinFreeDiskBytesBeforeBackup = long.MaxValue;

		DatabaseBackupCreationDto creation = await _service.CreateSnapshotAsync(
			_databasePath,
			includeShards: false,
			DatabaseBackupKind.Manual,
			CancellationToken.None);

		Assert.Equal(IpcResultStatus.Refused, creation.Status);
		Assert.Contains("Refusing to snapshot", creation.Message!, StringComparison.Ordinal);
		Assert.Contains("MinFreeDiskBytesBeforeBackup", creation.Message!, StringComparison.Ordinal);
		Assert.False(Directory.Exists(_backupRoot));
	}

	/// <summary>Given a backup destination that cannot be created, when a snapshot is requested, then
	/// the result is a refusal that names the destination and the free space on it, and no partial
	/// directory is left behind.</summary>
	[Fact]
	public async Task CreateSnapshotAsync_WhenTheDestinationCannotBeCreated_RefusesAndLeavesNothingBehind()
	{
		await MigrateAllAsync();

		// A file where a directory is expected makes Directory.CreateDirectory fail on every platform.
		string blocker = Path.Combine(_root, "blocked");
		await File.WriteAllTextAsync(blocker, "not a directory", CancellationToken.None);
		_options.Storage.Backup.BackupDirectory = Path.Combine(blocker, "Backups");

		DatabaseBackupCreationDto creation = await _service.CreateSnapshotAsync(
			_databasePath,
			includeShards: false,
			DatabaseBackupKind.Manual,
			CancellationToken.None);

		Assert.Equal(IpcResultStatus.Refused, creation.Status);
		Assert.Contains("could not be created", creation.Message!, StringComparison.Ordinal);
		Assert.False(Directory.Exists(Path.Combine(blocker, "Backups")));
	}

	// ── Shard tree ───────────────────────────────────────────────────────────────

	/// <summary>Given a populated shard tree and the shard scope requested, when a snapshot is taken,
	/// then the tree travels with the database, the manifest reports its file count and size, and the
	/// files are present inside the snapshot.</summary>
	[Fact]
	public async Task CreateSnapshotAsync_WithShards_CopiesTheTreeAndRecordsItInTheManifest()
	{
		await MigrateAllAsync();
		string actionsRoot = Path.Combine(_root, "actions");
		Directory.CreateDirectory(Path.Combine(actionsRoot, "10"));
		await File.WriteAllTextAsync(Path.Combine(actionsRoot, "10", "a.rdpshard"), "shard-a", CancellationToken.None);
		await File.WriteAllTextAsync(Path.Combine(actionsRoot, "10", "b.rdpshard"), "shard-bb", CancellationToken.None);
		_options.Sharding.Enabled = true;
		_options.Sharding.ActionsRoot = actionsRoot;

		DatabaseBackupCreationDto creation = await _service.CreateSnapshotAsync(
			_databasePath,
			includeShards: true,
			DatabaseBackupKind.Manual,
			CancellationToken.None);

		Assert.Equal(IpcResultStatus.Success, creation.Status);
		Assert.True(creation.ShardsIncluded);
		Assert.Equal(2, creation.ShardFileCount);
		Assert.Equal("shard-a".Length + "shard-bb".Length, creation.ShardBytes);

		string copiedA = Path.Combine(creation.SnapshotDirectory, "actions", "10", "a.rdpshard");
		Assert.True(File.Exists(copiedA));
		Assert.Equal("shard-a", await File.ReadAllTextAsync(copiedA, CancellationToken.None));

		DatabaseBackupManifest? manifest = ReadManifestOf(creation.SnapshotDirectory);
		Assert.True(manifest!.ShardsIncluded);
		Assert.Equal(2, manifest.ShardFileCount);
		Assert.Equal(creation.SnapshotDirectory, Path.GetDirectoryName(manifest.ShardsDirectory));
	}

	// ── Verification ─────────────────────────────────────────────────────────────

	/// <summary>Given a snapshot whose database file was modified after it was taken, when it is
	/// verified, then the tamper is reported as a hash mismatch with both digests, and the verdict is not
	/// conflated with a corrupt-but-untouched file.</summary>
	[Fact]
	public async Task VerifyAsync_DetectsAChangedByteInTheSnapshot()
	{
		DatabaseBackupCreationDto creation = await CreateSnapshotOfSeededDatabaseAsync();
		string snapshotDatabase = Path.Combine(creation.SnapshotDirectory, "db", "rdpaudit.db");
		FlipOneByteInTheMiddleOf(snapshotDatabase);

		DatabaseBackupVerificationDto verification = await _service.VerifyAsync(
			creation.SnapshotName,
			KnownMigrations(),
			CancellationToken.None);

		Assert.Equal(DatabaseSnapshotVerdict.HashMismatch, verification.Verdict);
		Assert.False(verification.IsUsable);
		Assert.Equal(creation.DatabaseSha256, verification.ExpectedSha256);
		Assert.NotEqual(verification.ExpectedSha256, verification.ActualSha256);
		Assert.Contains("does not match the SHA-256", verification.Message!, StringComparison.Ordinal);
	}

	/// <summary>Given a snapshot whose manifest was replaced by garbage, when it is verified, then the
	/// verdict is specifically "manifest unreadable", so an operator does not conclude the database copy
	/// itself is damaged.</summary>
	[Fact]
	public async Task VerifyAsync_ReportsAnUnreadableManifestSeparately()
	{
		DatabaseBackupCreationDto creation = await CreateSnapshotOfSeededDatabaseAsync();
		await File.WriteAllTextAsync(
			Path.Combine(creation.SnapshotDirectory, DatabaseBackupLayout.ManifestFileName),
			"{ this was edited by hand",
			CancellationToken.None);

		DatabaseBackupVerificationDto verification = await _service.VerifyAsync(
			creation.SnapshotName,
			KnownMigrations(),
			CancellationToken.None);

		Assert.Equal(DatabaseSnapshotVerdict.ManifestUnreadable, verification.Verdict);
		Assert.False(verification.IsUsable);
		Assert.Contains("manifest", verification.Message!, StringComparison.OrdinalIgnoreCase);
	}

	/// <summary>Given a snapshot whose database copy was deleted, when it is verified, then the verdict
	/// distinguishes a missing copy from a damaged one.</summary>
	[Fact]
	public async Task VerifyAsync_ReportsAMissingDatabaseCopySeparately()
	{
		DatabaseBackupCreationDto creation = await CreateSnapshotOfSeededDatabaseAsync();
		File.Delete(Path.Combine(creation.SnapshotDirectory, "db", "rdpaudit.db"));

		DatabaseBackupVerificationDto verification = await _service.VerifyAsync(
			creation.SnapshotName,
			KnownMigrations(),
			CancellationToken.None);

		Assert.Equal(DatabaseSnapshotVerdict.DatabaseMissing, verification.Verdict);
	}

	/// <summary>Given a snapshot taken by a newer schema than the running binaries know, when it is
	/// verified with the binaries' migration list, then restoring it is refused as a schema downgrade
	/// even though the file itself is sound.</summary>
	[Fact]
	public async Task VerifyAsync_RefusesASnapshotAheadOfTheBinaries()
	{
		DatabaseBackupCreationDto creation = await CreateSnapshotOfSeededDatabaseAsync();

		DatabaseBackupVerificationDto verification = await _service.VerifyAsync(
			creation.SnapshotName,
			["20200101000000_SomethingMuchOlder"],
			CancellationToken.None);

		Assert.Equal(DatabaseSnapshotVerdict.SchemaIncompatible, verification.Verdict);
		Assert.False(verification.IsUsable);
		Assert.Equal(SchemaCompatibilityVerdict.DatabaseAheadOfBinaries, verification.SchemaVerdict);
		Assert.Equal("ok", verification.QuickCheckResult);
	}

	/// <summary>Given an empty or absent backup root, when snapshots are listed and verified, then the
	/// list is an honest empty inventory and a verification names the missing snapshot rather than
	/// failing.</summary>
	[Fact]
	public async Task ListAndVerify_OnAnEmptyBackupRoot_ReportHonestly()
	{
		DatabaseBackupListDto list = await _service.ListAsync(CancellationToken.None);

		Assert.Equal(IpcResultStatus.Success, list.Status);
		Assert.Empty(list.Entries);
		Assert.Equal(0, list.TotalCount);
		Assert.True(list.Enabled);
		Assert.Equal(5, list.RetentionCopies);
		Assert.False(list.Truncated);
		Assert.Equal(Path.GetFullPath(_backupRoot), list.BackupDirectory);

		DatabaseBackupVerificationDto verification = await _service.VerifyAsync(null, KnownMigrations(), CancellationToken.None);
		Assert.Equal(IpcResultStatus.NotFound, verification.Status);
		Assert.Contains("no database snapshot", verification.Message!, StringComparison.OrdinalIgnoreCase);
	}

	/// <summary>Given several snapshots, when they are listed, then they are newest first and each one
	/// carries the manifest facts and the size of the whole snapshot directory.</summary>
	[Fact]
	public async Task ListAsync_ReturnsSnapshotsNewestFirstWithTheirManifestFacts()
	{
		await MigrateAllAsync();
		DatabaseBackupCreationDto first = await CreateAsync();
		DatabaseBackupCreationDto second = await CreateAsync();

		DatabaseBackupListDto list = await _service.ListAsync(CancellationToken.None);

		Assert.Equal(2, list.TotalCount);
		Assert.Equal(second.SnapshotName, list.Entries[0].Name);
		Assert.Equal(first.SnapshotName, list.Entries[1].Name);
		Assert.All(list.Entries, entry =>
		{
			Assert.True(entry.ManifestValid);
			Assert.Null(entry.ManifestError);
			Assert.Equal(DatabaseBackupKind.Manual, entry.Kind);
			Assert.True(entry.DatabaseBytes > 0);
			Assert.True(entry.SnapshotBytes > 0);
			Assert.False(string.IsNullOrWhiteSpace(entry.DatabaseSha256));
			Assert.NotEqual(default, entry.CreatedUtc);
			Assert.True(entry.RowCounts.ContainsKey("RawEvents"));
		});
	}

	/// <summary>Given a directory in the backup root that belongs to another scope, when the inventory
	/// is built, then that directory is counted as skipped and is not presented as a database
	/// snapshot.</summary>
	[Fact]
	public async Task ListAsync_CountsForeignSnapshotDirectoriesWithoutListingThem()
	{
		await MigrateAllAsync();
		await CreateAsync();
		string settingsSnapshot = Path.Combine(_backupRoot, "20260101-000000");
		Directory.CreateDirectory(settingsSnapshot);
		await File.WriteAllTextAsync(Path.Combine(settingsSnapshot, "metadata.json"), "{}", CancellationToken.None);
		await File.WriteAllTextAsync(Path.Combine(settingsSnapshot, "appsettings.json"), "{}", CancellationToken.None);

		DatabaseBackupListDto list = await _service.ListAsync(CancellationToken.None);

		Assert.Equal(1, list.TotalCount);
		Assert.Equal(1, list.SkippedDirectoryCount);
		Assert.DoesNotContain(list.Entries, entry => entry.Name == "20260101-000000");
	}

	// ── Restore into a scratch directory ─────────────────────────────────────────

	/// <summary>Given a verified snapshot, when it is restored into a scratch directory, then the
	/// restored file reproduces the counts recorded in the manifest and is a usable, standalone
	/// database - that is what a restore drill has to prove.</summary>
	[Fact]
	public async Task RestoreToDirectoryAsync_ReproducesTheSnapshotCounts()
	{
		DatabaseBackupCreationDto creation = await CreateSnapshotOfSeededDatabaseAsync();
		string target = Path.Combine(_root, "scratch");

		DatabaseBackupRestoreReportDto report = await _service.RestoreToDirectoryAsync(
			creation.SnapshotName,
			target,
			KnownMigrations(),
			CancellationToken.None);

		Assert.Equal(IpcResultStatus.Success, report.Status);
		Assert.Equal(Path.Combine(target, "rdpaudit.db"), report.TargetDatabasePath);
		Assert.True(report.DatabaseBytesCopied > 0);
		Assert.NotNull(report.Verification);
		Assert.True(report.Verification!.IsUsable);

		Dictionary<string, long> restored = DatabaseSnapshotVerifier.CountKeyTables(report.TargetDatabasePath, CancellationToken.None);
		DatabaseBackupManifest manifest = ReadManifestOf(creation.SnapshotDirectory)!;
		Assert.Equal(manifest.RowCounts["RawEvents"], restored["RawEvents"]);
		Assert.Equal("ok", DatabaseSnapshotVerifier.RunQuickCheck(report.TargetDatabasePath, CancellationToken.None));

		// The snapshot itself must be untouched by the restore.
		Assert.True(File.Exists(Path.Combine(creation.SnapshotDirectory, "db", "rdpaudit.db")));
		Assert.False(File.Exists(report.TargetDatabasePath + ".restoring"));
	}

	/// <summary>Given a snapshot that fails verification, when a restore is attempted, then nothing is
	/// written to the target directory at all.</summary>
	[Fact]
	public async Task RestoreToDirectoryAsync_RefusesATamperedSnapshotWithoutWritingAnything()
	{
		DatabaseBackupCreationDto creation = await CreateSnapshotOfSeededDatabaseAsync();
		FlipOneByteInTheMiddleOf(Path.Combine(creation.SnapshotDirectory, "db", "rdpaudit.db"));
		string target = Path.Combine(_root, "scratch-refused");

		DatabaseBackupRestoreReportDto report = await _service.RestoreToDirectoryAsync(
			creation.SnapshotName,
			target,
			KnownMigrations(),
			CancellationToken.None);

		Assert.Equal(IpcResultStatus.Refused, report.Status);
		Assert.Contains("did not pass verification", report.Message!, StringComparison.Ordinal);
		Assert.False(File.Exists(Path.Combine(target, "rdpaudit.db")));
	}

	/// <summary>Given a snapshot name that does not exist, when a restore is attempted, then it is
	/// refused by name and no directory is created.</summary>
	[Fact]
	public async Task RestoreToDirectoryAsync_RefusesAnUnknownSnapshotName()
	{
		await MigrateAllAsync();
		string target = Path.Combine(_root, "scratch-unknown");

		DatabaseBackupRestoreReportDto report = await _service.RestoreToDirectoryAsync(
			"20260101-000000",
			target,
			KnownMigrations(),
			CancellationToken.None);

		Assert.Equal(IpcResultStatus.Refused, report.Status);
		Assert.Contains("No database snapshot named", report.Message!, StringComparison.Ordinal);
		Assert.False(Directory.Exists(target));
	}

	// ── Retention ────────────────────────────────────────────────────────────────

	/// <summary>
	/// Given a retention count of two and three snapshots taken, when the third completes, then the
	/// oldest database snapshot is removed and exactly two remain. Given also a settings snapshot
	/// directory and a database reset .bak file in the same tree, then both survive: database retention
	/// removes only artifacts this feature created.
	/// </summary>
	[Fact]
	public async Task Retention_KeepsOnlyItsOwnSnapshotsUpToTheConfiguredCount()
	{
		await MigrateAllAsync();
		_options.Storage.Backup.RetentionCopies = 2;

		// Two artifacts this feature must never touch: a settings snapshot (same directory shape) and a
		// guided-reset .bak file of the live database.
		Directory.CreateDirectory(_backupRoot);
		string settingsSnapshot = Path.Combine(_backupRoot, "20250101-000000");
		Directory.CreateDirectory(settingsSnapshot);
		await File.WriteAllTextAsync(Path.Combine(settingsSnapshot, "metadata.json"), "{}", CancellationToken.None);
		await File.WriteAllTextAsync(Path.Combine(settingsSnapshot, "appsettings.json"), "{}", CancellationToken.None);
		string resetBackup = _databasePath + ".20250101-000000.bak";
		await File.WriteAllTextAsync(resetBackup, "old database", CancellationToken.None);

		DatabaseBackupCreationDto first = await CreateAsync();
		DatabaseBackupCreationDto second = await CreateAsync();
		DatabaseBackupCreationDto third = await CreateAsync();

		Assert.Equal(2, third.SnapshotCountAfter);
		Assert.Contains(first.SnapshotName, third.RetentionDeleted);
		Assert.DoesNotContain(second.SnapshotName, third.RetentionDeleted);
		Assert.DoesNotContain(third.SnapshotName, third.RetentionDeleted);

		Assert.False(Directory.Exists(first.SnapshotDirectory));
		Assert.True(Directory.Exists(second.SnapshotDirectory));
		Assert.True(Directory.Exists(third.SnapshotDirectory));

		// The foreign artifacts are still there, and the settings one is reported as deliberately kept.
		Assert.True(Directory.Exists(settingsSnapshot));
		Assert.True(File.Exists(Path.Combine(settingsSnapshot, "appsettings.json")));
		Assert.True(File.Exists(resetBackup));

		DatabaseBackupListDto list = await _service.ListAsync(CancellationToken.None);
		Assert.Equal(2, list.TotalCount);
	}

	/// <summary>Given a database snapshot that also carries the settings scope in the same directory,
	/// when retention runs, then that directory is not deleted: the settings feature owns its
	/// lifecycle.</summary>
	[Fact]
	public async Task Retention_NeverDeletesASnapshotThatAlsoCarriesTheSettingsScope()
	{
		await MigrateAllAsync();
		_options.Storage.Backup.RetentionCopies = 1;

		DatabaseBackupCreationDto first = await CreateAsync();
		// The same directory also carries settings artifacts, which makes it a shared snapshot.
		await File.WriteAllTextAsync(Path.Combine(first.SnapshotDirectory, "metadata.json"), "{}", CancellationToken.None);

		DatabaseBackupCreationDto second = await CreateAsync();

		Assert.True(Directory.Exists(first.SnapshotDirectory));
		Assert.DoesNotContain(first.SnapshotName, second.RetentionDeleted);
		Assert.Contains(
			second.RetentionSkipped,
			entry => entry.Contains(first.SnapshotName, StringComparison.Ordinal)
				&& entry.Contains("settings", StringComparison.OrdinalIgnoreCase));
	}

	/// <summary>Given a partial working directory left behind by an interrupted snapshot, when the next
	/// snapshot's retention runs, then the stale directory is cleaned up and was never listed as a
	/// snapshot.</summary>
	[Fact]
	public async Task Retention_RemovesAnAbandonedPartialWorkingDirectory()
	{
		await MigrateAllAsync();
		Directory.CreateDirectory(_backupRoot);
		string abandoned = Path.Combine(_backupRoot, "20250101-000000" + DatabaseBackupLayout.PartialSuffix);
		Directory.CreateDirectory(Path.Combine(abandoned, "db"));
		await File.WriteAllTextAsync(Path.Combine(abandoned, "db", "rdpaudit.db"), "half a copy", CancellationToken.None);
		Directory.SetLastWriteTimeUtc(abandoned, DateTime.UtcNow.AddDays(-1));

		DatabaseBackupListDto before = await _service.ListAsync(CancellationToken.None);
		Assert.Empty(before.Entries);
		Assert.Equal(0, before.SkippedDirectoryCount);

		DatabaseBackupCreationDto creation = await CreateAsync();

		Assert.Equal(1, creation.SnapshotCountAfter);
		Assert.False(Directory.Exists(abandoned));
		Assert.Contains(creation.RetentionSkipped, entry => entry.Contains("incomplete snapshot", StringComparison.Ordinal));
	}

	/// <summary>Given a snapshot count below the retention limit, when more snapshots are taken, then
	/// nothing is deleted and the report says so.</summary>
	[Fact]
	public async Task Retention_DeletesNothingBelowTheLimit()
	{
		await MigrateAllAsync();
		_options.Storage.Backup.RetentionCopies = 5;

		await CreateAsync();
		DatabaseBackupCreationDto second = await CreateAsync();

		Assert.Empty(second.RetentionDeleted);
		Assert.Equal(2, second.SnapshotCountAfter);
	}

	/// <summary>Given two snapshots inside the same UTC second, when the second is taken, then it gets a
	/// collision suffix and the first one is not overwritten.</summary>
	[Fact]
	public async Task CreateSnapshotAsync_InsideTheSameSecond_DoesNotOverwriteThePreviousSnapshot()
	{
		await MigrateAllAsync();
		_options.Storage.Backup.RetentionCopies = 10;

		DatabaseBackupCreationDto first = await CreateAsync();
		DatabaseBackupCreationDto second = await CreateAsync();

		Assert.NotEqual(first.SnapshotDirectory, second.SnapshotDirectory);
		Assert.True(Directory.Exists(first.SnapshotDirectory));
		Assert.True(Directory.Exists(second.SnapshotDirectory));
		Assert.Equal(2, second.SnapshotCountAfter);
	}

	// ── Status ───────────────────────────────────────────────────────────────────

	/// <summary>Given snapshots exist, when the light status is read, then it names the newest snapshot
	/// and the effective switches without walking every snapshot.</summary>
	[Fact]
	public async Task GetStatus_NamesTheNewestSnapshotAndTheEffectiveSwitches()
	{
		await MigrateAllAsync();
		DatabaseBackupCreationDto creation = await CreateAsync();

		DatabaseBackupStatus status = _service.GetStatus(CancellationToken.None);

		Assert.True(status.Enabled);
		Assert.True(status.PreMigrationBackupEnabled);
		Assert.Equal(5, status.RetentionCopies);
		Assert.Equal(1, status.SnapshotCount);
		Assert.Equal(creation.SnapshotDirectory, status.LastSnapshotDirectory);
		Assert.Equal(creation.DatabaseSha256, status.LastSnapshotSha256);
		Assert.NotNull(status.LastCreatedUtc);
	}

	/// <summary>Given an empty backup root, when the status is read, then it reports zero snapshots and
	/// no newest snapshot rather than failing.</summary>
	[Fact]
	public void GetStatus_OnAnEmptyRoot_ReportsZeroSnapshots()
	{
		DatabaseBackupStatus status = _service.GetStatus(CancellationToken.None);

		Assert.Equal(0, status.SnapshotCount);
		Assert.Null(status.LastSnapshotDirectory);
		Assert.Null(status.LastCreatedUtc);
		Assert.Equal(Path.GetFullPath(_backupRoot), status.BackupDirectory);
	}

	// ── Pre-migration provider surface ───────────────────────────────────────────

	/// <summary>Given the pre-migration switch on, when the provider takes its snapshot, then it writes
	/// a PreMigration manifest and reports the directory the initializer asked for.</summary>
	[Fact]
	public async Task PreMigrationProvider_WritesAPreMigrationSnapshot()
	{
		await MigrateAllAsync();

		Assert.True(_service.IsEnabled);
		Assert.Equal(Path.GetFullPath(_backupRoot), _service.ExpectedDirectory);

		PreMigrationBackupResult result = await _service.CreateAsync(_databasePath, CancellationToken.None);

		Assert.True(result.Success);
		Assert.NotNull(result.SnapshotDirectory);
		DatabaseBackupManifest? manifest = ReadManifestOf(result.SnapshotDirectory!);
		Assert.Equal(DatabaseBackupKind.PreMigration, manifest!.Kind);
	}

	/// <summary>Given the pre-migration switch off, when the provider is asked whether it is enabled,
	/// then it reports false so the initializer migrates and logs that no snapshot was taken.</summary>
	[Fact]
	public void PreMigrationProvider_IsDisabledWhenTheSwitchIsOff()
	{
		_options.Storage.Backup.PreMigrationBackupEnabled = false;

		Assert.False(_service.IsEnabled);
	}

	// ── Harness ──────────────────────────────────────────────────────────────────

	private async Task<DatabaseBackupCreationDto> CreateAsync()
		=> await _service.CreateSnapshotAsync(
			_databasePath,
			includeShards: false,
			DatabaseBackupKind.Manual,
			CancellationToken.None);

	private async Task<DatabaseBackupCreationDto> CreateSnapshotOfSeededDatabaseAsync()
	{
		await MigrateAllAsync();
		await using AuditDbContext db = new(_dbOptions);
		SeedRawEvents(db, 25);
		return await CreateAsync();
	}

	/// <summary>Applies every migration, which is what gives the database a real migration history for
	/// the manifest to record and for the downgrade guard to compare against.</summary>
	private async Task<int> MigrateAllAsync()
	{
		await using AuditDbContext db = new(_dbOptions);
		await db.Database.MigrateAsync(CancellationToken.None);
		IEnumerable<string> applied = await db.Database.GetAppliedMigrationsAsync(CancellationToken.None);
		return applied.Count();
	}

	private static void SeedRawEvents(AuditDbContext db, int count)
	{
		DateTime startUtc = DateTime.UtcNow.AddMinutes(-count);
		for (int index = 0; index < count; index++)
		{
			db.RawEvents.Add(new RawEvent
			{
				EventId = 4625,
				Channel = "Security",
				TimeUtc = startUtc.AddMinutes(index),
			});
		}

		db.SaveChanges();
	}

	/// <summary>A writer that keeps committing while the snapshot is taken, so the copy has to be
	/// consistent against a moving source rather than an idle file.</summary>
	private async Task WriteInBackgroundAsync(CancellationToken ct)
	{
		while (!ct.IsCancellationRequested)
		{
			await using AuditDbContext db = new(_dbOptions);
			db.RawEvents.Add(new RawEvent
			{
				EventId = 4624,
				Channel = "Security",
				TimeUtc = DateTime.UtcNow,
			});
			await db.SaveChangesAsync(ct);
			await Task.Delay(5, ct);
		}
	}

	private long CountSourceRawEvents()
	{
		using AuditDbContext db = new(_dbOptions);
		return db.RawEvents.AsNoTracking().LongCount();
	}

	private List<string> KnownMigrations()
	{
		using AuditDbContext db = new(_dbOptions);
		return [.. db.Database.GetMigrations()];
	}

	private string? LastKnownMigration()
	{
		using AuditDbContext db = new(_dbOptions);
		List<string> known = [.. db.Database.GetMigrations()];
		return known.Count > 0 ? known[^1] : null;
	}

	private static DatabaseBackupManifest? ReadManifestOf(string snapshotDirectory)
		=> DatabaseBackupManifestCodec.TryRead(
			Path.Combine(snapshotDirectory, DatabaseBackupLayout.ManifestFileName),
			out DatabaseBackupManifest? manifest,
			out _)
			? manifest
			: null;

	private static string ReadJournalMode(string databasePath)
	{
		using SqliteConnection connection = new(new SqliteConnectionStringBuilder
		{
			DataSource = databasePath,
			Mode = SqliteOpenMode.ReadOnly,
			Cache = SqliteCacheMode.Private,
		}.ToString());
		connection.Open();
		using SqliteCommand command = connection.CreateCommand();
		command.CommandText = "PRAGMA journal_mode;";
		return (command.ExecuteScalar() as string ?? string.Empty).ToLowerInvariant();
	}

	/// <summary>Changes one byte in the middle of a file without changing its length, which is the
	/// cheapest way to model an artifact that was edited or damaged after it was written.</summary>
	private static void FlipOneByteInTheMiddleOf(string path)
	{
		using FileStream stream = new(path, FileMode.Open, FileAccess.ReadWrite);
		long offset = stream.Length / 2;
		stream.Position = offset;
		int original = stream.ReadByte();
		stream.Position = offset;
		stream.WriteByte((byte)(original ^ 0xFF));
	}

	// ── Test doubles ─────────────────────────────────────────────────────────────

	private sealed class FileDbContextFactory : IDbContextFactory<AuditDbContext>
	{
		private readonly DbContextOptions<AuditDbContext> _options;

		public FileDbContextFactory(DbContextOptions<AuditDbContext> options) => _options = options;

		public AuditDbContext CreateDbContext() => new(_options);
	}

	private sealed class FakePathsProvider : IRdpAuditPathsProvider
	{
		public FakePathsProvider(RdpAuditPaths paths) => Paths = paths;

		public RdpAuditPaths Paths { get; }
	}

	private sealed class StubOptionsMonitor : IOptionsMonitor<RdpAuditOptions>
	{
		private readonly RdpAuditOptions _options;

		public StubOptionsMonitor(RdpAuditOptions options) => _options = options;

		public RdpAuditOptions CurrentValue => _options;

		public RdpAuditOptions Get(string? name) => _options;

		public IDisposable? OnChange(Action<RdpAuditOptions, string?> listener) => null;
	}
}
