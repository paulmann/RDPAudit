/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 2.0.0
// File   : AuditDbInitializerBackupGuardTests.cs
// Project: RdpAudit.Service.Tests (RdpAudit.Service.Tests)
// Purpose: Proves the two guarantees the storage-hardening stage adds to service startup, against a real
//          SQLite file with a real (incomplete) migration chain:
//          (1) the mandatory pre-migration snapshot is taken BEFORE the pending migration is applied, so
//              the artifact is restorable to the pre-upgrade schema - asserted by reading the manifest of
//              the snapshot the real backup engine wrote, not by trusting a call order;
//          (2) when that snapshot cannot be taken, no migration runs at all and a recovery marker is
//              written, so an operator never ends up with a migrated store and no rollback point;
//          (3) the downgrade guard refuses to open a database whose history names a migration the
//              binaries do not know, and does not refuse the ordinary case.
// Depends: AuditDbInitializer, DatabaseBackupService, DatabaseMigrationFailureMarker, AuditDbContext, xUnit
// Extends: Add a scenario here for every new refusal the initializer can produce at startup.

using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using RdpAudit.Core.Backup;
using RdpAudit.Core.Config;
using RdpAudit.Core.Data;
using RdpAudit.Core.Util;
using RdpAudit.Service.Services;
using Xunit;

namespace RdpAudit.Service.Tests;

public sealed class AuditDbInitializerBackupGuardTests : IDisposable
{
	// ── Fields & DI ──────────────────────────────────────────────────────────────

	private readonly string _root;
	private readonly string _backupRoot;
	private readonly string _databasePath;
	private readonly DbContextOptions<AuditDbContext> _dbOptions;
	private readonly RdpAuditOptions _options;

	public AuditDbInitializerBackupGuardTests()
	{
		_root = Path.Combine(Path.GetTempPath(), "rdpaudit-premigration-" + Guid.NewGuid().ToString("N"));
		_backupRoot = Path.Combine(_root, "Backups");
		Directory.CreateDirectory(_root);
		_databasePath = Path.Combine(_root, "rdpaudit.db");

		_dbOptions = new DbContextOptionsBuilder<AuditDbContext>()
			.UseSqlite($"Data Source={_databasePath};Cache=Shared")
			.AddInterceptors(new SqlitePragmaInterceptor())
			.Options;

		_options = new RdpAuditOptions();
		_options.Storage.DatabasePath = _databasePath;
		_options.Storage.Backup.BackupDirectory = _backupRoot;
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
		}
		catch (UnauthorizedAccessException)
		{
		}
	}

	// ── Mandatory pre-migration snapshot ─────────────────────────────────────────

	/// <summary>
	/// Given a database migrated to all but the last migration, when the initializer runs, then the
	/// snapshot that exists afterwards was taken before the pending migration: its manifest records the
	/// pre-migration schema state and its own history table lacks the last migration. The store is
	/// migrated afterwards, which is what makes the snapshot the rollback point.
	/// </summary>
	[Fact]
	public async Task EnsureCreatedAsync_TakesTheSnapshotBeforeApplyingPendingMigrations()
	{
		List<string> known = KnownMigrations();
		Assert.True(known.Count >= 2, "The suite needs at least two migrations to leave one pending.");
		string pending = known[^1];
		MigrateTo(known[^2]);
		int appliedBefore = AppliedMigrationCount();
		Assert.Equal(known.Count - 1, appliedBefore);

		DatabaseBackupService backups = CreateBackupService();
		using AuditDbInitializer initializer = new(
			new FileDbContextFactory(_dbOptions),
			NullLogger<AuditDbInitializer>.Instance,
			backups);

		await initializer.EnsureCreatedAsync(CancellationToken.None);

		// The migration ran...
		Assert.Equal(known.Count, AppliedMigrationCount());
		Assert.Contains(pending, AppliedMigrations());

		// ...and exactly one snapshot exists, holding the pre-migration schema state.
		string[] snapshots = Directory.GetDirectories(_backupRoot);
		string snapshot = Assert.Single(snapshots);
		DatabaseBackupManifest? manifest = ReadManifest(snapshot);
		Assert.NotNull(manifest);
		Assert.Equal(DatabaseBackupKind.PreMigration, manifest!.Kind);
		Assert.Equal(known.Count - 1, manifest.AppliedMigrationCount);
		Assert.Equal(known[^2], manifest.LastAppliedMigration);

		// The snapshot's own database is a real, restorable pre-migration copy: it opens, it passes
		// quick_check, and its history stops before the pending migration.
		string snapshotDatabase = Path.Combine(snapshot, "db", "rdpaudit.db");
		Assert.True(File.Exists(snapshotDatabase));
		Assert.Equal("ok", DatabaseSnapshotVerifier.RunQuickCheck(snapshotDatabase, CancellationToken.None));
		IReadOnlyList<string> snapshotMigrations =
			DatabaseSnapshotVerifier.ReadAppliedMigrations(snapshotDatabase, CancellationToken.None);
		Assert.DoesNotContain(pending, snapshotMigrations);
		Assert.Equal(known.Count - 1, snapshotMigrations.Count);
	}

	/// <summary>Given no pending migrations, when the initializer runs, then no snapshot is taken: an
	/// up-to-date schema has nothing to roll back.</summary>
	[Fact]
	public async Task EnsureCreatedAsync_WithoutPendingMigrations_TakesNoSnapshot()
	{
		await MigrateAllAsync();

		DatabaseBackupService backups = CreateBackupService();
		using AuditDbInitializer initializer = new(
			new FileDbContextFactory(_dbOptions),
			NullLogger<AuditDbInitializer>.Instance,
			backups);

		await initializer.EnsureCreatedAsync(CancellationToken.None);

		Assert.False(Directory.Exists(_backupRoot));
	}

	/// <summary>Given the operator switched the pre-migration snapshot off, when a migration is pending,
	/// then the initializer migrates and writes no snapshot - the documented escape hatch, and the only
	/// way to migrate without a rollback point.</summary>
	[Fact]
	public async Task EnsureCreatedAsync_WithTheSnapshotSwitchOff_MigratesWithoutASnapshot()
	{
		List<string> known = KnownMigrations();
		MigrateTo(known[^2]);
		_options.Storage.Backup.PreMigrationBackupEnabled = false;

		DatabaseBackupService backups = CreateBackupService();
		using AuditDbInitializer initializer = new(
			new FileDbContextFactory(_dbOptions),
			NullLogger<AuditDbInitializer>.Instance,
			backups);

		await initializer.EnsureCreatedAsync(CancellationToken.None);

		Assert.Equal(known.Count, AppliedMigrationCount());
		Assert.False(Directory.Exists(_backupRoot));
		Assert.Null(DatabaseMigrationFailureMarker.TryRead(_root));
	}

	/// <summary>
	/// Given a backup destination that cannot be created, when a migration is pending, then the
	/// initializer does NOT migrate: it throws a blocked-initialization exception, the schema stays at
	/// its pre-migration state, and the marker names the reason, the expected snapshot directory, the
	/// database path and what the operator should do.
	/// </summary>
	[Fact]
	public async Task EnsureCreatedAsync_WhenTheSnapshotCannotBeTaken_DoesNotMigrateAndWritesTheMarker()
	{
		List<string> known = KnownMigrations();
		MigrateTo(known[^2]);
		int appliedBefore = AppliedMigrationCount();

		// A file where the backup root's parent directory is expected makes the snapshot impossible.
		string blocker = Path.Combine(_root, "blocked");
		await File.WriteAllTextAsync(blocker, "not a directory", CancellationToken.None);
		string expectedBackupDirectory = Path.Combine(blocker, "Backups");
		_options.Storage.Backup.BackupDirectory = expectedBackupDirectory;

		DatabaseBackupService backups = CreateBackupService();
		using AuditDbInitializer initializer = new(
			new FileDbContextFactory(_dbOptions),
			NullLogger<AuditDbInitializer>.Instance,
			backups);

		DatabaseInitializationBlockedException blocked =
			await Assert.ThrowsAsync<DatabaseInitializationBlockedException>(
				() => initializer.EnsureCreatedAsync(CancellationToken.None));

		Assert.Equal(DatabaseInitializationBlockReason.PreMigrationBackupFailed, blocked.Reason);

		// The migration was NOT applied: the store is still at its pre-migration schema.
		Assert.Equal(appliedBefore, AppliedMigrationCount());
		Assert.DoesNotContain(known[^1], AppliedMigrations());

		// The operator message contains the reason, the expected path and what to do.
		Assert.Contains("NOT started", blocked.Message, StringComparison.Ordinal);
		Assert.Contains("mandatory pre-migration snapshot could not be taken", blocked.Message, StringComparison.Ordinal);
		Assert.Contains(expectedBackupDirectory, blocked.Message, StringComparison.Ordinal);
		Assert.Contains(_databasePath, blocked.Message, StringComparison.Ordinal);
		Assert.Contains("PreMigrationBackupEnabled", blocked.Message, StringComparison.Ordinal);

		MigrationFailureMarkerPayload? marker = DatabaseMigrationFailureMarker.TryRead(_root);
		Assert.NotNull(marker);
		Assert.Equal(MigrationFailureKind.PreMigrationBackupFailed, marker!.FailureKind);
		Assert.Equal(expectedBackupDirectory, marker.ExpectedBackupDirectory);
		Assert.Equal(_databasePath, marker.DatabasePath);
		Assert.False(string.IsNullOrWhiteSpace(marker.Guidance));
	}

	// ── Downgrade guard ──────────────────────────────────────────────────────────

	/// <summary>
	/// Given a database whose migration history names a migration this build does not know, when the
	/// initializer runs, then it refuses to open the store: the exception names the unknown migration, the
	/// marker records it, and the marker's guidance tells the operator what to do. Nothing is migrated.
	/// </summary>
	[Fact]
	public async Task EnsureCreatedAsync_WithADatabaseAheadOfTheBinaries_RefusesToStart()
	{
		await MigrateAllAsync();
		const string fromANewerBuild = "20990101000000_StageFromANewerBuild";
		InsertMigrationHistoryRow(fromANewerBuild);
		int appliedBefore = AppliedMigrationCount();

		DatabaseBackupService backups = CreateBackupService();
		using AuditDbInitializer initializer = new(
			new FileDbContextFactory(_dbOptions),
			NullLogger<AuditDbInitializer>.Instance,
			backups);

		DatabaseInitializationBlockedException blocked =
			await Assert.ThrowsAsync<DatabaseInitializationBlockedException>(
				() => initializer.EnsureCreatedAsync(CancellationToken.None));

		Assert.Equal(DatabaseInitializationBlockReason.SchemaAheadOfBinaries, blocked.Reason);
		Assert.Contains(fromANewerBuild, blocked.Message, StringComparison.Ordinal);
		Assert.Contains("downgrading the binaries is not supported", blocked.Message, StringComparison.OrdinalIgnoreCase);
		Assert.Contains("Guidance:", blocked.Message, StringComparison.Ordinal);

		// The refusal happened before anything touched the schema.
		Assert.Equal(appliedBefore, AppliedMigrationCount());

		MigrationFailureMarkerPayload? marker = DatabaseMigrationFailureMarker.TryRead(_root);
		Assert.NotNull(marker);
		Assert.Equal(MigrationFailureKind.SchemaAheadOfBinaries, marker!.FailureKind);
		Assert.Equal([fromANewerBuild], marker.UnknownAppliedMigrations);
	}

	/// <summary>
	/// Counterfactual to <see cref="EnsureCreatedAsync_WithADatabaseAheadOfTheBinaries_RefusesToStart"/>:
	/// the same database without the unknown history row starts normally, so the guard keys on the unknown
	/// migration and not on the mere presence of a migration history.
	/// </summary>
	[Fact]
	public async Task EnsureCreatedAsync_WithAKnownHistory_DoesNotRefuse()
	{
		await MigrateAllAsync();

		DatabaseBackupService backups = CreateBackupService();
		using AuditDbInitializer initializer = new(
			new FileDbContextFactory(_dbOptions),
			NullLogger<AuditDbInitializer>.Instance,
			backups);

		await initializer.EnsureCreatedAsync(CancellationToken.None);

		Assert.Null(DatabaseMigrationFailureMarker.TryRead(_root));
		Assert.Equal(KnownMigrations().Count, AppliedMigrationCount());
	}

	/// <summary>
	/// Given a brand new database, when the initializer runs, then the store is created by the migration
	/// chain and NO snapshot is taken: there is no pre-migration state to preserve, and requiring one
	/// would make a fresh installation unable to start. This is the documented single exception to the
	/// mandatory pre-migration snapshot; once the file exists, every later migration is covered.
	/// </summary>
	[Fact]
	public async Task EnsureCreatedAsync_OnANewDatabase_MigratesWithoutASnapshotBecauseThereIsNothingToRollBack()
	{
		Assert.False(File.Exists(_databasePath));

		DatabaseBackupService backups = CreateBackupService();
		using AuditDbInitializer initializer = new(
			new FileDbContextFactory(_dbOptions),
			NullLogger<AuditDbInitializer>.Instance,
			backups);

		await initializer.EnsureCreatedAsync(CancellationToken.None);

		Assert.Equal(KnownMigrations().Count, AppliedMigrationCount());
		Assert.True(File.Exists(_databasePath));
		Assert.False(Directory.Exists(_backupRoot));
		Assert.Null(DatabaseMigrationFailureMarker.TryRead(_root));
	}

	/// <summary>Given a host that registered no snapshot engine, when a migration is pending, then the
	/// initializer migrates (it can do nothing else) and writes no marker, which keeps Core-only hosts and
	/// direct-initializer callers working exactly as before this stage.</summary>
	[Fact]
	public async Task EnsureCreatedAsync_WithoutABackupProvider_MigratesWithoutASnapshot()
	{
		List<string> known = KnownMigrations();
		MigrateTo(known[^2]);

		using AuditDbInitializer initializer = new(
			new FileDbContextFactory(_dbOptions),
			NullLogger<AuditDbInitializer>.Instance);

		await initializer.EnsureCreatedAsync(CancellationToken.None);

		Assert.Equal(known.Count, AppliedMigrationCount());
		Assert.Null(DatabaseMigrationFailureMarker.TryRead(_root));
	}

	/// <summary>Given a corrupted migration history entry, when the initializer runs, then it refuses the
	/// store with the history-invalid reason instead of guessing at the schema state.</summary>
	[Fact]
	public async Task EnsureCreatedAsync_WithADamagedMigrationHistory_Refuses()
	{
		await MigrateAllAsync();
		InsertMigrationHistoryRow(string.Empty);

		DatabaseBackupService backups = CreateBackupService();
		using AuditDbInitializer initializer = new(
			new FileDbContextFactory(_dbOptions),
			NullLogger<AuditDbInitializer>.Instance,
			backups);

		DatabaseInitializationBlockedException blocked =
			await Assert.ThrowsAsync<DatabaseInitializationBlockedException>(
				() => initializer.EnsureCreatedAsync(CancellationToken.None));

		Assert.Equal(DatabaseInitializationBlockReason.MigrationHistoryInvalid, blocked.Reason);
		MigrationFailureMarkerPayload? marker = DatabaseMigrationFailureMarker.TryRead(_root);
		Assert.Equal(MigrationFailureKind.MigrationHistoryInvalid, marker!.FailureKind);
	}

	// ── Harness ──────────────────────────────────────────────────────────────────

	private DatabaseBackupService CreateBackupService()
		=> new(
			new StubOptionsMonitor(_options),
			NullLogger<DatabaseBackupService>.Instance,
			new FakePathsProvider(new RdpAuditPaths(_root)));

	private List<string> KnownMigrations()
	{
		using AuditDbContext db = new(_dbOptions);
		return [.. db.Database.GetMigrations()];
	}

	private async Task MigrateAllAsync()
	{
		await using AuditDbContext db = new(_dbOptions);
		await db.Database.MigrateAsync(CancellationToken.None);
	}

	/// <summary>Applies the migration chain up to and including <paramref name="targetMigration"/>, which
	/// is how this suite produces a database with exactly one pending migration. EF Core exposes only the
	/// synchronous migrator for a target migration, and this is test setup, not a production path.</summary>
	private void MigrateTo(string targetMigration)
	{
		using AuditDbContext db = new(_dbOptions);
		db.GetService<IMigrator>().Migrate(targetMigration);
	}

	private int AppliedMigrationCount()
	{
		using SqliteConnection connection = Open();
		using SqliteCommand command = connection.CreateCommand();
		command.CommandText = "SELECT COUNT(*) FROM \"__EFMigrationsHistory\";";
		return Convert.ToInt32(command.ExecuteScalar(), System.Globalization.CultureInfo.InvariantCulture);
	}

	private List<string> AppliedMigrations()
	{
		using SqliteConnection connection = Open();
		List<string> migrations = [];
		using SqliteCommand command = connection.CreateCommand();
		command.CommandText = "SELECT MigrationId FROM \"__EFMigrationsHistory\" ORDER BY MigrationId;";
		using SqliteDataReader reader = command.ExecuteReader();
		while (reader.Read())
		{
			migrations.Add(reader.GetString(0));
		}

		return migrations;
	}

	/// <summary>Simulates a database written by a newer build by adding a history row this assembly has no
	/// migration for; an empty id simulates a damaged history row.</summary>
	private void InsertMigrationHistoryRow(string migrationId)
	{
		using SqliteConnection connection = Open();
		using SqliteCommand command = connection.CreateCommand();
		command.CommandText = "INSERT INTO \"__EFMigrationsHistory\" (\"MigrationId\", \"ProductVersion\") VALUES ($id, '9.9.9');";
		command.Parameters.AddWithValue("$id", migrationId);
		command.ExecuteNonQuery();
	}

	private SqliteConnection Open()
	{
		SqliteConnection connection = new($"Data Source={_databasePath};Cache=Private");
		connection.Open();
		return connection;
	}

	private static DatabaseBackupManifest? ReadManifest(string snapshotDirectory)
		=> DatabaseBackupManifestCodec.TryRead(
			Path.Combine(snapshotDirectory, DatabaseBackupLayout.ManifestFileName),
			out DatabaseBackupManifest? manifest,
			out _)
			? manifest
			: null;

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
