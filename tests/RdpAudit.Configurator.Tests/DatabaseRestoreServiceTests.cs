/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 2.0.0
// File   : DatabaseRestoreServiceTests.cs
// Project: RdpAudit.Configurator.Tests (RdpAudit.Configurator.Tests)
// Purpose: Covers the guard half of the in-place restore - the part that runs before anything
//          destructive. A snapshot that fails verification, or that was taken by a newer schema than the
//          installed binaries know, must be refused without stopping the service and without renaming,
//          replacing or deleting a single file in the live store. The steps that need a real Windows
//          service (stop, rename, copy, start) are deliberately not driven from a unit test; what is
//          tested here is that they are never reached on the refusal paths.
// Depends: DatabaseRestoreService, DatabaseSnapshotVerifier, xUnit
// Extends: Add a scenario here for every new refusal that must happen before the service is stopped.

using Microsoft.Data.Sqlite;
using RdpAudit.Core.Backup;
using RdpAudit.Configurator.Services;
using Xunit;

namespace RdpAudit.Configurator.Tests;

public sealed class DatabaseRestoreServiceTests : IDisposable
{
	// ── Fields & DI ──────────────────────────────────────────────────────────────

	private readonly string _root;
	private readonly string _snapshotDirectory;
	private readonly string _databasePath;
	private readonly DatabaseRestoreService _service = new("RdpAuditServiceTestDouble", "RdpAudit Service (test)");

	public DatabaseRestoreServiceTests()
	{
		_root = Path.Combine(Path.GetTempPath(), "rdpaudit-restore-" + Guid.NewGuid().ToString("N"));
		_snapshotDirectory = Path.Combine(_root, "Backups", "20260914-103045");
		Directory.CreateDirectory(Path.Combine(_snapshotDirectory, "db"));
		_databasePath = Path.Combine(_root, "rdpaudit.db");
		File.WriteAllText(_databasePath, "the live store that must not be touched");
	}

	public void Dispose()
	{
		try
		{
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

	// ── Refusals before anything destructive ─────────────────────────────────────

	/// <summary>Given a snapshot directory with no manifest at all, when the restore runs, then it is
	/// refused, the live database is byte-identical afterwards and no pre-state backup or receipt was
	/// created.</summary>
	[Fact]
	public async Task ExecuteAsync_WithAnUnreadableSnapshot_RefusesAndLeavesTheStoreUntouched()
	{
		string liveBefore = await File.ReadAllTextAsync(_databasePath, CancellationToken.None);

		DatabaseRestoreResult result = await _service.ExecuteAsync(
			_snapshotDirectory,
			_databasePath,
			knownMigrations: Array.Empty<string>(),
			CancellationToken.None);

		Assert.False(result.Success);
		Assert.Contains("REFUSED", result.Log, StringComparison.Ordinal);
		Assert.Contains("NOT touched", result.Log, StringComparison.Ordinal);
		Assert.Equal(liveBefore, await File.ReadAllTextAsync(_databasePath, CancellationToken.None));
		Assert.Null(result.PreStateBackupPath);
		Assert.Empty(Directory.GetFiles(_root, "*.bak"));
		Assert.Empty(Directory.GetFiles(_root, "*.restore.json"));
		Assert.False(File.Exists(_databasePath + ".restoring"));
	}

	/// <summary>
	/// Given a snapshot that is sound as a file - it opens, its digest matches and quick_check passes -
	/// but whose migration history names migrations the installed binaries do not know, when the restore
	/// runs, then it is refused as a downgrade. Restoring it would leave a store the service itself
	/// refuses to open, so the refusal has to happen here, before the live file is replaced.
	/// </summary>
	[Fact]
	public async Task ExecuteAsync_WithASnapshotAheadOfTheBinaries_RefusesAsADowngrade()
	{
		string snapshotDatabase = Path.Combine(_snapshotDirectory, "db", "rdpaudit.db");
		CreateSqliteDatabaseWithHistory(
			snapshotDatabase,
			["20270101000000_FromANewerBuild", "20270202000000_AlsoFromANewerBuild"]);
		WriteManifestFor(snapshotDatabase, appliedMigrations: 2);

		DatabaseRestoreResult result = await _service.ExecuteAsync(
			_snapshotDirectory,
			_databasePath,
			knownMigrations: ["20200101000000_OnlyThisBuildKnowsOneMigration"],
			CancellationToken.None);

		Assert.False(result.Success);
		Assert.Contains("REFUSED", result.Log, StringComparison.Ordinal);
		Assert.Contains("SchemaIncompatible", result.Log, StringComparison.Ordinal);
		Assert.Contains("downgrade", result.Log, StringComparison.OrdinalIgnoreCase);
		Assert.False(File.Exists(_databasePath + ".restoring"));
		Assert.Empty(Directory.GetFiles(_root, "*.bak"));
		Assert.StartsWith("the live store", await File.ReadAllTextAsync(_databasePath, CancellationToken.None), StringComparison.Ordinal);
	}

	/// <summary>Given a snapshot whose database copy was modified after it was taken, when the restore
	/// runs, then the digest mismatch is reported and nothing is replaced.</summary>
	[Fact]
	public async Task ExecuteAsync_WithATamperedSnapshot_RefusesOnTheDigest()
	{
		string snapshotDatabase = Path.Combine(_snapshotDirectory, "db", "rdpaudit.db");
		File.Copy(_databasePath, snapshotDatabase);
		WriteManifestFor(snapshotDatabase, appliedMigrations: 0);
		using (FileStream stream = new(snapshotDatabase, FileMode.Open, FileAccess.ReadWrite))
		{
			stream.Position = 0;
			stream.WriteByte(0x00);
		}

		DatabaseRestoreResult result = await _service.ExecuteAsync(
			_snapshotDirectory,
			_databasePath,
			knownMigrations: Array.Empty<string>(),
			CancellationToken.None);

		Assert.False(result.Success);
		Assert.Contains("HashMismatch", result.Log, StringComparison.Ordinal);
		Assert.False(File.Exists(_databasePath + ".restoring"));
	}

	/// <summary>Given a snapshot directory that does not exist, when the restore runs, then it is
	/// refused by name and the live store is untouched.</summary>
	[Fact]
	public async Task ExecuteAsync_WithAMissingSnapshotDirectory_Refuses()
	{
		DatabaseRestoreResult result = await _service.ExecuteAsync(
			Path.Combine(_root, "Backups", "20200101-000000"),
			_databasePath,
			knownMigrations: Array.Empty<string>(),
			CancellationToken.None);

		Assert.False(result.Success);
		Assert.Contains("REFUSED", result.Log, StringComparison.Ordinal);
		Assert.True(File.Exists(_databasePath));
		Assert.Empty(Directory.GetFiles(_root, "*.bak"));
	}

	// ── Harness ──────────────────────────────────────────────────────────────────

	/// <summary>Creates a real, structurally sound SQLite database whose only content is a migration
	/// history table, so verification reaches the schema comparison instead of failing on quick_check.</summary>
	private static void CreateSqliteDatabaseWithHistory(string databasePath, IReadOnlyList<string> migrations)
	{
		using SqliteConnection connection = new(new SqliteConnectionStringBuilder
		{
			DataSource = databasePath,
			Mode = SqliteOpenMode.ReadWriteCreate,
			Pooling = false,
		}.ToString());
		connection.Open();
		using (SqliteCommand create = connection.CreateCommand())
		{
			create.CommandText =
				"CREATE TABLE \"__EFMigrationsHistory\" (\"MigrationId\" TEXT NOT NULL PRIMARY KEY, \"ProductVersion\" TEXT NOT NULL);";
			create.ExecuteNonQuery();
		}

		foreach (string migration in migrations)
		{
			using SqliteCommand insert = connection.CreateCommand();
			insert.CommandText = "INSERT INTO \"__EFMigrationsHistory\" VALUES ($id, '9.9.9');";
			insert.Parameters.AddWithValue("$id", migration);
			insert.ExecuteNonQuery();
		}
	}

	/// <summary>Writes a manifest whose digest matches the file as it stands, so the digest check is not
	/// what refuses the restore - the schema comparison is.</summary>
	private static void WriteManifestFor(string databasePath, int appliedMigrations)
	{
		string directory = Path.GetDirectoryName(databasePath)!;
		DatabaseBackupManifest manifest = new()
		{
			Kind = DatabaseBackupKind.Manual,
			CreatedUtc = new DateTime(2026, 9, 14, 10, 30, 45, DateTimeKind.Utc),
			DatabasePath = databasePath,
			DatabaseBytes = new FileInfo(databasePath).Length,
			DatabaseSha256 = DatabaseSnapshotVerifier.ComputeSha256(databasePath, CancellationToken.None),
			AppliedMigrationCount = appliedMigrations,
			RowCounts = new Dictionary<string, long>(StringComparer.Ordinal),
		};

		DatabaseBackupManifestCodec.WriteAtomic(
			Path.Combine(Path.GetDirectoryName(directory)!, DatabaseBackupLayout.ManifestFileName),
			manifest);
	}

	// ── The path that actually replaces the store ────────────────────────────────

	/// <summary>Given a snapshot that verifies, when the restore runs, then the live file is replaced, a
	/// pre-state backup and a receipt are written, and the restored database is checked for referential
	/// violations before the service is started again (Requirement R23). The service under test is a
	/// non-installed test double, so the stop/start steps report "not installed" - which is exactly how the
	/// swap becomes reachable from a unit test - and the receipt records the foreign-key outcome.</summary>
	[Fact]
	public async Task ExecuteAsync_WithAVerifiedSnapshot_ReplacesTheStoreAndChecksForeignKeys()
	{
		string snapshotDatabase = Path.Combine(_snapshotDirectory, "db", "rdpaudit.db");
		CreateSqliteDatabaseWithHistory(snapshotDatabase, ["20260101000000_Initial"]);
		WriteManifestFor(snapshotDatabase, appliedMigrations: 1);

		DatabaseRestoreResult result = await _service.ExecuteAsync(
			_snapshotDirectory,
			_databasePath,
			knownMigrations: ["20260101000000_Initial"],
			CancellationToken.None);

		// The store was replaced: the live file is now the snapshot's content, not the fixture text.
		Assert.NotEqual("the live store that must not be touched", await File.ReadAllTextAsync(_databasePath, CancellationToken.None));
		Assert.Contains("Moved the validated replacement into place", result.Log, StringComparison.Ordinal);
		Assert.Contains("Renamed the live database to:", result.Log, StringComparison.Ordinal);

		// The foreign-key check ran against the restored file and is recorded in the log and the receipt.
		Assert.Contains("Foreign-key check:", result.Log, StringComparison.Ordinal);
		Assert.Contains("ok (no foreign-key violations)", result.Log, StringComparison.Ordinal);
		Assert.NotNull(result.PreStateBackupPath);
		Assert.True(File.Exists(result.PreStateBackupPath!));
		Assert.Equal(
			"the live store that must not be touched",
			await File.ReadAllTextAsync(result.PreStateBackupPath!, CancellationToken.None));

		string receipt = await File.ReadAllTextAsync(
			result.PreStateBackupPath + DatabaseRestoreService.ReceiptSuffix,
			CancellationToken.None);
		Assert.Contains("foreignKeyCheck", receipt, StringComparison.Ordinal);
	}
}
