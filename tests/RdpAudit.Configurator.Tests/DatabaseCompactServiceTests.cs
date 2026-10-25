/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 1.0.0
// File   : DatabaseCompactServiceTests.cs
// Project: RdpAudit.Configurator.Tests (RdpAudit.Configurator.Tests)
// Purpose: Proves the offline compaction contract (Requirement R24): the service that is allowed to run a
//          full VACUUM is the one that runs with the RdpAudit service stopped, it compacts through
//          VACUUM INTO plus an atomic swap, it refuses unless the copy proves data preservation
//          (quick_check, matching migration history, matching per-table row counts, no foreign-key
//          violations), and a failure leaves the live store byte-identical.
//          The tests drive the real file-swap path against a temp directory; only the Windows service
//          itself is a non-installed test double, which is exactly how the restore tests reach the swap.
// Depends: DatabaseCompactService, DatabaseSnapshotVerifier, AuditDbContextOptionsFactory, xUnit
// Extends: Add a scenario here for every new refusal that must happen before the swap.

using System.Text.Json;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using RdpAudit.Configurator.Services;
using RdpAudit.Core.Backup;
using RdpAudit.Core.Data;
using RdpAudit.Core.Models;
using Xunit;

namespace RdpAudit.Configurator.Tests;

public sealed class DatabaseCompactServiceTests : IDisposable
{
	// ── Fields & DI ──────────────────────────────────────────────────────────────

	private readonly string _root;
	private readonly string _databasePath;
	private readonly DatabaseCompactService _service = new("RdpAuditServiceTestDouble", "RdpAudit Service (test)");

	public DatabaseCompactServiceTests()
	{
		_root = Path.Combine(Path.GetTempPath(), "rdpaudit-compact-" + Guid.NewGuid().ToString("N"));
		Directory.CreateDirectory(_root);
		_databasePath = Path.Combine(_root, "rdpaudit.db");
	}

	public void Dispose()
	{
		SqliteConnection.ClearAllPools();
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

	// ── Acceptance ───────────────────────────────────────────────────────────────

	/// <summary>Given a store that still occupies the space of rows it no longer holds, when the offline
	/// compaction runs, then the file shrinks, the surviving rows are intact (quick_check plus a row-count
	/// comparison inside the service and an independent count here), an FK check ran on the copy, the
	/// pre-compaction database is kept as a .bak for undo, and a receipt records the operation.
	/// <para>The test double is a service that is not installed, so <c>Success</c> is false for the one
	/// reason that the service could not be started again - which is exactly why the result separates
	/// <c>Compacted</c> from <c>Success</c>. The assertion is on <c>Compacted</c> plus the log, so the
	/// evidence-file half of the operation is still fully verified here.</para></summary>
	[Fact]
	public async Task ExecuteAsync_ShrinksAStoreWithDeletedRows_AndPreservesEveryRow()
	{
		await SeedStoreAsync(rows: 4_000, survivors: 25);
		SqliteConnection.ClearAllPools();
		long bytesBefore = new FileInfo(_databasePath).Length;
		Assert.True(bytesBefore > 0);

		DatabaseCompactResult result = await _service.ExecuteAsync(_databasePath, CancellationToken.None);

		Assert.True(result.Compacted, result.Log);
		Assert.False(result.Success);
		Assert.Contains("could not be started", result.Log, StringComparison.Ordinal);
		Assert.Equal(bytesBefore, result.BytesBefore);
		Assert.True(result.BytesReclaimed > 0, "the compaction must shrink the file: " + result.Log);
		Assert.True(result.BytesAfter < bytesBefore);
		Assert.Contains("Row counts match", result.Log, StringComparison.Ordinal);
		Assert.Contains("foreign_key_check on the copy: ok", result.Log, StringComparison.Ordinal);
		Assert.Contains("quick_check on the copy: ok", result.Log, StringComparison.Ordinal);

		// Independent verification of the swapped-in file.
		SqliteConnection.ClearAllPools();
		Assert.Equal("ok", DatabaseSnapshotVerifier.RunQuickCheck(_databasePath, CancellationToken.None));
		Dictionary<string, long> counts = DatabaseSnapshotVerifier.CountKeyTables(_databasePath, CancellationToken.None);
		Assert.Equal(25L, counts["RawEvents"]);

		// The pre-state database is preserved (the operator's undo): same 25 surviving rows, still inside
		// the un-shrunk file.
		Assert.NotNull(result.PreStateBackupPath);
		Assert.True(File.Exists(result.PreStateBackupPath!));
		Assert.Equal(
			25L,
			DatabaseSnapshotVerifier.CountKeyTables(result.PreStateBackupPath!, CancellationToken.None)["RawEvents"]);
		Assert.True(
			new FileInfo(result.PreStateBackupPath!).Length > result.BytesAfter,
			"the pre-state file is the un-compacted original, so it must still be the larger one");
		Assert.True(File.Exists(result.PreStateBackupPath + DatabaseCompactService.ReceiptSuffix));

		// Neither staging artifact is left behind.
		Assert.False(File.Exists(_databasePath + DatabaseCompactService.StagingSuffix));
		Assert.False(File.Exists(_databasePath + DatabaseCompactService.CompactedCopySuffix));
	}

	/// <summary>Given the database path does not exist, when the compaction runs, then it is refused before
	/// the service is stopped and no file is created.</summary>
	[Fact]
	public async Task ExecuteAsync_WithoutADatabaseFile_RefusesBeforeStoppingAnything()
	{
		string missing = Path.Combine(_root, "absent.db");

		DatabaseCompactResult result = await _service.ExecuteAsync(missing, CancellationToken.None);

		Assert.False(result.Success);
		Assert.Contains("REFUSED", result.Log, StringComparison.Ordinal);
		Assert.Contains("no database file exists", result.Log, StringComparison.Ordinal);
		Assert.False(File.Exists(missing));
		Assert.Empty(Directory.GetFiles(_root, "*.bak"));
	}

	/// <summary>Given the target is a file that is not a SQLite database, when the compaction runs, then
	/// the VACUUM INTO fails, the report says the live store was not touched, and the file is
	/// byte-identical afterwards - a failure on the copy path must never damage the store.</summary>
	[Fact]
	public async Task ExecuteAsync_WithAnUnreadableStore_LeavesTheFileByteIdentical()
	{
		string notADatabase = Path.Combine(_root, "not-a-database.txt");
		await File.WriteAllTextAsync(notADatabase, "this is not a SQLite database", CancellationToken.None);

		DatabaseCompactResult result = await _service.ExecuteAsync(notADatabase, CancellationToken.None);

		Assert.False(result.Success);
		Assert.Contains("FAILED", result.Log, StringComparison.Ordinal);
		Assert.Contains("was not touched", result.Log, StringComparison.Ordinal);
		Assert.Equal("this is not a SQLite database", await File.ReadAllTextAsync(notADatabase, CancellationToken.None));
		Assert.Empty(Directory.GetFiles(_root, "*.bak"));
		Assert.False(File.Exists(notADatabase + DatabaseCompactService.StagingSuffix));
	}

	// ── Auto-vacuum mode (B27) ───────────────────────────────────────────────────

	/// <summary>Given a legacy store in auto-vacuum mode NONE - what every store created before the B27 fix
	/// is - when the offline compaction runs, then the store that comes back reports INCREMENTAL, the
	/// pre-state backup is still the mode-NONE original (the undo really is the old store), and the receipt
	/// records both modes. Without the mode step the compacted copy would inherit mode NONE and the next
	/// online purge would release nothing again.</summary>
	[Fact]
	public async Task ExecuteAsync_OnALegacyStoreInModeNone_BringsTheStoreToIncrementalAutoVacuumMode()
	{
		await SeedStoreAsync(rows: 4_000, survivors: 25);
		SqliteConnection.ClearAllPools();
		Assert.Equal(0, DatabaseCompactService.ReadAutoVacuumMode(_databasePath));

		DatabaseCompactResult result = await _service.ExecuteAsync(_databasePath, CancellationToken.None);

		Assert.True(result.Compacted, result.Log);
		Assert.Equal(0, result.AutoVacuumModeBefore);
		Assert.Equal(DatabaseCompactService.IncrementalAutoVacuumMode, result.AutoVacuumModeAfter);
		Assert.Contains("Auto-vacuum mode: 0 -> 2", result.Log, StringComparison.Ordinal);
		Assert.Contains("normalised: 0 -> 2", result.Log, StringComparison.Ordinal);

		// Independent verification on the file that is now in place, and on the kept original.
		SqliteConnection.ClearAllPools();
		Assert.Equal(
			DatabaseCompactService.IncrementalAutoVacuumMode,
			DatabaseCompactService.ReadAutoVacuumMode(_databasePath));
		Assert.NotNull(result.PreStateBackupPath);
		Assert.Equal(0, DatabaseCompactService.ReadAutoVacuumMode(result.PreStateBackupPath!));

		string receipt = await File.ReadAllTextAsync(
			result.PreStateBackupPath + DatabaseCompactService.ReceiptSuffix,
			CancellationToken.None);
		using JsonDocument document = JsonDocument.Parse(receipt);
		Assert.Equal(0, document.RootElement.GetProperty("autoVacuumModeBefore").GetInt32());
		Assert.Equal(2, document.RootElement.GetProperty("autoVacuumModeAfter").GetInt32());
	}

	/// <summary>Given a store already in incremental auto-vacuum mode, when the offline compaction runs,
	/// then no second rewrite happens for the mode: the copy carries it over and the log says so, because a
	/// redundant full rewrite of a multi-gigabyte store is not something to do silently.</summary>
	[Fact]
	public async Task ExecuteAsync_OnAStoreAlreadyInIncrementalMode_SkipsTheModeRewrite()
	{
		await SeedStoreAsync(rows: 2_000, survivors: 25, incrementalAutoVacuum: true);
		SqliteConnection.ClearAllPools();
		Assert.Equal(
			DatabaseCompactService.IncrementalAutoVacuumMode,
			DatabaseCompactService.ReadAutoVacuumMode(_databasePath));

		DatabaseCompactResult result = await _service.ExecuteAsync(_databasePath, CancellationToken.None);

		Assert.True(result.Compacted, result.Log);
		Assert.Equal(DatabaseCompactService.IncrementalAutoVacuumMode, result.AutoVacuumModeBefore);
		Assert.Equal(DatabaseCompactService.IncrementalAutoVacuumMode, result.AutoVacuumModeAfter);
		Assert.Contains("no further rewrite was needed", result.Log, StringComparison.Ordinal);
		Assert.DoesNotContain("normalised", result.Log, StringComparison.Ordinal);
	}

	/// <summary>Closes the loop the mode step exists for: given a legacy store, when it is compacted
	/// offline and rows are then deleted again, then the ONLINE reclamation pair - the bounded
	/// <c>PRAGMA incremental_vacuum(5000)</c> the purge and the maintenance surface issue - releases the
	/// freed pages and the file shrinks. On the same store before the compaction that pair is a measured
	/// no-op (see AutoVacuumModeTests), so this is the end-to-end proof that the offline pass hands the
	/// operator a store that can reclaim space online again.</summary>
	[Fact]
	public async Task ExecuteAsync_AfterCompactingALegacyStore_OnlineReclamationReleasesPages()
	{
		await SeedStoreAsync(rows: 4_000, survivors: 2_000);
		SqliteConnection.ClearAllPools();
		Assert.Equal(0, DatabaseCompactService.ReadAutoVacuumMode(_databasePath));

		DatabaseCompactResult result = await _service.ExecuteAsync(_databasePath, CancellationToken.None);
		Assert.True(result.Compacted, result.Log);
		SqliteConnection.ClearAllPools();

		// Delete another contiguous half of what survived, so there are free pages to release again.
		await using (AuditDbContext db = new(AuditDbContextOptionsFactory.Create(_databasePath)))
		{
			DateTime cutoff = await db.RawEvents
				.OrderByDescending(row => row.TimeUtc)
				.Select(row => row.TimeUtc)
				.Skip(await db.RawEvents.CountAsync() / 2)
				.FirstAsync();
			await db.RawEvents.Where(row => row.TimeUtc > cutoff).ExecuteDeleteAsync();
		}

		SqliteConnection.ClearAllPools();
		long freePagesBefore = ReadFreeListPages(_databasePath);
		long bytesBefore = new FileInfo(_databasePath).Length;
		Assert.True(freePagesBefore > 0, "the fixture must leave free pages behind");

		using (SqliteConnection connection = new("Data Source=" + _databasePath + ";Pooling=False"))
		{
			await connection.OpenAsync();
			await using SqliteCommand command = connection.CreateCommand();
			command.CommandText = "PRAGMA wal_checkpoint(TRUNCATE); PRAGMA incremental_vacuum(5000);";
			await command.ExecuteNonQueryAsync();
		}

		SqliteConnection.ClearAllPools();
		long freePagesAfter = ReadFreeListPages(_databasePath);
		long bytesAfter = new FileInfo(_databasePath).Length;
		Assert.True(
			freePagesAfter < freePagesBefore,
			"online reclamation must work on the compacted store: before=" + freePagesBefore + " after=" + freePagesAfter);
		Assert.True(bytesAfter < bytesBefore, "the released pages must leave the file: " + bytesBefore + " -> " + bytesAfter);
	}

	/// <summary>The counterfactual that justifies the mode step, measured against the SQLite this product
	/// ships: <c>VACUUM INTO</c> carries the SOURCE's auto-vacuum mode into the new file. A legacy store
	/// therefore produces a mode-NONE copy on its own, which is exactly why the compaction must normalise
	/// the mode instead of assuming the rewrite fixed it.</summary>
	[Fact]
	public async Task VacuumInto_OnALegacyStore_CarriesModeNoneIntoTheCopy()
	{
		await SeedStoreAsync(rows: 2_000, survivors: 25);
		SqliteConnection.ClearAllPools();
		string copyPath = _databasePath + ".vacuum-into-copy.db";

		using (SqliteConnection connection = new("Data Source=" + _databasePath + ";Pooling=False"))
		{
			await connection.OpenAsync();
			await using SqliteCommand command = connection.CreateCommand();
#pragma warning disable CA2100 // VACUUM INTO takes a string literal, not a bound parameter; the path is a temp path this test resolved.
			command.CommandText = "VACUUM INTO '" + copyPath.Replace("'", "''", StringComparison.Ordinal) + "';";
#pragma warning restore CA2100
			await command.ExecuteNonQueryAsync();
		}

		Assert.Equal(0, DatabaseCompactService.ReadAutoVacuumMode(_databasePath));
		Assert.Equal(0, DatabaseCompactService.ReadAutoVacuumMode(copyPath));
	}

	// ── Fixture helpers ──────────────────────────────────────────────────────────

	private static long ReadFreeListPages(string databasePath)
	{
		using SqliteConnection connection = new("Data Source=" + databasePath + ";Pooling=False");
		connection.Open();
		using SqliteCommand command = connection.CreateCommand();
		command.CommandText = "PRAGMA freelist_count;";
		return Convert.ToInt64(command.ExecuteScalar(), System.Globalization.CultureInfo.InvariantCulture);
	}

	/// <summary>Creates a store with <paramref name="rows"/> detail rows, deletes all but
	/// <paramref name="survivors"/> of them, and checkpoints the WAL, so the file occupies the space of
	/// rows it no longer holds - the exact precondition a compaction exists for. No interceptor is
	/// involved, so the store's auto-vacuum mode is whatever <paramref name="incrementalAutoVacuum"/> asks
	/// for: <c>false</c> is the legacy shape (mode NONE), and it is set before the schema exists when
	/// <c>true</c>, which is the only point at which SQLite writes the mode into the file header.</summary>
	private async Task SeedStoreAsync(int rows, int survivors, bool incrementalAutoVacuum = false)
	{
		string detail = new('x', 600);
		SqliteConnection? pinned = null;
		try
		{
			DbContextOptions<AuditDbContext> options;
			if (incrementalAutoVacuum)
			{
				pinned = new SqliteConnection("Data Source=" + _databasePath);
				await pinned.OpenAsync();
				await using SqliteCommand pragma = pinned.CreateCommand();
				pragma.CommandText = "PRAGMA auto_vacuum = INCREMENTAL;";
				await pragma.ExecuteNonQueryAsync();
				options = new DbContextOptionsBuilder<AuditDbContext>().UseSqlite(pinned).Options;
			}
			else
			{
				options = AuditDbContextOptionsFactory.Create(_databasePath);
			}

			await using (AuditDbContext db = new(options))
			{
				await db.Database.EnsureCreatedAsync();
				for (int index = 0; index < rows; index++)
				{
					db.RawEvents.Add(new RawEvent
					{
						Channel = "Security",
						EventId = 4625,
						TimeUtc = DateTime.UtcNow.AddSeconds(-index),
						Details = detail,
					});
				}

				await db.SaveChangesAsync();

				// Keep the OLDEST rows so the survivors are deterministic by Id.
				await db.RawEvents
					.Where(row => row.Id > survivors)
					.ExecuteDeleteAsync();
			}
		}
		finally
		{
			if (pinned is not null)
			{
				await pinned.DisposeAsync();
			}
		}

		await using (SqliteConnection connection = new("Data Source=" + _databasePath))
		{
			await connection.OpenAsync();
			await using SqliteCommand command = connection.CreateCommand();
			command.CommandText = "PRAGMA wal_checkpoint(TRUNCATE);";
			await command.ExecuteNonQueryAsync();
		}
	}
}
