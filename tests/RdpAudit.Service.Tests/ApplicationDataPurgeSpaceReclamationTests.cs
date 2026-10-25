/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 1.0.0
// File   : ApplicationDataPurgeSpaceReclamationTests.cs
// Project: RdpAudit.Service.Tests
// Purpose: Pins the online space-reclamation policy of the application-data purge (Requirement R24):
//          the live path issues a WAL checkpoint (TRUNCATE) and a BOUNDED PRAGMA incremental_vacuum and
//          has no code path that can emit a full VACUUM. Two kinds of evidence are produced:
//          (1) a composition assertion over the statement list the service actually executes, and
//          (2) a file-backed behavioural assertion that the database file is NOT shrunk by the purge and
//          that the report says so honestly — plus the counterfactual that a store created in
//          incremental auto-vacuum mode does release freelist pages through the same bounded statement.
// Depends: ApplicationDataPurgeService, AuditDbContext, xunit
// Extends: Add the matching assertion whenever a new space-reclamation step is introduced on the
//          online path.

using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using RdpAudit.Core.Data;
using RdpAudit.Core.Ipc.Contracts;
using RdpAudit.Core.Models;
using RdpAudit.Service.Services;
using Xunit;

namespace RdpAudit.Service.Tests;

public sealed class ApplicationDataPurgeSpaceReclamationTests
{
	// ── Test doubles ─────────────────────────────────────────────────────────────

	private sealed class FileDbContextFactory : IDbContextFactory<AuditDbContext>
	{
		private readonly DbContextOptions<AuditDbContext> _options;

		public FileDbContextFactory(DbContextOptions<AuditDbContext> options) => _options = options;

		public AuditDbContext CreateDbContext() => new(_options);
	}

	// ── Statement composition ────────────────────────────────────────────────────

	/// <summary>Given the online purge path, when its post-commit statement list is built, then it
	/// carries the WAL checkpoint and the bounded incremental vacuum and NOTHING that could be a full
	/// VACUUM. This is the "assert on command composition" half of the acceptance criterion: the
	/// strongest available statement is that the service has no way to emit one.</summary>
	[Fact]
	public void SpaceReclamationStatements_ContainNoFullVacuum()
	{
		IReadOnlyList<string> statements =
			ApplicationDataPurgeService.BuildSpaceReclamationStatements(ApplicationDataPurgeService.IncrementalVacuumPages);

		Assert.Equal(2, statements.Count);
		Assert.Equal("PRAGMA wal_checkpoint(TRUNCATE);", statements[0]);
		Assert.Equal("PRAGMA incremental_vacuum(5000);", statements[1]);
		Assert.DoesNotContain(statements, statement =>
			statement.TrimStart().StartsWith("VACUUM", StringComparison.OrdinalIgnoreCase));
		Assert.All(statements, statement =>
			Assert.DoesNotContain("VACUUM;", statement, StringComparison.OrdinalIgnoreCase));
	}

	/// <summary>Given a caller asking for an unbounded vacuum, when the statement list is built, then the
	/// page budget is clamped to the shared maintenance ceiling so the writer-lock cost stays bounded.</summary>
	[Theory]
	[InlineData(0, 1)]
	[InlineData(-5, 1)]
	[InlineData(250, 250)]
	[InlineData(int.MaxValue, ApplicationDataPurgeService.IncrementalVacuumPages)]
	public void SpaceReclamationStatements_ClampThePageBudget(int requested, int expectedPages)
	{
		IReadOnlyList<string> statements = ApplicationDataPurgeService.BuildSpaceReclamationStatements(requested);

		Assert.Equal("PRAGMA incremental_vacuum(" + expectedPages + ");", statements[1]);
	}

	/// <summary>Given a store whose auto-vacuum mode is NONE, when the incremental vacuum releases
	/// nothing, then the report says exactly that instead of claiming the file shrank, and points at the
	/// offline compaction as the only remedy.</summary>
	[Fact]
	public void DescribeSpaceReclamation_WhenNothingWasReleased_SaysSoAndPointsAtOfflineCompaction()
	{
		string text = ApplicationDataPurgeService.DescribeSpaceReclamation(
			walCheckpointed: true,
			incrementalVacuumed: true,
			incrementalVacuumPages: 5000,
			freeListPagesBefore: 700,
			freeListPagesAfter: 700,
			reclaimedFreePages: 0);

		Assert.Contains("released nothing", text, StringComparison.Ordinal);
		Assert.Contains("not INCREMENTAL", text, StringComparison.Ordinal);
		Assert.Contains("offline compaction", text, StringComparison.Ordinal);
		Assert.Contains("No full VACUUM is run on the live store", text, StringComparison.Ordinal);
	}

	/// <summary>Given pages really were released, when the report is rendered, then it reports the
	/// observed number of pages rather than a promise.</summary>
	[Fact]
	public void DescribeSpaceReclamation_WhenPagesWereReleased_ReportsTheObservedCount()
	{
		string text = ApplicationDataPurgeService.DescribeSpaceReclamation(
			walCheckpointed: true,
			incrementalVacuumed: true,
			incrementalVacuumPages: 5000,
			freeListPagesBefore: 700,
			freeListPagesAfter: 40,
			reclaimedFreePages: 660);

		Assert.Contains("returned 660 freelist page(s)", text, StringComparison.Ordinal);
		Assert.DoesNotContain("released nothing", text, StringComparison.Ordinal);
	}

	// ── Behaviour on a real file ─────────────────────────────────────────────────

	/// <summary>Given a file-backed store created without incremental auto-vacuum, when the purge runs
	/// with several thousand rows, then the database file is not shrunk (a full VACUUM would have shrunk
	/// it), the freelist survives, and the report states the honest reason. This is the reproduction of
	/// the behaviour the requirement asks for, with the file length as the observable.</summary>
	[Fact]
	public async Task PurgeAllAsync_OnPlainStore_DoesNotShrinkTheFile_AndReportsWhy()
	{
		string directory = CreateTempDirectory();
		string databasePath = Path.Combine(directory, "rdpaudit.db");
		try
		{
			(IDbContextFactory<AuditDbContext> factory, SqliteConnection connection) =
				await CreateFileDbAsync(databasePath, incrementalAutoVacuum: false);
			await using (connection.ConfigureAwait(false))
			{
				await SeedRawEventsAsync(factory, 4_000);
				SqliteConnection.ClearAllPools();
				long bytesBefore = new FileInfo(databasePath).Length;
				Assert.True(bytesBefore > 0, "the fixture must produce a non-empty database file");

				ApplicationDataPurgeService service = MakeService(factory);
				AppDataPurgeResultDto result = await service.PurgeAllAsync(CancellationToken.None);

				Assert.Equal(IpcResultStatus.Success, result.Status);
				Assert.True(result.WalCheckpointed);
				Assert.True(result.IncrementalVacuumed);
				Assert.False(result.DatabaseVacuumed);

				SqliteConnection.ClearAllPools();
				long bytesAfter = new FileInfo(databasePath).Length;
				Assert.True(
					bytesAfter >= bytesBefore,
					"the online purge must not shrink the database file (a full VACUUM would have); "
						+ "before=" + bytesBefore + " after=" + bytesAfter);

				// On a store with auto-vacuum NONE the freed pages stay inside the file, and the report
				// must say so rather than claim a reclaim that did not happen.
				Assert.Equal(0, result.ReclaimedFreePages);
				Assert.Contains("No full VACUUM", result.SpaceReclamation, StringComparison.Ordinal);
				Assert.Equal(0, await CountRawEventsAsync(factory));
			}
		}
		finally
		{
			SqliteConnection.ClearAllPools();
			DeleteDirectory(directory);
		}
	}

	/// <summary>Counterfactual to the previous test: given the SAME purge code path against a store
	/// created in incremental auto-vacuum mode, the bounded incremental vacuum does release the freed
	/// pages and the file does shrink — so the non-shrinking result above is a property of the store's
	/// auto-vacuum mode, not of a step that never ran.</summary>
	[Fact]
	public async Task PurgeAllAsync_OnIncrementalAutoVacuumStore_ReleasesFreelistPages()
	{
		string directory = CreateTempDirectory();
		string databasePath = Path.Combine(directory, "rdpaudit.db");
		try
		{
			(IDbContextFactory<AuditDbContext> factory, SqliteConnection connection) =
				await CreateFileDbAsync(databasePath, incrementalAutoVacuum: true);
			await using (connection.ConfigureAwait(false))
			{
				await SeedRawEventsAsync(factory, 4_000);
				SqliteConnection.ClearAllPools();
				long bytesBefore = new FileInfo(databasePath).Length;

				ApplicationDataPurgeService service = MakeService(factory);
				AppDataPurgeResultDto result = await service.PurgeAllAsync(CancellationToken.None);

				Assert.Equal(IpcResultStatus.Success, result.Status);
				Assert.True(result.IncrementalVacuumed);
				Assert.False(result.DatabaseVacuumed);
				Assert.True(
					result.FreeListPagesBefore > 0,
					"the fixture must leave free pages behind for the counterfactual to be meaningful");
				Assert.True(
					result.ReclaimedFreePages > 0,
					"incremental auto-vacuum must release the freed pages; "
						+ "before=" + result.FreeListPagesBefore + " after=" + result.FreeListPagesAfter);
				Assert.Contains("returned", result.SpaceReclamation, StringComparison.Ordinal);

				SqliteConnection.ClearAllPools();
				long bytesAfter = new FileInfo(databasePath).Length;
				Assert.True(
					bytesAfter < bytesBefore,
					"a store in incremental auto-vacuum mode must shrink after the purge; "
						+ "before=" + bytesBefore + " after=" + bytesAfter);
				Assert.Equal(0, await CountRawEventsAsync(factory));
			}
		}
		finally
		{
			SqliteConnection.ClearAllPools();
			DeleteDirectory(directory);
		}
	}

	// ── Fixture helpers ──────────────────────────────────────────────────────────

	private static ApplicationDataPurgeService MakeService(IDbContextFactory<AuditDbContext> factory) =>
		new(factory, NullLogger<ApplicationDataPurgeService>.Instance, TimeProvider.System);

	/// <summary>Creates a file-backed store. When <paramref name="incrementalAutoVacuum"/> is true the
	/// pragma is set on the connection BEFORE the schema exists, which is the only point at which SQLite
	/// writes the auto-vacuum mode into the file header.</summary>
	private static async Task<(IDbContextFactory<AuditDbContext>, SqliteConnection)> CreateFileDbAsync(
		string databasePath,
		bool incrementalAutoVacuum)
	{
		SqliteConnection connection = new("DataSource=" + databasePath);
		await connection.OpenAsync();

		if (incrementalAutoVacuum)
		{
			await using SqliteCommand pragma = connection.CreateCommand();
			pragma.CommandText = "PRAGMA auto_vacuum = INCREMENTAL;";
			await pragma.ExecuteNonQueryAsync();
		}

		DbContextOptions<AuditDbContext> options = new DbContextOptionsBuilder<AuditDbContext>()
			.UseSqlite(connection)
			.Options;

		await using (AuditDbContext init = new(options))
		{
			await init.Database.EnsureCreatedAsync();
		}

		return (new FileDbContextFactory(options), connection);
	}

	/// <summary>Seeds enough detail rows that the file is several megabytes, so a released freelist is
	/// measurable in bytes rather than lost in page-granularity rounding.</summary>
	private static async Task SeedRawEventsAsync(IDbContextFactory<AuditDbContext> factory, int count)
	{
		string detail = new('x', 600);
		await using AuditDbContext db = factory.CreateDbContext();
		for (int index = 0; index < count; index++)
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
	}

	private static async Task<int> CountRawEventsAsync(IDbContextFactory<AuditDbContext> factory)
	{
		await using AuditDbContext db = factory.CreateDbContext();
		return await db.RawEvents.CountAsync();
	}

	private static string CreateTempDirectory()
	{
		string directory = Path.Combine(Path.GetTempPath(), "rdpaudit-purge-" + Guid.NewGuid().ToString("N"));
		Directory.CreateDirectory(directory);
		return directory;
	}

	private static void DeleteDirectory(string directory)
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
			// Best effort: a leaked temp folder must never fail the assertion.
		}
		catch (UnauthorizedAccessException)
		{
			// Best effort.
		}
	}
}
