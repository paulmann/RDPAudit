/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 1.0.0
// File   : AutoVacuumModeTests.cs
// Project: RdpAudit.Service.Tests
// Purpose: Pins the auto-vacuum mode of the stores this product creates (B27). The online
//          space-reclamation path is a bounded PRAGMA incremental_vacuum, and that statement releases
//          nothing at all unless the store's header carries auto_vacuum = INCREMENTAL. SQLite honours an
//          auto_vacuum change immediately only while the database still has no pages, and
//          `journal_mode = WAL` is the statement that creates page 1 - so the mode of a brand-new store
//          is decided by the ORDER of the two statements in SqlitePragmaInterceptor's batch, and by
//          nothing else. Four facts are pinned here:
//          (1) a store created the product's way (AuditDbInitializer over the interceptor) ends in mode
//              INCREMENTAL - the regression anchor for the whole bug;
//          (2) on such a store the bounded incremental_vacuum really does release free pages and shrink
//              the file, so the test fails if the interceptor's order is ever rolled back;
//          (3) on an EXISTING store neither order changes the mode observably - the pragma can only
//              become pending there, and only a full VACUUM applies it (an offline operator action;
//              see DatabaseCompactService, which now normalises the mode of the store it rewrites);
//          (4) the counterfactual that makes (1) meaningful: the retired WAL-first order leaves a FRESH
//              store in mode NONE, which is the measurement B27 was reported from;
//          (5) the operator can SEE the mode and the freelist in the Database-tab overview, together with
//              the sentence that says whether online release is possible on that store and, when it is
//              not, that the offline compaction is the only way out;
//          (6) the maintenance report tells the truth about what the bounded incremental vacuum released
//              (the statement returns no result rows either way, so the step must measure the freelist) and
//              names the mode when it released nothing.
// Depends: AuditDbInitializer, AuditDbContextOptionsFactory, SqlitePragmaInterceptor, AuditDbContext,
//          DatabaseOverviewService, Microsoft.Data.Sqlite, xUnit
// Extends: Add an assertion here whenever the connection-time pragma batch gains a statement whose
//          effect depends on the store already having pages.

using System.Globalization;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using RdpAudit.Core.Config;
using RdpAudit.Core.Data;
using RdpAudit.Core.Ipc.Contracts;
using RdpAudit.Core.Models;
using RdpAudit.Service.Services;
using Xunit;

namespace RdpAudit.Service.Tests;

public sealed class AutoVacuumModeTests
{
	// ── SQLite facts this suite is built on ──────────────────────────────────────

	/// <summary>The value <c>PRAGMA auto_vacuum</c> reports for a store in incremental mode.</summary>
	private const int IncrementalMode = 2;

	/// <summary>The value it reports for a store with no auto-vacuum at all - the mode B27 was reported
	/// from, because <c>incremental_vacuum</c> is a documented no-op there.</summary>
	private const int NoAutoVacuumMode = 0;

	/// <summary>The statement batch SqlitePragmaInterceptor ships: <c>auto_vacuum</c> FIRST, before
	/// <c>journal_mode = WAL</c> materialises page 1 of a new store.</summary>
	private const string ProductOrderBatch =
		"PRAGMA auto_vacuum  = INCREMENTAL;" +
		"PRAGMA journal_mode = WAL;" +
		"PRAGMA synchronous  = NORMAL;" +
		"PRAGMA cache_size   = -32000;" +
		"PRAGMA foreign_keys = ON;" +
		"PRAGMA temp_store   = MEMORY;";

	/// <summary>The RETIRED order - WAL first, auto_vacuum last. Kept verbatim as the counterfactual that
	/// proves the order is the mechanism (measured on SQLite 3.41.2: this is what leaves a fresh store in
	/// mode NONE). It must never be reintroduced; the product's batch lives in
	/// <c>SqlitePragmaInterceptor</c>, not here.</summary>
	private const string RetiredOrderBatch =
		"PRAGMA journal_mode = WAL;" +
		"PRAGMA synchronous  = NORMAL;" +
		"PRAGMA cache_size   = -32000;" +
		"PRAGMA foreign_keys = ON;" +
		"PRAGMA auto_vacuum  = INCREMENTAL;" +
		"PRAGMA temp_store   = MEMORY;";

	/// <summary>Rows the release test seeds. Sized so the free pages a delete leaves behind are worth
	/// thousands of pages, i.e. measurable as released pages and as file bytes rather than lost in page
	/// granularity.</summary>
	private const int SeededRows = 20_000;

	// ── Test double ──────────────────────────────────────────────────────────────

	private sealed class StoreFactory : IDbContextFactory<AuditDbContext>
	{
		private readonly DbContextOptions<AuditDbContext> _options;

		public StoreFactory(DbContextOptions<AuditDbContext> options) => _options = options;

		public AuditDbContext CreateDbContext() => new(_options);
	}

	// ── (1) Regression anchor ────────────────────────────────────────────────────

	/// <summary>Given the product's own creation path (AuditDbInitializer over the interceptor's batch),
	/// when a brand-new store is created, then its header carries auto_vacuum = INCREMENTAL. This is the
	/// anchor for B27: if the interceptor's statement order regresses, the fresh store comes out in mode
	/// NONE and every online space-reclamation step silently becomes a no-op again.</summary>
	[Fact]
	public async Task FreshStore_CreatedByTheProductPath_StartsInIncrementalAutoVacuumMode()
	{
		string directory = CreateTempDirectory();
		string databasePath = Path.Combine(directory, "rdpaudit.db");
		try
		{
			await CreateProductStoreAsync(databasePath);

			Assert.Equal(IncrementalMode, ReadPragma(databasePath, "PRAGMA auto_vacuum;"));
			Assert.Equal("wal", ReadPragmaText(databasePath, "PRAGMA journal_mode;"), ignoreCase: true);

			// The same reading through the interceptor's own connection: this is the value the Overview's
			// page-accounting section reports, so it must not differ from what a fresh reader sees.
			DbContextOptions<AuditDbContext> options =
				AuditDbContextOptionsFactory.Create(databasePath, new SqlitePragmaInterceptor());
			await using AuditDbContext db = new(options);
			await db.Database.OpenConnectionAsync();
			Assert.Equal(
				IncrementalMode.ToString(CultureInfo.InvariantCulture),
				Scalar(db.Database.GetDbConnection(), "PRAGMA auto_vacuum;"));
			Assert.Equal("ok", DatabaseSnapshotQuickCheck(databasePath));
		}
		finally
		{
			DeleteDirectory(directory);
		}
	}

	// ── (2) The behaviour the mode exists for ────────────────────────────────────

	/// <summary>Given a store the product created, when rows are deleted and the online reclamation steps
	/// run (exactly the pair the purge and the maintenance surface issue), then the freed pages really are
	/// handed back and the file really shrinks. On a store in mode NONE the very same statements release
	/// nothing (which is the counterfactual asserted in the mechanism test below), so this test fails if
	/// the interceptor's order is rolled back - it is the behavioural half of the B27 fix.</summary>
	[Fact]
	public async Task IncrementalVacuum_OnAProductCreatedStore_ReleasesFreePagesAndShrinksTheFile()
	{
		string directory = CreateTempDirectory();
		string databasePath = Path.Combine(directory, "rdpaudit.db");
		try
		{
			await CreateProductStoreAsync(databasePath);
			DbContextOptions<AuditDbContext> options =
				AuditDbContextOptionsFactory.Create(databasePath, new SqlitePragmaInterceptor());

			await SeedRawEventsAsync(options, SeededRows);
			await DeleteNewestHalfAsync(options);
			SqliteConnection.ClearAllPools();

			long freePagesBefore = ReadPragma(databasePath, "PRAGMA freelist_count;");
			long bytesBefore = Bytes(databasePath);
			Assert.True(
				freePagesBefore > 0,
				"the fixture must leave free pages behind, otherwise this test cannot observe a release");

			RunSpaceReclamation(databasePath);

			long freePagesAfter = ReadPragma(databasePath, "PRAGMA freelist_count;");
			long bytesAfter = Bytes(databasePath);

			// Deliberately no assertion on the mode itself: this test asserts the BEHAVIOUR the mode
			// exists for, so it fails on its own terms when the store is not in incremental mode - with
			// the interceptor's statement order rolled back, the very same statements release nothing.
			Assert.True(
				freePagesAfter < freePagesBefore,
				"a store in incremental auto-vacuum mode must release free pages: before="
					+ freePagesBefore + " after=" + freePagesAfter);
			Assert.True(
				bytesAfter < bytesBefore,
				"the released pages must actually leave the file: before=" + bytesBefore + " after=" + bytesAfter);
			Assert.Equal("ok", DatabaseSnapshotQuickCheck(databasePath));
		}
		finally
		{
			DeleteDirectory(directory);
		}
	}

	// ── (3) Existing stores are not touched either way ───────────────────────────

	/// <summary>Given an EXISTING store in mode NONE or in mode INCREMENTAL, when the connection-time
	/// batch runs against it in either order, then the store keeps the mode it had, stays in WAL and stays
	/// intact. On a store that already has pages the pragma can only ever become PENDING, and only a full
	/// VACUUM applies a pending mode - so this is the expectation, not a defect: the interceptor neither
	/// repairs a legacy store nor breaks a newer one. Repairing a legacy store is the offline compaction's
	/// job (<c>DatabaseCompactService</c>).</summary>
	[Theory]
	[InlineData(NoAutoVacuumMode, false)]
	[InlineData(NoAutoVacuumMode, true)]
	[InlineData(IncrementalMode, false)]
	[InlineData(IncrementalMode, true)]
	public async Task ExistingStore_KeepsItsAutoVacuumMode_WhicheverOrderTheBatchUses(int startingMode, bool autoVacuumFirst)
	{
		string directory = CreateTempDirectory();
		string databasePath = Path.Combine(directory, "rdpaudit.db");
		try
		{
			await CreateExistingStoreAsync(databasePath, startingMode);
			Assert.Equal(startingMode, ReadPragma(databasePath, "PRAGMA auto_vacuum;"));

			using (SqliteConnection connection = OpenRaw(databasePath))
			{
				Execute(connection, autoVacuumFirst ? ProductOrderBatch : RetiredOrderBatch);
			}

			SqliteConnection.ClearAllPools();
			Assert.Equal(startingMode, ReadPragma(databasePath, "PRAGMA auto_vacuum;"));
			Assert.Equal("wal", ReadPragmaText(databasePath, "PRAGMA journal_mode;"), ignoreCase: true);
			Assert.Equal("ok", DatabaseSnapshotQuickCheck(databasePath));
		}
		finally
		{
			DeleteDirectory(directory);
		}
	}

	/// <summary>Given an existing legacy store in mode NONE, when the product opens it through its own
	/// interceptor (the upgrade path), then the store still reports mode NONE afterwards: every connection
	/// merely schedules a pending change it never applies. The Overview therefore has to SHOW that mode,
	/// because otherwise the operator would read "incremental_vacuum released nothing" as a bug instead of
	/// as the documented consequence of the store's header.</summary>
	[Fact]
	public async Task ExistingLegacyStore_OpenedThroughTheProductInterceptor_StillReportsModeNone()
	{
		string directory = CreateTempDirectory();
		string databasePath = Path.Combine(directory, "rdpaudit.db");
		try
		{
			await CreateExistingStoreAsync(databasePath, NoAutoVacuumMode);

			DbContextOptions<AuditDbContext> options =
				AuditDbContextOptionsFactory.Create(databasePath, new SqlitePragmaInterceptor());
			await using (AuditDbContext db = new(options))
			{
				await db.Database.OpenConnectionAsync();
				Assert.Equal(
					NoAutoVacuumMode.ToString(CultureInfo.InvariantCulture),
					Scalar(db.Database.GetDbConnection(), "PRAGMA auto_vacuum;"));
			}

			SqliteConnection.ClearAllPools();
			Assert.Equal(NoAutoVacuumMode, ReadPragma(databasePath, "PRAGMA auto_vacuum;"));

			// And the online reclamation pair is a measured no-op there - the same statement that releases
			// thousands of pages on a product-created store. This is why a legacy store needs the offline
			// rewrite, and why the product must not promise online reclamation for it.
			await using (AuditDbContext db = new(options))
			{
				await SeedRawEventsAsync(db, SeededRows);
			}

			await DeleteNewestHalfAsync(options);
			SqliteConnection.ClearAllPools();
			long freePagesBefore = ReadPragma(databasePath, "PRAGMA freelist_count;");
			RunSpaceReclamation(databasePath);
			long freePagesAfter = ReadPragma(databasePath, "PRAGMA freelist_count;");

			Assert.True(freePagesBefore > 0, "the fixture must produce a non-empty freelist");
			Assert.Equal(freePagesBefore, freePagesAfter);
		}
		finally
		{
			DeleteDirectory(directory);
		}
	}

	// ── (4) The mechanism, measured ──────────────────────────────────────────────

	/// <summary>Given a brand-new store, when the connection-time batch is applied before the schema
	/// exists, then the resulting mode is decided by the ORDER of the two statements and by nothing else:
	/// with <c>journal_mode = WAL</c> first the store comes out in mode NONE (the B27 symptom), with
	/// <c>auto_vacuum</c> first it comes out in INCREMENTAL (the fix). Both halves are asserted, so a
	/// regression in the shipped order cannot pass unnoticed, and the dependency on the order is explicit
	/// here instead of hidden in a fixture.</summary>
	[Theory]
	[InlineData(false, NoAutoVacuumMode)]
	[InlineData(true, IncrementalMode)]
	public async Task FreshStore_AutoVacuumModeIsDecidedByTheStatementOrder(bool autoVacuumFirst, int expectedMode)
	{
		string directory = CreateTempDirectory();
		string databasePath = Path.Combine(directory, "rdpaudit.db");
		try
		{
			using (SqliteConnection connection = OpenRaw(databasePath))
			{
				Execute(connection, autoVacuumFirst ? ProductOrderBatch : RetiredOrderBatch);
				DbContextOptions<AuditDbContext> options = new DbContextOptionsBuilder<AuditDbContext>()
					.UseSqlite(connection)
					.Options;
				await using AuditDbContext db = new(options);
				await db.Database.MigrateAsync();
			}

			SqliteConnection.ClearAllPools();
			Assert.Equal(expectedMode, ReadPragma(databasePath, "PRAGMA auto_vacuum;"));
		}
		finally
		{
			DeleteDirectory(directory);
		}
	}

	// ── (5) What the operator can see (B16 remediation) ──────────────────────────

	/// <summary>Given a store the product created, when the Database-tab overview is built, then it states
	/// the store's auto-vacuum mode, its page accounting and that online reclamation is available - so an
	/// operator reading "the purge released nothing" can tell a broken purge from a store whose header
	/// never allowed the release in the first place.</summary>
	[Fact]
	public async Task Overview_OnAFreshProductStore_ReportsIncrementalModeAndOnlineReclamation()
	{
		string directory = CreateTempDirectory();
		string databasePath = Path.Combine(directory, "rdpaudit.db");
		try
		{
			await CreateProductStoreAsync(databasePath);

			DatabaseOverviewDto overview = await BuildOverviewAsync(databasePath);

			Assert.Equal(IncrementalMode, overview.AutoVacuumMode);
			Assert.Equal("wal", overview.JournalMode, ignoreCase: true);
			Assert.Equal(4096, overview.PageSize);
			Assert.True(overview.PageCount > 0, "a store with a schema must report its pages");
			Assert.Equal(0, overview.FreeListPages);
			Assert.Equal(0, overview.ReclaimableBytes);
			Assert.NotNull(overview.SpaceReclamationNote);
			Assert.Contains("Online reclamation is available", overview.SpaceReclamationNote!, StringComparison.Ordinal);
			Assert.Contains(
				overview.Sections,
				section => section.Section == "StorePages" && section.Status == "Completed");
		}
		finally
		{
			DeleteDirectory(directory);
		}
	}

	/// <summary>Given a legacy store in mode NONE that already holds free pages, when the overview is
	/// built, then it names the mode, the free pages and the bytes allocated to them, and says in plain
	/// words that online release is impossible on this store and that the offline compaction - which also
	/// rewrites it into INCREMENTAL - is the way out. The hint is the operator-facing half of B27: without
	/// it the honest "released nothing" report looks like a defect instead of a property of the store.</summary>
	[Fact]
	public async Task Overview_OnALegacyStoreWithFreePages_ReportsModeNoneAndTheOfflineRoute()
	{
		string directory = CreateTempDirectory();
		string databasePath = Path.Combine(directory, "rdpaudit.db");
		try
		{
			await CreateExistingStoreAsync(databasePath, NoAutoVacuumMode);
			DbContextOptions<AuditDbContext> options =
				AuditDbContextOptionsFactory.Create(databasePath, new SqlitePragmaInterceptor());
			await SeedRawEventsAsync(options, 4_000);
			await DeleteNewestHalfAsync(options);
			SqliteConnection.ClearAllPools();

			DatabaseOverviewDto overview = await BuildOverviewAsync(databasePath);

			Assert.Equal(NoAutoVacuumMode, overview.AutoVacuumMode);
			Assert.NotNull(overview.FreeListPages);
			Assert.True(overview.FreeListPages > 0, "the fixture must leave free pages inside the file");
			Assert.Equal(overview.PageSize * overview.FreeListPages, overview.ReclaimableBytes);
			Assert.NotNull(overview.SpaceReclamationNote);
			Assert.Contains("ONLINE RELEASE IS NOT POSSIBLE", overview.SpaceReclamationNote!, StringComparison.Ordinal);
			Assert.Contains("Compact database (offline)", overview.SpaceReclamationNote!, StringComparison.Ordinal);
			Assert.Contains("INCREMENTAL mode", overview.SpaceReclamationNote!, StringComparison.Ordinal);
		}
		finally
		{
			DeleteDirectory(directory);
		}
	}

	// ── (6) The maintenance report measures, it does not guess ───────────────────

	/// <summary>Given a store in incremental mode with free pages, when the operator runs the bounded
	/// incremental vacuum from the Database tab, then the report states the number of pages that were
	/// actually released. <c>PRAGMA incremental_vacuum(N)</c> returns NO result rows (measured on SQLite
	/// 3.41.2) whether it released five pages or five thousand, so a report built from those rows said "no
	/// free pages to release" on a store that had just released pages; the step measures the freelist depth
	/// instead, which is what this test pins.</summary>
	[Fact]
	public async Task MaintenanceReport_ReportsThePagesTheIncrementalVacuumActuallyReleased()
	{
		string directory = CreateTempDirectory();
		string databasePath = Path.Combine(directory, "rdpaudit.db");
		try
		{
			await CreateProductStoreAsync(databasePath);
			DbContextOptions<AuditDbContext> options =
				AuditDbContextOptionsFactory.Create(databasePath, new SqlitePragmaInterceptor());
			await SeedRawEventsAsync(options, 4_000);
			await DeleteNewestHalfAsync(options);
			SqliteConnection.ClearAllPools();
			long freePagesBefore = ReadPragma(databasePath, "PRAGMA freelist_count;");
			Assert.True(freePagesBefore > 0, "the fixture must leave free pages inside the file");

			DatabaseMaintenanceReportDto report = await RunIncrementalVacuumAsync(databasePath);

			DatabaseMaintenanceStepDto step = Assert.Single(report.Steps);
			Assert.Equal("Completed", step.Outcome);
			Assert.StartsWith("freedPages=", step.Detail, StringComparison.Ordinal);
			Assert.DoesNotContain("Released nothing", step.Detail, StringComparison.Ordinal);
			SqliteConnection.ClearAllPools();
			Assert.True(ReadPragma(databasePath, "PRAGMA freelist_count;") < freePagesBefore);
		}
		finally
		{
			DeleteDirectory(directory);
		}
	}

	/// <summary>Given a legacy store in mode NONE with free pages, when the same action runs, then the
	/// report says it released nothing AND why - naming the mode and the offline compaction - instead of the
	/// bare "no free pages to release" that would read as "there is nothing to reclaim here" while thousands
	/// of free pages sit inside the file.</summary>
	[Fact]
	public async Task MaintenanceReport_OnALegacyStore_NamesTheModeInsteadOfClaimingNothingToRelease()
	{
		string directory = CreateTempDirectory();
		string databasePath = Path.Combine(directory, "rdpaudit.db");
		try
		{
			await CreateExistingStoreAsync(databasePath, NoAutoVacuumMode);
			DbContextOptions<AuditDbContext> options =
				AuditDbContextOptionsFactory.Create(databasePath, new SqlitePragmaInterceptor());
			await SeedRawEventsAsync(options, 4_000);
			await DeleteNewestHalfAsync(options);
			SqliteConnection.ClearAllPools();
			Assert.True(ReadPragma(databasePath, "PRAGMA freelist_count;") > 0);

			DatabaseMaintenanceReportDto report = await RunIncrementalVacuumAsync(databasePath);

			DatabaseMaintenanceStepDto step = Assert.Single(report.Steps);
			Assert.Equal("Completed", step.Outcome);
			Assert.Contains("Released nothing although", step.Detail, StringComparison.Ordinal);
			Assert.Contains("not INCREMENTAL", step.Detail, StringComparison.Ordinal);
			Assert.Contains("Compact database (offline)", step.Detail, StringComparison.Ordinal);
			Assert.DoesNotContain("freelist is empty", step.Detail, StringComparison.Ordinal);
		}
		finally
		{
			DeleteDirectory(directory);
		}
	}

	// ── Overview fixture ─────────────────────────────────────────────────────────

	/// <summary>Runs the real maintenance action (the one the Database tab's "Incremental vacuum" button
	/// issues) against a file-backed store and returns its report.</summary>
	private static async Task<DatabaseMaintenanceReportDto> RunIncrementalVacuumAsync(string databasePath)
	{
		DbContextOptions<AuditDbContext> options =
			AuditDbContextOptionsFactory.Create(databasePath, new SqlitePragmaInterceptor());
		RdpAuditOptions auditOptions = new()
		{
			Storage = new StorageOptions { DatabasePath = databasePath },
		};
		DatabaseMaintenanceService service = new(
			new StoreFactory(options),
			new StaticOptionsMonitor(auditOptions),
			NullLogger<DatabaseMaintenanceService>.Instance);
		return await service.RunAsync(
			new DatabaseMaintenanceRequest { Kind = DatabaseMaintenanceKind.IncrementalVacuum },
			CancellationToken.None);
	}

	/// <summary>Builds the real overview over a file-backed store, through the same factory the service
	/// uses (write path plus the interceptor), so the pragma readings are taken exactly as the Database tab
	/// takes them.</summary>
	private static async Task<DatabaseOverviewDto> BuildOverviewAsync(string databasePath)
	{
		DbContextOptions<AuditDbContext> options =
			AuditDbContextOptionsFactory.Create(databasePath, new SqlitePragmaInterceptor());
		RdpAuditOptions auditOptions = new()
		{
			Storage = new StorageOptions { DatabasePath = databasePath },
		};
		DatabaseOverviewService service = new(
			new StoreFactory(options),
			new StaticOptionsMonitor(auditOptions),
			NullLogger<DatabaseOverviewService>.Instance);
		return await service.BuildAsync(CancellationToken.None);
	}

	private sealed class StaticOptionsMonitor : IOptionsMonitor<RdpAuditOptions>
	{
		private readonly RdpAuditOptions _options;

		public StaticOptionsMonitor(RdpAuditOptions options) => _options = options;

		public RdpAuditOptions CurrentValue => _options;

		public RdpAuditOptions Get(string? name) => _options;

		public IDisposable? OnChange(Action<RdpAuditOptions, string?> listener) => null;
	}

	// ── Fixtures ─────────────────────────────────────────────────────────────────

	/// <summary>Creates a store exactly the way the product does: options built by
	/// <see cref="AuditDbContextOptionsFactory"/> with the write-enabling interceptor, initialized by
	/// <see cref="AuditDbInitializer"/> so the schema is applied by migrations.</summary>
	private static async Task CreateProductStoreAsync(string databasePath)
	{
		DbContextOptions<AuditDbContext> options =
			AuditDbContextOptionsFactory.Create(databasePath, new SqlitePragmaInterceptor());
		using AuditDbInitializer initializer = new(
			new StoreFactory(options),
			NullLogger<AuditDbInitializer>.Instance);
		await initializer.EnsureCreatedAsync(CancellationToken.None);
	}

	/// <summary>Creates a store that already has pages before any batch runs, in the requested
	/// auto-vacuum mode: the mode is set on the connection BEFORE the schema exists, which is the only
	/// point at which SQLite writes it into the file header (there is no interceptor here, so the fixture
	/// is independent of the order the interceptor uses).</summary>
	private static async Task CreateExistingStoreAsync(string databasePath, int mode)
	{
		using SqliteConnection connection = OpenRaw(databasePath);
		if (mode != NoAutoVacuumMode)
		{
			Execute(connection, "PRAGMA auto_vacuum = INCREMENTAL;");
		}

		DbContextOptions<AuditDbContext> options = new DbContextOptionsBuilder<AuditDbContext>()
			.UseSqlite(connection)
			.Options;
		await using AuditDbContext db = new(options);
		await db.Database.EnsureCreatedAsync();
	}

	/// <summary>Seeds detail rows large enough that the file is several megabytes, so a released freelist
	/// is measurable in bytes rather than lost in page granularity.</summary>
	private static async Task SeedRawEventsAsync(DbContextOptions<AuditDbContext> options, int rows)
	{
		string detail = new('x', 600);
		for (int chunk = 0; chunk < rows; chunk += 10_000)
		{
			await using AuditDbContext db = new(options);
			for (int index = 0; index < 10_000 && chunk + index < rows; index++)
			{
				db.RawEvents.Add(new RawEvent
				{
					Channel = "Security",
					EventId = 4625,
					TimeUtc = DateTime.UtcNow.AddSeconds(-(chunk + index)),
					Details = detail,
				});
			}

			await db.SaveChangesAsync();
		}
	}

	private static async Task SeedRawEventsAsync(AuditDbContext db, int rows)
	{
		string detail = new('x', 600);
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
	}

	/// <summary>Deletes a contiguous chunk (the newest half by timestamp), which leaves whole free pages
	/// behind regardless of the id parity an earlier delete would have left.</summary>
	private static async Task DeleteNewestHalfAsync(DbContextOptions<AuditDbContext> options)
	{
		await using AuditDbContext db = new(options);
		int total = await db.RawEvents.CountAsync();
		Assert.True(total > 1, "the fixture must have rows to delete");
		DateTime cutoff = await db.RawEvents
			.OrderByDescending(row => row.TimeUtc)
			.Select(row => row.TimeUtc)
			.Skip(total / 2)
			.FirstAsync();
		await db.RawEvents.Where(row => row.TimeUtc > cutoff).ExecuteDeleteAsync();
	}

	/// <summary>Runs the exact pair the online reclamation paths issue after a delete: a TRUNCATE
	/// checkpoint, then the bounded incremental vacuum. Deliberately a literal, so the assertion is about
	/// SQLite's behaviour and not about a helper the product could change underneath the test.</summary>
	private static void RunSpaceReclamation(string databasePath)
	{
		using SqliteConnection connection = OpenRaw(databasePath);
		Execute(connection, "PRAGMA wal_checkpoint(TRUNCATE);");
		Execute(connection, "PRAGMA incremental_vacuum(5000);");
	}

	private static string DatabaseSnapshotQuickCheck(string databasePath)
		=> RdpAudit.Core.Backup.DatabaseSnapshotVerifier.RunQuickCheck(databasePath, CancellationToken.None);

	// ── Raw SQLite helpers (no interceptor, no EF) ───────────────────────────────

	/// <summary>Opens a NON-POOLED connection: a pooled one keeps a Win32 handle on the file after
	/// Dispose, which turns this suite's temp-directory cleanup into a flaky failure.</summary>
	private static SqliteConnection OpenRaw(string databasePath)
	{
		SqliteConnection connection = new(
			new SqliteConnectionStringBuilder { DataSource = databasePath, Pooling = false }.ToString());
		connection.Open();
		return connection;
	}

	private static void Execute(SqliteConnection connection, string sql)
	{
		using SqliteCommand command = connection.CreateCommand();
#pragma warning disable CA2100 // Every statement is a literal defined in this file.
		command.CommandText = sql;
#pragma warning restore CA2100
		command.ExecuteNonQuery();
	}

	private static long ReadPragma(string databasePath, string pragma)
		=> long.Parse(Scalar(databasePath, pragma), CultureInfo.InvariantCulture);

	private static string ReadPragmaText(string databasePath, string pragma) => Scalar(databasePath, pragma);

	private static string Scalar(string databasePath, string pragma)
	{
		using SqliteConnection connection = OpenRaw(databasePath);
		object? value = Scalar(connection, pragma);
		return value is null or DBNull ? "(null)" : Convert.ToString(value, CultureInfo.InvariantCulture) ?? "(null)";
	}

	private static string Scalar(System.Data.Common.DbConnection connection, string pragma)
	{
		using System.Data.Common.DbCommand command = connection.CreateCommand();
#pragma warning disable CA2100 // Every statement is a literal defined in this file.
		command.CommandText = pragma;
#pragma warning restore CA2100
		object? value = command.ExecuteScalar();
		return value is null or DBNull ? "(null)" : Convert.ToString(value, CultureInfo.InvariantCulture) ?? "(null)";
	}

	private static long Bytes(string path) => File.Exists(path) ? new FileInfo(path).Length : -1;

	private static string CreateTempDirectory()
	{
		string directory = Path.Combine(Path.GetTempPath(), "rdpaudit-autovacuum-" + Guid.NewGuid().ToString("N"));
		Directory.CreateDirectory(directory);
		return directory;
	}

	/// <summary>Removes the temp store. Pooling is cleared first because EF and the raw connections in
	/// this suite both hold handles on the file until the pools are drained.</summary>
	private static void DeleteDirectory(string directory)
	{
		SqliteConnection.ClearAllPools();
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
