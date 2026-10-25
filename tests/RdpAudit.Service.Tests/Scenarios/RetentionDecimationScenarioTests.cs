/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 2.0.0
// File   : RetentionDecimationScenarioTests.cs
// Project: RdpAudit.Service.Tests (RdpAudit.Service.Tests.Scenarios)
// Purpose: Tier-3 scenario tests for Storage.Decimation, driven through RetentionWorker.RunOnceAsync -
//          the same entry point the production minute tick invokes. Each scenario walks the system
//          like an administrator would:
//          1. Happy path - a night of brute-force 4625 traffic from one IP is compacted to the head
//             and tail of every burst, and a second retention tick changes nothing (converged).
//          2. Rare-event preservation - low-volume 4776 evidence from the same IP stays whole while
//             the hot 4625 event id is decimated.
//          3. Cross-IP isolation - a second IP that produced only ten rows of the same event id is
//             left untouched.
// Depends: RetentionWorker, RawEventDecimationEngine, DecimationOptions, AuditDbContext
// Extends: Add a mixed-channel scenario when decimation gains per-event overrides.

using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using RdpAudit.Core.Config;
using RdpAudit.Core.Data;
using RdpAudit.Core.Models;
using RdpAudit.Service.Workers;
using Xunit;

namespace RdpAudit.Service.Tests.Scenarios;

/// <summary>Administrator-level retention-decimation scenarios driven through
/// <see cref="RetentionWorker.RunOnceAsync"/> against a real in-memory SQLite database.</summary>
public sealed class RetentionDecimationScenarioTests
{
	private const string AttackerIp = "203.0.113.77";
	private const string SecondIp = "198.51.100.9";
	private const int BurstGapSeconds = 3_600;
	private const int RowsInDecimatedFixture = 12_000;

	[Fact]
	public async Task BruteForceBurst_TickKeepsBurstHeadsAndTails_AndSecondTickChangesNothing()
	{
		(TestDbContextFactory factory, SqliteConnection conn) = await CreateDbAsync();
		try
		{
			DateTime nowUtc = DateTime.UtcNow;

			// Given: sixty-day-old brute-force logon-failure telemetry - one event id, one IP,
			// three 4000-row bursts separated by silent gaps. The 365-day retention policy keeps
			// every row, so any compaction observed below comes from decimation alone.
			long firstInsertedId;
			long lastInsertedId;
			DateTime burst0Start = nowUtc.AddDays(-60);
			await using (AuditDbContext seed = factory.CreateDbContext())
			{
				await SeedBurstRowsAsync(seed, 4625, AttackerIp, burst0Start, RowsInDecimatedFixture);
				await seed.SaveChangesAsync();
				firstInsertedId = await seed.RawEvents.AsNoTracking().MinAsync(item => item.Id);
				lastInsertedId = await seed.RawEvents.AsNoTracking().MaxAsync(item => item.Id);
			}

			RetentionWorker worker = CreateWorker(factory, decimationEnabled: true, batchSize: 1_000);

			// When: the retention tick runs, then runs again on the next schedule.
			await worker.RunOnceAsync(CancellationToken.None);
			long afterFirstTick = await CountAsync(factory, 4625, AttackerIp);
			await worker.RunOnceAsync(CancellationToken.None);
			long afterSecondTick = await CountAsync(factory, 4625, AttackerIp);

			// Then: three bursts x (100 head + 100 tail) survive, no middle row is left, the
			// absolute first and last rows are preserved for forensics, and the second tick
			// refuses to delete anything (the pass has converged).
			Assert.Equal(600, afterFirstTick);
			Assert.Equal(afterFirstTick, afterSecondTick);

			await using AuditDbContext verify = factory.CreateDbContext();
			List<RawEvent> survivors = await verify.RawEvents
				.AsNoTracking()
				.OrderBy(item => item.TimeUtc).ThenBy(item => item.Id)
				.ToListAsync();
			Assert.Equal(firstInsertedId, survivors[0].Id);
			Assert.Equal(lastInsertedId, survivors[^1].Id);

			// Precise per-burst keep windows: the first 100 and last 100 timestamps of
			// each 4000-row burst must survive. The 3600-second gap is added before the
			// 4001st row is inserted, so burst heads sit at +0, +7600 and +15200 seconds
			// and their tails end at +3999, +11599 and +19199.
			(long headOffset, long tailOffset)[] keepWindows =
			{
				(0, 3_900),
				(7_600, 11_500),
				(15_200, 19_100),
			};
			foreach ((long headOffset, long tailOffset) in keepWindows)
			{
				DateTime headStart = burst0Start.AddSeconds(headOffset);
				DateTime headEnd = burst0Start.AddSeconds(headOffset + 99);
				DateTime tailStart = burst0Start.AddSeconds(tailOffset);
				DateTime tailEnd = burst0Start.AddSeconds(tailOffset + 99);

				int headKept = await verify.RawEvents.AsNoTracking()
					.CountAsync(item => item.TimeUtc >= headStart && item.TimeUtc <= headEnd);
				Assert.Equal(100, headKept);

				int tailKept = await verify.RawEvents.AsNoTracking()
					.CountAsync(item => item.TimeUtc >= tailStart && item.TimeUtc <= tailEnd);
				Assert.Equal(100, tailKept);
			}
		}
		finally
		{
			await conn.DisposeAsync();
		}
	}

	[Fact]
	public async Task RareLowVolumeEvent_FromTheSameIp_StaysWholeDuringDecimation()
	{
		(TestDbContextFactory factory, SqliteConnection conn) = await CreateDbAsync();
		try
		{
			DateTime nowUtc = DateTime.UtcNow;

			// Given: the same night produced a 4625 brute-force storm AND 500 rows of the
			// lower-frequency 4776 event from the same IP (below the candidate threshold).
			await using (AuditDbContext seed = factory.CreateDbContext())
			{
				await SeedBurstRowsAsync(seed, 4625, AttackerIp, nowUtc.AddDays(-60), RowsInDecimatedFixture);
				await SeedBurstRowsAsync(seed, 4776, AttackerIp, nowUtc.AddDays(-60), 500);
				await seed.SaveChangesAsync();
			}

			RetentionWorker worker = CreateWorker(factory, decimationEnabled: true);

			// When: one retention tick runs.
			await worker.RunOnceAsync(CancellationToken.None);

			// Then: the hot event is compacted to its head/tail rows, while the rare event is
			// preserved verbatim - every one of its 500 rows still exists for the investigator.
			Assert.Equal(600, await CountAsync(factory, 4625, AttackerIp));
			Assert.Equal(500, await CountAsync(factory, 4776, AttackerIp));
		}
		finally
		{
			await conn.DisposeAsync();
		}
	}

	[Fact]
	public async Task SecondIp_LowVolumeOfTheSameEvent_IsLeftUntouched()
	{
		(TestDbContextFactory factory, SqliteConnection conn) = await CreateDbAsync();
		try
		{
			DateTime nowUtc = DateTime.UtcNow;

			// Given: while 203.0.113.77 caused the 4625 storm, a second IP contributed only
			// ten rows of the very same event id (its burst is smaller than the head+tail
			// keep budget, so nothing in it qualifies as a middle row).
			await using (AuditDbContext seed = factory.CreateDbContext())
			{
				await SeedBurstRowsAsync(seed, 4625, AttackerIp, nowUtc.AddDays(-60), RowsInDecimatedFixture);
				await SeedBurstRowsAsync(seed, 4625, SecondIp, nowUtc.AddDays(-60), 10);
				await seed.SaveChangesAsync();
			}

			RetentionWorker worker = CreateWorker(factory, decimationEnabled: true);

			// When: one retention tick runs.
			await worker.RunOnceAsync(CancellationToken.None);

			// Then: only the abusive IP is compacted; the second IP's ten rows remain
			// completely intact.
			Assert.Equal(600, await CountAsync(factory, 4625, AttackerIp));
			Assert.Equal(10, await CountAsync(factory, 4625, SecondIp));
		}
		finally
		{
			await conn.DisposeAsync();
		}
	}

	// ── Helpers ──────────────────────────────────────────────────────────────────

	private static async Task<(TestDbContextFactory Factory, SqliteConnection Connection)> CreateDbAsync()
	{
		SqliteConnection conn = new("DataSource=:memory:");
		await conn.OpenAsync();
		DbContextOptions<AuditDbContext> options = new DbContextOptionsBuilder<AuditDbContext>()
			.UseSqlite(conn)
			.Options;

		await using (AuditDbContext init = new(options))
		{
			await init.Database.EnsureCreatedAsync();
		}

		return (new TestDbContextFactory(options), conn);
	}

	/// <summary>
	/// Inserts rows for one event id and one IP as a monotonic 1-second stream; long runs are
	/// split into 4000-row bursts separated by <see cref="BurstGapSeconds"/> of silence.
	/// </summary>
	private static async Task SeedBurstRowsAsync(
		AuditDbContext db,
		int eventId,
		string ip,
		DateTime startUtc,
		int totalRows)
	{
		DateTime cursor = startUtc;
		for (int i = 0; i < totalRows; i++)
		{
			if (i > 0 && i % 4_000 == 0)
			{
				cursor = cursor.AddSeconds(BurstGapSeconds);
			}

			db.RawEvents.Add(new RawEvent
			{
				EventId = eventId,
				Channel = "Security",
				TimeUtc = cursor,
				SourceIp = ip,
				Status = "0xC000006D",
			});
			cursor = cursor.AddSeconds(1);
		}

		await Task.CompletedTask;
	}

	private static RetentionWorker CreateWorker(TestDbContextFactory factory, bool decimationEnabled, int batchSize = 5_000)
	{
		RdpAuditOptions options = new()
		{
			Storage = new StorageOptions
			{
				EventRetentionDays = 365,
				MaintenanceBatchSize = 50_000,
				Decimation = new DecimationOptions
				{
					Enabled = decimationEnabled,
					MinAgeDays = 30,
					BurstGapSeconds = BurstGapSeconds,
					CandidateMinRows = 10_000,
					HeadKeepPerBurst = 100,
					TailKeepPerBurst = 100,
					MaxCandidateEventIds = 5,
					BatchSize = batchSize,
				},
			},
		};

		return new RetentionWorker(
			factory,
			new StaticOptionsMonitor<RdpAuditOptions>(options),
			NullLogger<RetentionWorker>.Instance);
	}

	private static async Task<long> CountAsync(TestDbContextFactory factory, int eventId, string ip)
	{
		await using AuditDbContext db = factory.CreateDbContext();
		return await db.RawEvents.LongCountAsync(item => item.EventId == eventId && item.SourceIp == ip);
	}

	private sealed class TestDbContextFactory(DbContextOptions<AuditDbContext> options) : IDbContextFactory<AuditDbContext>
	{
		public AuditDbContext CreateDbContext() => new(options);

		public Task<AuditDbContext> CreateDbContextAsync(CancellationToken cancellationToken = default)
			=> Task.FromResult(new AuditDbContext(options));
	}

	private sealed class StaticOptionsMonitor<T>(T value) : IOptionsMonitor<T>
		where T : class
	{
		public T CurrentValue => value;

		public T Get(string? name) => value;

		public IDisposable? OnChange(Action<T, string?> listener) => null;
	}
}
