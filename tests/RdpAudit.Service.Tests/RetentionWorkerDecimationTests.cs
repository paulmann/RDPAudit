/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 2.0.0
// File   : RetentionWorkerDecimationTests.cs
// Project: RdpAudit.Service.Tests (RdpAudit.Service.Tests)
// Purpose: Integration tests for the RetentionWorker decimation stage: after the ordinary prune,
//          RunOnceAsync drives RawEventDecimationEngine against Storage.Decimation. Locks that an
//          enabled pass shrinks synthetic bursts to their head/tail rows without touching other
//          telemetry, that rows younger than MinAgeDays survive, and that a disabled policy is a
//          no-op.
// Depends: RetentionWorker, RawEventDecimationEngine, DecimationOptions, AuditDbContext
// Extends: Add per-event overrides or whitelist scenarios when policy surface grows.

using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using RdpAudit.Core.Config;
using RdpAudit.Core.Data;
using RdpAudit.Core.Models;
using RdpAudit.Service.Workers;
using Xunit;

namespace RdpAudit.Service.Tests;

/// <summary>Worker-level decimation integration tests for <see cref="RetentionWorker"/>.</summary>
public sealed class RetentionWorkerDecimationTests
{
	private const string AttackerIp = "203.0.113.77";
	private const int RowCount = 12_000; // three bursts of 4000 rows each
	private const int BurstGapSeconds = 3_600; // gap between bursts; rows are 1 second apart

	private sealed class TestDbContextFactory : IDbContextFactory<AuditDbContext>
	{
		private readonly DbContextOptions<AuditDbContext> _options;
		public TestDbContextFactory(DbContextOptions<AuditDbContext> options) => _options = options;
		public AuditDbContext CreateDbContext() => new(_options);
	}

	private sealed class StaticOptionsMonitor<T> : IOptionsMonitor<T>
	{
		public StaticOptionsMonitor(T value) => CurrentValue = value;
		public T CurrentValue { get; }
		public T Get(string? name) => CurrentValue;
		public IDisposable? OnChange(Action<T, string?> listener) => null;
	}

	private static async Task<(IDbContextFactory<AuditDbContext>, SqliteConnection)> CreateDbAsync()
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

	/// <summary>Seeds three bursts of 4625 rows from one IP, each 1 second apart, with a gap between bursts.</summary>
	private static async Task SeedBurstAsync(
		AuditDbContext db,
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
				EventId = 4625,
				Channel = "Security",
				TimeUtc = cursor,
				SourceIp = AttackerIp,
				Status = "0xC000006D",
			});
			cursor = cursor.AddSeconds(1);
		}

		await db.SaveChangesAsync();
	}

	private static RdpAuditOptions BuildOptions(bool decimationEnabled, int batchSize = 5_000) => new()
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

	[Fact]
	public async Task RunOnceAsync_DecimationEnabled_ShrinksBurstsToHeadAndTail()
	{
		(IDbContextFactory<AuditDbContext> factory, SqliteConnection conn) = await CreateDbAsync();
		try
		{
			DateTime now = DateTime.UtcNow;
			await using (AuditDbContext seed = factory.CreateDbContext())
			{
				// Rows are 60 days old: older than MinAgeDays (30) but younger than the
				// ordinary retention cutoff (365), so only decimation can touch them.
				await SeedBurstAsync(seed, now.AddDays(-60), RowCount);
				// Fresh correlation fact: survives fact pruning, so the count assertion
				// proves the decimation stage did not touch other telemetry tables.
				seed.SessionIpCorrelations.Add(new SessionIpCorrelation
				{
					Ip = AttackerIp,
					FirstSeenUtc = now.AddDays(-1),
					LastSeenUtc = now.AddDays(-1),
				});
				await seed.SaveChangesAsync();
			}

			RetentionWorker worker = new(
				factory,
				new StaticOptionsMonitor<RdpAuditOptions>(BuildOptions(decimationEnabled: true, batchSize: 1_000)),
				NullLogger<RetentionWorker>.Instance);

			await worker.RunOnceAsync(CancellationToken.None);

			await using AuditDbContext verify = factory.CreateDbContext();
			List<RawEvent> survivors = await verify.RawEvents.AsNoTracking().OrderBy(r => r.Id).ToListAsync();

			// Three bursts x (100 head + 100 tail) survive; the middle of every burst is gone.
			Assert.Equal(600, survivors.Count);
			Assert.Equal(AttackerIp, survivors[0].SourceIp);
			Assert.Equal(AttackerIp, survivors[^1].SourceIp);

			// Other telemetry in the same database is untouched by decimation.
			Assert.Equal(1, await verify.SessionIpCorrelations.CountAsync());
		}
		finally
		{
			await conn.DisposeAsync();
		}
	}

	[Fact]
	public async Task RunOnceAsync_DecimationDisabled_LeavesBurstIntact()
	{
		(IDbContextFactory<AuditDbContext> factory, SqliteConnection conn) = await CreateDbAsync();
		try
		{
			DateTime now = DateTime.UtcNow;
			await using (AuditDbContext seed = factory.CreateDbContext())
			{
				await SeedBurstAsync(seed, now.AddDays(-60), RowCount);
			}

			RetentionWorker worker = new(
				factory,
				new StaticOptionsMonitor<RdpAuditOptions>(BuildOptions(decimationEnabled: false)),
				NullLogger<RetentionWorker>.Instance);

			await worker.RunOnceAsync(CancellationToken.None);

			await using AuditDbContext verify = factory.CreateDbContext();
			Assert.Equal(RowCount, await verify.RawEvents.CountAsync());
		}
		finally
		{
			await conn.DisposeAsync();
		}
	}

	[Fact]
	public async Task RunOnceAsync_FreshRowsYoungerThanMinAge_AreNeverDecimated()
	{
		(IDbContextFactory<AuditDbContext> factory, SqliteConnection conn) = await CreateDbAsync();
		try
		{
			DateTime now = DateTime.UtcNow;
			await using (AuditDbContext seed = factory.CreateDbContext())
			{
				// 10 days old: below MinAgeDays, must never be a decimation candidate.
				await SeedBurstAsync(seed, now.AddDays(-10), RowCount);
			}

			RetentionWorker worker = new(
				factory,
				new StaticOptionsMonitor<RdpAuditOptions>(BuildOptions(decimationEnabled: true)),
				NullLogger<RetentionWorker>.Instance);

			await worker.RunOnceAsync(CancellationToken.None);

			await using AuditDbContext verify = factory.CreateDbContext();
			Assert.Equal(RowCount, await verify.RawEvents.CountAsync());
		}
		finally
		{
			await conn.DisposeAsync();
		}
	}
}
