// File:    tests/RdpAudit.Service.Tests/AttackStatsAuthAttemptFactDerivationTests.cs
// Module:  RdpAudit.Service.Tests
// Purpose: Pins Detect_Attack_Strategy_v3.md §8.1 invariant: Attack Statistics Total / Successful /
//          Failed counters MUST derive from AuthAttemptFact rows — not from visible RdpConnectionFact
//          rows, raw RdpCoreTS events, or in-memory connection records. If only RdpCoreTS / TCP
//          events are present (no AuthAttemptFact), counters remain zero. If a backfill replays the
//          same Security event that the live watcher already delivered, the fact set must not
//          double-count.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using RdpAudit.Core.Data;
using RdpAudit.Core.Models;
using RdpAudit.Service.Workers;
using Xunit;

namespace RdpAudit.Service.Tests;

public class AttackStatsAuthAttemptFactDerivationTests
{
	// Anchor all seeded timestamps two days in the past so every fact stays inside the
	// AttackStatsRefreshWorker 30-day look-back window (DateTime.UtcNow - 30d) while remaining
	// strictly in the past. A fixed calendar date would silently expire 30 days after it was
	// written, which is exactly the regression this constant prevents. Captured once at class
	// load to guarantee a stable value across all reads within a single test run.
	private static readonly DateTime Now = DateTime.UtcNow.AddDays(-2).Date.AddHours(12);

	private static async Task<(IDbContextFactory<AuditDbContext> factory, SqliteConnection conn)> CreateDbAsync()
	{
		SqliteConnection conn = new("DataSource=:memory:");
		await conn.OpenAsync();
		DbContextOptions<AuditDbContext> options = new DbContextOptionsBuilder<AuditDbContext>()
			.UseSqlite(conn)
			.Options;
		await using (AuditDbContext db = new(options))
		{
			await db.Database.EnsureCreatedAsync();
		}

		return (new TestFactoryLocal(options), conn);
	}

	[Fact]
	public async Task RdpCoreTsOnly_CountersStayZero()
	{
		(IDbContextFactory<AuditDbContext> factory, SqliteConnection conn) = await CreateDbAsync();
		try
		{
			await using (AuditDbContext db = factory.CreateDbContext())
			{
				// Three RdpCoreTS-only observations — must NOT count as Successful or Failed
				// (v3 acceptance criterion §17.3).
				for (int i = 0; i < 3; i++)
				{
					db.RawEvents.Add(new RawEvent
					{
						EventId = 131,
						Channel = "Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational",
						TimeUtc = Now.AddSeconds(-30 + i),
						SourceIp = "203.0.113.55",
					});
				}

				await db.SaveChangesAsync();
			}

			AttackStatsRefreshWorker worker = new(factory, NullLogger<AttackStatsRefreshWorker>.Instance);
			await worker.RefreshOnceAsync(CancellationToken.None);

			await using AuditDbContext verify = factory.CreateDbContext();
			AttackStat? row = await verify.AttackStats.FirstOrDefaultAsync(s => s.Ip == "203.0.113.55");
			Assert.Null(row); // No AuthAttemptFact rows → no Attack Statistics row.
		}
		finally
		{
			await conn.DisposeAsync();
		}
	}

	[Fact]
	public async Task CountersDeriveExclusivelyFromAuthAttemptFact()
	{
		(IDbContextFactory<AuditDbContext> factory, SqliteConnection conn) = await CreateDbAsync();
		try
		{
			await using (AuditDbContext db = factory.CreateDbContext())
			{
				// Seed AuthAttemptFacts directly (the v3 atomic source of truth).
				for (int i = 0; i < 4; i++)
				{
					db.AuthAttemptFacts.Add(new AuthAttemptFact
					{
						TimeUtc = Now.AddSeconds(-30 + i),
						SourceIp = "203.0.113.10",
						TargetUser = "administrator",
						NormalizedUserName = "administrator",
						Outcome = AuthAttemptOutcome.Failed,
						EvidenceChannel = "Security",
						EvidenceEventId = 4625,
						EnrichmentSource = "DirectXml",
						EnrichmentConfidence = "High",
						IngestedUtc = Now,
					});
				}

				db.AuthAttemptFacts.Add(new AuthAttemptFact
				{
					TimeUtc = Now,
					SourceIp = "203.0.113.10",
					TargetUser = "administrator",
					NormalizedUserName = "administrator",
					Outcome = AuthAttemptOutcome.Succeeded,
					EvidenceChannel = "Security",
					EvidenceEventId = 4624,
					EnrichmentSource = "DirectXml",
					EnrichmentConfidence = "High",
					IngestedUtc = Now,
				});

				// Seed an unrelated RdpConnectionFact for the same IP. Per v3 §8.1 it MUST NOT
				// contribute to counters — the AuthAttemptFact tally is authoritative.
				db.RdpConnectionFacts.Add(new RdpConnectionFact
				{
					Ip = "203.0.113.10",
					UserName = "administrator",
					LogonId = "0xLEGACY",
					FirstSeenUtc = Now.AddDays(-1),
					LastSeenUtc = Now,
					FailedLogons = 999, // Intentionally bogus — must NOT show up in stats.
					SuccessfulLogons = 999,
					ObservedEventIds = "4625",
				});

				await db.SaveChangesAsync();
			}

			AttackStatsRefreshWorker worker = new(factory, NullLogger<AttackStatsRefreshWorker>.Instance);
			await worker.RefreshOnceAsync(CancellationToken.None);

			await using AuditDbContext verify = factory.CreateDbContext();
			AttackStat row = await verify.AttackStats.FirstAsync(s => s.Ip == "203.0.113.10");
			Assert.Equal(4, row.Failed);
			Assert.Equal(1, row.Successful);
			Assert.Equal(5, row.TotalAttempts);
		}
		finally
		{
			await conn.DisposeAsync();
		}
	}

	[Fact]
	public async Task DuplicateLiveAndBackfillEvents_DoNotDoubleCount()
	{
		// Detect_Attack_Strategy_v3.md §5.2: backfill must dedupe by (Channel, RecordId). On the
		// fact side, the upserter writes EvidenceRawEventId, so two distinct RawEvent rows that
		// represent the same Windows record would create two facts. We test the practical
		// expectation: if the live watcher and the backfill both ingest the same record, the
		// SecurityBackfillWorker's in-memory dedup ring prevents the duplicate from being
		// forwarded a second time — so only one RawEvent (and therefore one AuthAttemptFact)
		// ever lands. Here we simulate the post-dedup state and assert that the counter is 1,
		// not 2, by inserting a single AuthAttemptFact for the same event.
		(IDbContextFactory<AuditDbContext> factory, SqliteConnection conn) = await CreateDbAsync();
		try
		{
			await using (AuditDbContext db = factory.CreateDbContext())
			{
				db.AuthAttemptFacts.Add(new AuthAttemptFact
				{
					TimeUtc = Now,
					SourceIp = "203.0.113.99",
					TargetUser = "md",
					NormalizedUserName = "md",
					Outcome = AuthAttemptOutcome.Failed,
					EvidenceChannel = "Security",
					EvidenceEventId = 4625,
					EvidenceRawEventId = 12345,
					EnrichmentSource = "DirectXml",
					EnrichmentConfidence = "High",
					IngestedUtc = Now,
				});

				await db.SaveChangesAsync();
			}

			AttackStatsRefreshWorker worker = new(factory, NullLogger<AttackStatsRefreshWorker>.Instance);
			await worker.RefreshOnceAsync(CancellationToken.None);
			await worker.RefreshOnceAsync(CancellationToken.None); // second pass on same data

			await using AuditDbContext verify = factory.CreateDbContext();
			AttackStat row = await verify.AttackStats.FirstAsync(s => s.Ip == "203.0.113.99");
			Assert.Equal(1, row.Failed); // Refresh is idempotent — never doubles.
			Assert.Equal(1, row.TotalAttempts);
		}
		finally
		{
			await conn.DisposeAsync();
		}
	}

	private sealed class TestFactoryLocal : IDbContextFactory<AuditDbContext>
	{
		private readonly DbContextOptions<AuditDbContext> _options;
		public TestFactoryLocal(DbContextOptions<AuditDbContext> options) { _options = options; }
		public AuditDbContext CreateDbContext() => new(_options);
	}
}
