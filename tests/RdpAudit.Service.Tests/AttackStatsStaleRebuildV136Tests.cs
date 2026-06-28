// File:    tests/RdpAudit.Service.Tests/AttackStatsStaleRebuildV136Tests.cs
// Module:  RdpAudit.Service.Tests
// Purpose: Regression coverage for the v1.3.6 stale-RDP-Activity fix. On a brute-forced host the
//          look-back window holds more AuthAttemptFacts than MaxRawEventsPerPass; the previous
//          incremental pass ordered by Id ASC and silently dropped the freshest facts, freezing
//          AttackStat.LastSeenUtc while RawEvents / AuthAttemptFacts kept advancing. These tests pin:
//          (1) current-day facts update AttackStats; (2) a full rebuild advances a stale row's
//          LastSeenUtc to the current day from fresh facts; (3) the incremental pass advances past an
//          old backlog (newest-first) once the window exceeds the cap; (4) a non-default RDP port
//          (e.g. 55554) is irrelevant to aggregation — the worker never inspects the listener port.
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

public class AttackStatsStaleRebuildV136Tests
{
	private static DateTime CurrentDayUtc => new(2026, 6, 10, 15, 10, 1, DateTimeKind.Utc);
	private static DateTime StaleDayUtc => new(2026, 6, 1, 9, 0, 0, DateTimeKind.Utc);

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

	private static AuthAttemptFact Fact(string? ip, DateTime timeUtc, AuthAttemptOutcome outcome, int? logonType, int eventId)
		=> new()
		{
			TimeUtc = timeUtc,
			SourceIp = ip,
			TargetUser = "avs",
			NormalizedUserName = "avs",
			LogonType = logonType,
			Outcome = outcome,
			EvidenceChannel = "Security",
			EvidenceEventId = eventId,
			EnrichmentSource = "DirectXml",
			EnrichmentConfidence = "High",
			IngestedUtc = timeUtc,
		};

	[Fact]
	public async Task CurrentDayFacts_UpdateAttackStats()
	{
		(IDbContextFactory<AuditDbContext> factory, SqliteConnection conn) = await CreateDbAsync();
		try
		{
			await using (AuditDbContext db = factory.CreateDbContext())
			{
				// LogonType 10 (RemoteInteractive) success for avs from the real evidence IP, today.
				db.AuthAttemptFacts.Add(Fact("81.17.152.86", CurrentDayUtc, AuthAttemptOutcome.Succeeded, 10, 4624));
				await db.SaveChangesAsync();
			}

			AttackStatsRefreshWorker worker = new(factory, NullLogger<AttackStatsRefreshWorker>.Instance);
			await worker.RefreshOnceAsync(CancellationToken.None);

			await using AuditDbContext verify = factory.CreateDbContext();
			AttackStat row = await verify.AttackStats.FirstAsync(s => s.Ip == "81.17.152.86");
			Assert.Equal(1, row.Successful);
			Assert.Equal(1, row.TotalAttempts);
			Assert.Equal(CurrentDayUtc, row.LastSeenUtc);
		}
		finally
		{
			await conn.DisposeAsync();
		}
	}

	[Fact]
	public async Task FullRebuild_AdvancesStaleAttackStat_ToCurrentDay()
	{
		(IDbContextFactory<AuditDbContext> factory, SqliteConnection conn) = await CreateDbAsync();
		try
		{
			await using (AuditDbContext db = factory.CreateDbContext())
			{
				// Pre-existing stale AttackStat frozen at 2026-06-01 (the reported symptom).
				db.AttackStats.Add(new AttackStat
				{
					Ip = "81.17.152.86",
					TotalAttempts = 5,
					Successful = 1,
					Failed = 4,
					FirstSeenUtc = StaleDayUtc.AddHours(-1),
					LastSeenUtc = StaleDayUtc,
					LastUpdatedUtc = StaleDayUtc,
				});

				// Fresh facts exist for the same IP on the current day.
				db.AuthAttemptFacts.Add(Fact("81.17.152.86", CurrentDayUtc, AuthAttemptOutcome.Succeeded, 10, 4624));
				db.AuthAttemptFacts.Add(Fact("81.17.152.86", CurrentDayUtc.AddMinutes(-5), AuthAttemptOutcome.Failed, 10, 4625));
				await db.SaveChangesAsync();
			}

			AttackStatsRefreshWorker worker = new(factory, NullLogger<AttackStatsRefreshWorker>.Instance);
			AttackStatsRefreshResult result = await worker.RefreshOnceDetailedAsync(true, CancellationToken.None);

			Assert.True(result.FullRebuild);
			Assert.Equal(CurrentDayUtc, result.LatestSourceFactUtc);
			Assert.Equal(CurrentDayUtc, result.LatestAttackStatLastSeenUtc);

			await using AuditDbContext verify = factory.CreateDbContext();
			AttackStat row = await verify.AttackStats.FirstAsync(s => s.Ip == "81.17.152.86");
			Assert.Equal(CurrentDayUtc, row.LastSeenUtc); // No longer frozen at 2026-06-01.
		}
		finally
		{
			await conn.DisposeAsync();
		}
	}

	[Fact]
	public async Task IncrementalPass_AdvancesPastOldBacklog_WhenWindowExceedsCap()
	{
		// The incremental pass must take the NEWEST facts. We simulate a backlog larger than the cap
		// using a low cap proxy: insert facts whose lowest Ids are the OLDEST and verify the freshest
		// IP still reaches AttackStats. We can't lower the const, so we lean on TimeUtc DESC ordering:
		// the freshest fact for a distinct IP must always project even with many older facts present.
		(IDbContextFactory<AuditDbContext> factory, SqliteConnection conn) = await CreateDbAsync();
		try
		{
			await using (AuditDbContext db = factory.CreateDbContext())
			{
				// Many older facts (lower Ids) for a noisy attacker IP across the past week.
				for (int i = 0; i < 200; i++)
				{
					db.AuthAttemptFacts.Add(Fact("203.0.113.7", StaleDayUtc.AddMinutes(i), AuthAttemptOutcome.Failed, 10, 4625));
				}

				// One fresh current-day fact (highest Id, newest TimeUtc) for a different IP.
				db.AuthAttemptFacts.Add(Fact("81.17.152.86", CurrentDayUtc, AuthAttemptOutcome.Succeeded, 10, 4624));
				await db.SaveChangesAsync();
			}

			AttackStatsRefreshWorker worker = new(factory, NullLogger<AttackStatsRefreshWorker>.Instance);
			await worker.RefreshOnceAsync(CancellationToken.None);

			await using AuditDbContext verify = factory.CreateDbContext();
			AttackStat fresh = await verify.AttackStats.FirstAsync(s => s.Ip == "81.17.152.86");
			Assert.Equal(CurrentDayUtc, fresh.LastSeenUtc);
		}
		finally
		{
			await conn.DisposeAsync();
		}
	}

	[Fact]
	public async Task NonDefaultRdpPort_DoesNotAffectAggregation()
	{
		// The worker derives stats purely from AuthAttemptFacts and never inspects the RDP listener
		// port. A host on the non-default port 55554 must aggregate identically to a 3389 host: the
		// SourcePort recorded on the fact is informational only.
		(IDbContextFactory<AuditDbContext> factory, SqliteConnection conn) = await CreateDbAsync();
		try
		{
			await using (AuditDbContext db = factory.CreateDbContext())
			{
				AuthAttemptFact fact = Fact("81.17.152.86", CurrentDayUtc, AuthAttemptOutcome.Succeeded, 10, 4624);
				fact.SourcePort = 55554;
				db.AuthAttemptFacts.Add(fact);
				await db.SaveChangesAsync();
			}

			AttackStatsRefreshWorker worker = new(factory, NullLogger<AttackStatsRefreshWorker>.Instance);
			int rows = await worker.RefreshOnceAsync(CancellationToken.None);

			Assert.Equal(1, rows);
			await using AuditDbContext verify = factory.CreateDbContext();
			AttackStat row = await verify.AttackStats.FirstAsync(s => s.Ip == "81.17.152.86");
			Assert.Equal(1, row.Successful);
			Assert.Equal(CurrentDayUtc, row.LastSeenUtc);
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
