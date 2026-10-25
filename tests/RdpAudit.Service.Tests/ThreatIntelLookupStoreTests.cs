// File:    tests/RdpAudit.Service.Tests/ThreatIntelLookupStoreTests.cs
// Module:  RdpAudit.Service.Tests
// Purpose: Unit tests for the Backlog #5 ThreatIntelLookupStore against an in-memory SQLite
//          database that matches the Stage15 schema: upsert semantics on ThreatIntelLookups,
//          fail-closed freshness checks, NextRetryUtc arming and the persisted daily usage
//          counter. Also verifies that ToLookupResult refuses to fabricate Success-shaped data
//          from failed cache rows.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using RdpAudit.Core.Data;
using RdpAudit.Core.Models;
using RdpAudit.Core.ThreatIntel;
using RdpAudit.Service.ThreatIntel;
using Xunit;

namespace RdpAudit.Service.Tests;

public class ThreatIntelLookupStoreTests
{
	private sealed class FakeTimeProvider : TimeProvider
	{
		private readonly DateTimeOffset _now;

		public FakeTimeProvider(DateTimeOffset now) => _now = now;

		public override DateTimeOffset GetUtcNow() => _now;
	}

	private sealed class TestDbContextFactory : IDbContextFactory<AuditDbContext>
	{
		private readonly DbContextOptions<AuditDbContext> _options;
		public TestDbContextFactory(DbContextOptions<AuditDbContext> options) => _options = options;
		public AuditDbContext CreateDbContext() => new(_options);
	}

	private static async Task<(ThreatIntelLookupStore Store, IDbContextFactory<AuditDbContext> Factory, SqliteConnection Conn)> CreateAsync(DateTimeOffset now)
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

		IDbContextFactory<AuditDbContext> factory = new TestDbContextFactory(options);
		return (new ThreatIntelLookupStore(factory, new FakeTimeProvider(now)), factory, conn);
	}

	private static ThreatIntelLookupResult SuccessResult(string ip = "203.0.113.77", int score = 92) => new()
	{
		Outcome = ThreatIntelLookupOutcome.Success,
		Ip = ip,
		ResponseCode = 200,
		AbuseConfidenceScore = score,
		TotalReports = 15,
		IsWhitelisted = false,
		IsPublic = true,
		UsageType = "Data Center",
		CountryCode = "US",
	};

	[Fact]
	public async Task UpsertAsync_Success_IsReadableAndFresh()
	{
		DateTimeOffset now = new(2026, 9, 12, 10, 0, 0, TimeSpan.Zero);
		(ThreatIntelLookupStore store, _, SqliteConnection conn) = await CreateAsync(now);
		await using (conn.ConfigureAwait(false))
		{
			await store.UpsertAsync(SuccessResult());

			ThreatIntelLookup? row = await store.GetFreshSnapshotAsync("203.0.113.77", 30);
			Assert.NotNull(row);
			Assert.Equal(92, row!.Score);
			Assert.Equal(15, row.TotalReports);
			Assert.Null(row.NextRetryUtc);

			ThreatIntelLookupResult? mapped = ThreatIntelLookupStore.ToLookupResult(row);
			Assert.NotNull(mapped);
			Assert.True(ThreatIntelClassifier.IsHighRisk(mapped, threshold: 90));
		}
	}

	[Fact]
	public async Task UpsertAsync_RateLimited_ArmsNextRetryAndClearsSuccessFields()
	{
		DateTimeOffset now = new(2026, 9, 12, 10, 0, 0, TimeSpan.Zero);
		(ThreatIntelLookupStore store, _, SqliteConnection conn) = await CreateAsync(now);
		await using (conn.ConfigureAwait(false))
		{
			await store.UpsertAsync(new ThreatIntelLookupResult
			{
				Outcome = ThreatIntelLookupOutcome.RateLimited,
				Ip = "203.0.113.77",
				ResponseCode = 429,
				RetryAfter = TimeSpan.FromMinutes(2),
			});

			ThreatIntelLookup? row = await store.GetAsync("203.0.113.77");
			Assert.NotNull(row);
			Assert.Equal((int)ThreatIntelLookupOutcome.RateLimited, row!.Outcome);
			Assert.Null(row.Score);
			Assert.NotNull(row.NextRetryUtc);
			Assert.True(row.NextRetryUtc >= now.UtcDateTime.AddMinutes(2).AddSeconds(-5));

			Assert.Null(await store.GetFreshSnapshotAsync("203.0.113.77", 30));
			Assert.Null(ThreatIntelLookupStore.ToLookupResult(row));
		}
	}

	[Fact]
	public async Task UpsertAsync_ServerError_LeavesRetryCleared()
	{
		DateTimeOffset now = new(2026, 9, 12, 10, 0, 0, TimeSpan.Zero);
		(ThreatIntelLookupStore store, _, SqliteConnection conn) = await CreateAsync(now);
		await using (conn.ConfigureAwait(false))
		{
			await store.UpsertAsync(new ThreatIntelLookupResult
			{
				Outcome = ThreatIntelLookupOutcome.ServerError,
				Ip = "203.0.113.77",
				ResponseCode = 503,
			});

			ThreatIntelLookup? row = await store.GetAsync("203.0.113.77");
			Assert.NotNull(row);
			Assert.Equal((int)ThreatIntelLookupOutcome.ServerError, row!.Outcome);
			Assert.Null(row.NextRetryUtc);
		}
	}

	[Fact]
	public async Task UpsertAsync_SecondSuccess_OverwritesFirst_NoDuplicateRows()
	{
		DateTimeOffset now = new(2026, 9, 12, 10, 0, 0, TimeSpan.Zero);
		(ThreatIntelLookupStore store, IDbContextFactory<AuditDbContext> factory, SqliteConnection conn) = await CreateAsync(now);
		await using (conn.ConfigureAwait(false))
		{
			await store.UpsertAsync(SuccessResult(score: 10));
			await store.UpsertAsync(SuccessResult(score: 99));

			ThreatIntelLookup? row = await store.GetAsync("203.0.113.77");
			Assert.NotNull(row);
			Assert.Equal(99, row!.Score);

			await using AuditDbContext db = factory.CreateDbContext();
			Assert.Single(await db.ThreatIntelLookups.AsNoTracking().ToListAsync());
		}
	}

	[Fact]
	public async Task GetFreshSnapshotAsync_StaleRow_ReturnsNull()
	{
		DateTimeOffset now = new(2026, 9, 12, 10, 0, 0, TimeSpan.Zero);
		(ThreatIntelLookupStore store, _, SqliteConnection conn) = await CreateAsync(now);
		await using (conn.ConfigureAwait(false))
		{
			await store.UpsertAsync(SuccessResult(), nowUtc: new DateTime(2026, 8, 1, 10, 0, 0, DateTimeKind.Utc));

			Assert.Null(await store.GetFreshSnapshotAsync("203.0.113.77", 30));
		}
	}

	[Fact]
	public async Task GetFreshSnapshotAsync_MissingRow_ReturnsNull()
	{
		DateTimeOffset now = new(2026, 9, 12, 10, 0, 0, TimeSpan.Zero);
		(ThreatIntelLookupStore store, _, SqliteConnection conn) = await CreateAsync(now);
		await using (conn.ConfigureAwait(false))
		{
			Assert.Null(await store.GetFreshSnapshotAsync("198.51.100.9", 30));
		}
	}

	[Fact]
	public async Task DailyCounter_StartsAtZeroAndIncrementsEachDay()
	{
		DateTimeOffset now = new(2026, 9, 12, 10, 0, 0, TimeSpan.Zero);
		(ThreatIntelLookupStore store, _, SqliteConnection conn) = await CreateAsync(now);
		await using (conn.ConfigureAwait(false))
		{
			Assert.Equal(0, await store.GetDailyCountAsync("2026-09-12"));

			await store.IncrementDailyCountAsync("2026-09-12");
			await store.IncrementDailyCountAsync("2026-09-12");
			await store.IncrementDailyCountAsync("2026-09-13");

			Assert.Equal(2, await store.GetDailyCountAsync("2026-09-12"));
			Assert.Equal(1, await store.GetDailyCountAsync("2026-09-13"));
		}
	}

	[Fact]
	public void ToLookupResult_NullOrNonSuccess_ReturnsNull()
	{
		Assert.Null(ThreatIntelLookupStore.ToLookupResult(null));
		Assert.Null(ThreatIntelLookupStore.ToLookupResult(new ThreatIntelLookup
		{
			Ip = "203.0.113.77",
			Outcome = (int)ThreatIntelLookupOutcome.RateLimited,
		}));
	}
}
