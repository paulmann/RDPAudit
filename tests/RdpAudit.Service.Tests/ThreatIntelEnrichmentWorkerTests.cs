// File:    tests/RdpAudit.Service.Tests/ThreatIntelEnrichmentWorkerTests.cs
// Module:  RdpAudit.Service.Tests
// Purpose: Unit tests for the Backlog #5 ThreatIntelEnrichmentWorker. Covers the configuration
//          gates (no HTTP when disabled), candidate selection (AttackStats + recent
//          RdpConnectionFacts, public-only, whitelist exclusion), the per-minute rate-limit
//          stop, the provider back-off (NextRetryUtc) and the re-entrancy gate. Uses an
//          in-memory SQLite database with the Stage15 schema and a fake time provider.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using RdpAudit.Core.Config;
using RdpAudit.Core.Data;
using RdpAudit.Core.Models;
using RdpAudit.Core.ThreatIntel;
using RdpAudit.Service.ThreatIntel;
using RdpAudit.Service.Workers;
using Xunit;

namespace RdpAudit.Service.Tests;

public class ThreatIntelEnrichmentWorkerTests
{
	private sealed class FakeTimeProvider(DateTimeOffset now) : TimeProvider
	{
		public override DateTimeOffset GetUtcNow() => now;
	}

	private sealed class TestDbContextFactory(DbContextOptions<AuditDbContext> options) : IDbContextFactory<AuditDbContext>
	{
		public AuditDbContext CreateDbContext() => new(options);
	}

	private sealed class StaticOptionsMonitor<T>(T value) : IOptionsMonitor<T> where T : class
	{
		public T CurrentValue => value;
		public T Get(string? name) => value;
		public IDisposable? OnChange(Action<T, string?> listener) => null;
	}

	private sealed class FakeClient : IThreatIntelligenceClient
	{
		public List<string> LookedUp { get; } = new();
		public ThreatIntelLookupResult NextResult { get; set; } = new()
		{
			Outcome = ThreatIntelLookupOutcome.Success,
			Ip = string.Empty,
			AbuseConfidenceScore = 91,
			IsPublic = true,
			IsWhitelisted = false,
			TotalReports = 5,
		};

		public Task<ThreatIntelLookupResult> LookupAsync(string ip, CancellationToken ct)
		{
			LookedUp.Add(ip);
			NextResult.Ip = ip;
			return Task.FromResult(NextResult);
		}
	}

	private static async Task<(IDbContextFactory<AuditDbContext> Factory, SqliteConnection Connection)> CreateDbAsync()
	{
		SqliteConnection connection = new("DataSource=:memory:");
		await connection.OpenAsync();
		DbContextOptions<AuditDbContext> options = new DbContextOptionsBuilder<AuditDbContext>()
			.UseSqlite(connection)
			.Options;
		await using (AuditDbContext db = new(options))
		{
			await db.Database.EnsureCreatedAsync();
		}

		return (new TestDbContextFactory(options), connection);
	}

	private static ThreatIntelEnrichmentWorker CreateWorker(
		IDbContextFactory<AuditDbContext> factory,
		AbuseIpDbOptions abuseOptions,
		IThreatIntelligenceClient client,
		DateTimeOffset now)
	{
		RdpAuditOptions options = new() { AbuseIpDb = abuseOptions };
		StaticOptionsMonitor<RdpAuditOptions> monitor = new(options);
		FakeTimeProvider time = new(now);
		ThreatIntelLookupStore store = new(factory, time);
		ThreatIntelRateLimiter rateLimiter = new(time);
		return new ThreatIntelEnrichmentWorker(
			factory, monitor, client, store, rateLimiter, NullLogger<ThreatIntelEnrichmentWorker>.Instance, time);
	}

	private static AbuseIpDbOptions EnabledOptions() => new()
	{
		Enabled = true,
		CheckEnabled = true,
		CacheLookups = true,
		ApiKey = "test-key",
		CheckMaxLookupsPerMinute = 30,
		CheckMaxLookupsPerDay = 500,
		CheckMaxAgeInDays = 30,
		CheckWorkerIntervalSeconds = 300,
	};

	private static void SeedAttackStats(AuditDbContext db)
	{
		DateTime now = DateTime.UtcNow;
		db.AttackStats.AddRange(
			new AttackStat { Ip = "203.0.113.10", ThreatScore = 90, Failed = 10, LastSeenUtc = now, FirstSeenUtc = now.AddHours(-1), DurationSeconds = 3600 },
			new AttackStat { Ip = "192.168.10.20", ThreatScore = 40, Failed = 2, LastSeenUtc = now, FirstSeenUtc = now.AddHours(-1), DurationSeconds = 3600 },
			new AttackStat { Ip = "198.51.100.30", ThreatScore = 70, Failed = 5, LastSeenUtc = now, FirstSeenUtc = now.AddHours(-1), DurationSeconds = 3600 });
		db.SaveChanges();
	}

	private static void SeedConnectionFacts(AuditDbContext db)
	{
		DateTime now = DateTime.UtcNow;
		db.RdpConnectionFacts.AddRange(
			new RdpConnectionFact { Ip = "203.0.113.11", LastSeenUtc = now, FirstSeenUtc = now.AddHours(-1) },
			new RdpConnectionFact { Ip = "198.51.100.30", LastSeenUtc = now.AddHours(-2), FirstSeenUtc = now.AddHours(-3) },
			new RdpConnectionFact { Ip = "10.0.0.5", LastSeenUtc = now, FirstSeenUtc = now.AddHours(-1) });
		db.SaveChanges();
	}

	private static readonly DateTimeOffset NowUtc = new(2026, 9, 12, 10, 0, 0, TimeSpan.Zero);

	[Fact]
	public async Task RunOnceAsync_Disabled_DoesNothing()
	{
		(IDbContextFactory<AuditDbContext> factory, SqliteConnection connection) = await CreateDbAsync();
		await using (connection)
		{
			await using (AuditDbContext seed = factory.CreateDbContext())
			{
				SeedAttackStats(seed);
				SeedConnectionFacts(seed);
			}

			AbuseIpDbOptions options = EnabledOptions();
			options.CheckEnabled = false;
			FakeClient client = new();
			ThreatIntelEnrichmentWorker worker = CreateWorker(factory, options, client, NowUtc);

			int performed = await worker.RunOnceAsync(CancellationToken.None);

			Assert.Equal(0, performed);
			Assert.Empty(client.LookedUp);
		}
	}

	[Fact]
	public async Task RunOnceAsync_SkipsPrivateAndWhitelistedIps()
	{
		(IDbContextFactory<AuditDbContext> factory, SqliteConnection connection) = await CreateDbAsync();
		await using (connection)
		{
			await using (AuditDbContext seed = factory.CreateDbContext())
			{
				SeedAttackStats(seed);
				SeedConnectionFacts(seed);
				seed.WhitelistEntries.Add(new WhitelistEntry { Ip = "198.51.100.30" });
				await seed.SaveChangesAsync();
			}

			FakeClient client = new();
			ThreatIntelEnrichmentWorker worker = CreateWorker(factory, EnabledOptions(), client, NowUtc);

			int performed = await worker.RunOnceAsync(CancellationToken.None);

			Assert.Equal(2, performed);
			Assert.Equal(new[] { "203.0.113.10", "203.0.113.11" }, client.LookedUp.ToArray());
		}
	}

	[Fact]
	public async Task RunOnceAsync_SkipsFreshSuccessRows()
	{
		(IDbContextFactory<AuditDbContext> factory, SqliteConnection connection) = await CreateDbAsync();
		await using (connection)
		{
			await using (AuditDbContext seed = factory.CreateDbContext())
			{
				SeedAttackStats(seed);
				SeedConnectionFacts(seed);
				seed.ThreatIntelLookups.Add(new ThreatIntelLookup
				{
					Ip = "203.0.113.10",
					Outcome = (int)ThreatIntelLookupOutcome.Success,
					LookedUpUtc = NowUtc.UtcDateTime.AddHours(-1),
				});
				await seed.SaveChangesAsync();
			}

			FakeClient client = new();
			ThreatIntelEnrichmentWorker worker = CreateWorker(factory, EnabledOptions(), client, NowUtc);

			int performed = await worker.RunOnceAsync(CancellationToken.None);

			Assert.Equal(2, performed);
			Assert.Equal(new[] { "198.51.100.30", "203.0.113.11" }, client.LookedUp.ToArray());
		}
	}

	[Fact]
	public async Task RunOnceAsync_BackOff_SkipsIpWithFutureNextRetry()
	{
		(IDbContextFactory<AuditDbContext> factory, SqliteConnection connection) = await CreateDbAsync();
		await using (connection)
		{
			await using (AuditDbContext seed = factory.CreateDbContext())
			{
				SeedAttackStats(seed);
				SeedConnectionFacts(seed);
				seed.ThreatIntelLookups.Add(new ThreatIntelLookup
				{
					Ip = "203.0.113.10",
					Outcome = (int)ThreatIntelLookupOutcome.RateLimited,
					LookedUpUtc = NowUtc.UtcDateTime.AddMinutes(-1),
					NextRetryUtc = NowUtc.UtcDateTime.AddMinutes(10),
				});
				await seed.SaveChangesAsync();
			}

			FakeClient client = new();
			ThreatIntelEnrichmentWorker worker = CreateWorker(factory, EnabledOptions(), client, NowUtc);

			int performed = await worker.RunOnceAsync(CancellationToken.None);

			Assert.Equal(2, performed);
			Assert.Equal(new[] { "198.51.100.30", "203.0.113.11" }, client.LookedUp.ToArray());
		}
	}

	[Fact]
	public async Task RunOnceAsync_StopsWhenRateLimitReached()
	{
		(IDbContextFactory<AuditDbContext> factory, SqliteConnection connection) = await CreateDbAsync();
		await using (connection)
		{
			await using (AuditDbContext seed = factory.CreateDbContext())
			{
				for (int i = 0; i < 10; i++)
				{
					seed.AttackStats.Add(new AttackStat
					{
						Ip = "203.0.113." + (20 + i),
						ThreatScore = 90 - i,
						Failed = 10,
						LastSeenUtc = NowUtc.UtcDateTime,
						FirstSeenUtc = NowUtc.UtcDateTime.AddHours(-1),
						DurationSeconds = 3600,
					});
				}

				await seed.SaveChangesAsync();
			}

			AbuseIpDbOptions options = EnabledOptions();
			options.CheckMaxLookupsPerMinute = 3;
			FakeClient client = new();
			ThreatIntelEnrichmentWorker worker = CreateWorker(factory, options, client, NowUtc);

			int performed = await worker.RunOnceAsync(CancellationToken.None);

			Assert.Equal(3, performed);
			Assert.Equal(3, client.LookedUp.Count);
		}
	}

	[Fact]
	public async Task RunOnceAsync_ExistingCountCapsDailyBudget()
	{
		(IDbContextFactory<AuditDbContext> factory, SqliteConnection connection) = await CreateDbAsync();
		await using (connection)
		{
			await using (AuditDbContext seed = factory.CreateDbContext())
			{
				SeedAttackStats(seed);
				SeedConnectionFacts(seed);
				seed.ThreatIntelUsageCounters.Add(new ThreatIntelUsageCounter { DayDateUtc = "2026-09-12", Count = 499 });
				await seed.SaveChangesAsync();
			}

			FakeClient client = new();
			ThreatIntelEnrichmentWorker worker = CreateWorker(factory, EnabledOptions(), client, NowUtc);

			int performed = await worker.RunOnceAsync(CancellationToken.None);

			Assert.Equal(1, performed);
			Assert.Equal(new[] { "203.0.113.10" }, client.LookedUp.ToArray());
		}
	}

	[Fact]
	public async Task RunOnceAsync_RateLimitedResult_PersistsAndStopsPass()
	{
		(IDbContextFactory<AuditDbContext> factory, SqliteConnection connection) = await CreateDbAsync();
		await using (connection)
		{
			await using (AuditDbContext seed = factory.CreateDbContext())
			{
				SeedAttackStats(seed);
				SeedConnectionFacts(seed);
				await seed.SaveChangesAsync();
			}

			FakeClient client = new()
			{
				NextResult = new ThreatIntelLookupResult
				{
					Outcome = ThreatIntelLookupOutcome.RateLimited,
					Ip = string.Empty,
					ResponseCode = 429,
					RetryAfter = TimeSpan.FromMinutes(5),
				},
			};
			ThreatIntelEnrichmentWorker worker = CreateWorker(factory, EnabledOptions(), client, NowUtc);

			int performed = await worker.RunOnceAsync(CancellationToken.None);

			Assert.Equal(1, performed);
			Assert.Single(client.LookedUp);

			await using (AuditDbContext db = factory.CreateDbContext())
			{
				ThreatIntelLookup row = Assert.Single(db.ThreatIntelLookups.AsNoTracking().ToList());
				Assert.Equal((int)ThreatIntelLookupOutcome.RateLimited, row.Outcome);
				Assert.NotNull(row.NextRetryUtc);
			}
		}
	}

	[Fact]
	public async Task RunOnceAsync_ConcurrentCall_IsSkippedByGate()
	{
		(IDbContextFactory<AuditDbContext> factory, SqliteConnection connection) = await CreateDbAsync();
		await using (connection)
		{
			await using (AuditDbContext seed = factory.CreateDbContext())
			{
				SeedAttackStats(seed);
				SeedConnectionFacts(seed);
				await seed.SaveChangesAsync();
			}

			using SemaphoreSlim hold = new(0, 1);
			SlowClient client = new(hold);
			ThreatIntelEnrichmentWorker worker = CreateWorker(factory, EnabledOptions(), client, NowUtc);

			Task<int> first = worker.RunOnceAsync(CancellationToken.None);
			Task<int> second = worker.RunOnceAsync(CancellationToken.None);
			await Task.Delay(200);
			Assert.Equal(0, await second);
			hold.Release();
			Assert.Equal(3, await first);
		}
	}

	private sealed class SlowClient(SemaphoreSlim hold) : IThreatIntelligenceClient
	{
		private int _calls;
		public List<string> LookedUp { get; } = new();

		public async Task<ThreatIntelLookupResult> LookupAsync(string ip, CancellationToken ct)
		{
			LookedUp.Add(ip);
			if (Interlocked.Increment(ref _calls) == 1)
			{
				await hold.WaitAsync(ct);
			}

			return new ThreatIntelLookupResult
			{
				Outcome = ThreatIntelLookupOutcome.Success,
				Ip = ip,
				AbuseConfidenceScore = 90,
				IsPublic = true,
				IsWhitelisted = false,
			};
		}
	}
}
