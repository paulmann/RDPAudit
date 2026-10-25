// File:    tests/RdpAudit.Service.Tests/IpcDispatcherStage15ThreatIntelTests.cs
// Module:  RdpAudit.Service.Tests
// Purpose: End-to-end IPC dispatcher coverage for Stage 15 threat-intel enrichment: cache-only
//          High-risk stamping on GetAttackStats / ListConnectionFacts / GetRecentEvents (fail-closed
//          when the pipeline is disabled, rows are stale, or outcomes are non-Success) and the
//          GetThreatIntelStatus (ordinal 71) status handler. Never performs HTTP: everything is
//          seeded into the in-memory SQLite cache.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System.Text.Json;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using RdpAudit.Core.Config;
using RdpAudit.Core.Data;
using RdpAudit.Core.Firewall;
using RdpAudit.Core.Ipc;
using RdpAudit.Core.Ipc.Contracts;
using RdpAudit.Core.Models;
using RdpAudit.Core.ThreatIntel;
using RdpAudit.Core.Util;
using RdpAudit.Service.Ipc;
using RdpAudit.Service.Services;
using RdpAudit.Service.ThreatIntel;
using RdpAudit.Service.Workers;
using Xunit;

namespace RdpAudit.Service.Tests;

public class IpcDispatcherStage15ThreatIntelTests
{
	private static readonly DateTime Now = new(2026, 6, 1, 12, 0, 0, DateTimeKind.Utc);

	private sealed class TestDbContextFactory : IDbContextFactory<AuditDbContext>
	{
		private readonly DbContextOptions<AuditDbContext> _options;
		public TestDbContextFactory(DbContextOptions<AuditDbContext> options) => _options = options;
		public AuditDbContext CreateDbContext() => new(_options);
	}

	private sealed class StaticOptionsMonitorLocal<T> : IOptionsMonitor<T>
	{
		public StaticOptionsMonitorLocal(T value) => CurrentValue = value;
		public T CurrentValue { get; }
		public T Get(string? name) => CurrentValue;
		public IDisposable? OnChange(Action<T, string?> listener) => null;
	}

	private sealed class FakeTimeProvider : TimeProvider
	{
		private readonly DateTimeOffset _now;
		public FakeTimeProvider(DateTime utc) => _now = new DateTimeOffset(utc, TimeSpan.Zero);
		public override DateTimeOffset GetUtcNow() => _now;
	}

	private sealed class FakeThreatIntelClient : IThreatIntelligenceClient
	{
		public Task<ThreatIntelLookupResult> LookupAsync(string ip, CancellationToken ct)
			=> Task.FromResult(new ThreatIntelLookupResult
			{
				Outcome = ThreatIntelLookupOutcome.NotConfigured,
				Ip = ip,
			});
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

	private static RdpAuditOptions MakeOptions(bool pipelineEnabled = true) => new()
	{
		AbuseIpDb = new AbuseIpDbOptions
		{
			Enabled = pipelineEnabled,
			CheckEnabled = pipelineEnabled,
			CacheLookups = true,
			CheckMaxLookupsPerDay = 500,
			CheckMaxAgeInDays = 30,
			ReportThreshold = 80,
		},
	};

	private static IpcDispatcher CreateDispatcher(
		IDbContextFactory<AuditDbContext> factory,
		RdpAuditOptions? options = null,
		ThreatIntelLookupStore? store = null,
		ThreatIntelEnrichmentWorker? worker = null)
	{
		ServiceMetrics metrics = new();
		StaticOptionsMonitorLocal<RdpAuditOptions> mon = new(options ?? new RdpAuditOptions());
		SettingsManager settings = new(NullLogger<SettingsManager>.Instance);
		FirewallManager manager = new(NullLogger<FirewallManager>.Instance);
		return new IpcDispatcher(factory, metrics, mon, settings, manager,
			Array.Empty<IFirewallProvider>(), NullLogger<IpcDispatcher>.Instance,
			threatIntelStore: store,
			threatIntelWorker: worker);
	}

	private static async Task<T> CallAsync<T>(IpcDispatcher dispatcher, IpcCommand command, object? payload = null)
	{
		IpcRequest req = new()
		{
			Command = command,
			Payload = payload is null ? null : JsonSerializer.Serialize(payload, JsonOptions.Default),
		};

		IpcResponse response = await dispatcher.DispatchAsync(req, CancellationToken.None);
		Assert.True(response.Success, response.Error);
		Assert.NotNull(response.Payload);
		T? dto = JsonSerializer.Deserialize<T>(response.Payload!, JsonOptions.Default);
		Assert.NotNull(dto);
		return dto!;
	}

	private static ThreatIntelLookup MakeSuccessRow(
		string ip,
		int score,
		DateTime lookedUpUtc,
		bool isPublic = true,
		bool isWhitelisted = false) => new()
		{
			Ip = ip,
			LookedUpUtc = lookedUpUtc,
			Outcome = (int)ThreatIntelLookupOutcome.Success,
			Score = score,
			TotalReports = 42,
			IsWhitelisted = isWhitelisted,
			IsPublic = isPublic,
			UsageType = "Data Center",
			CountryCode = "US",
		};

	private static ThreatIntelLookup MakeRejectedRow(string ip, DateTime lookedUpUtc) => new()
	{
		Ip = ip,
		LookedUpUtc = lookedUpUtc,
		Outcome = (int)ThreatIntelLookupOutcome.TransportError,
	};

	private static AttackStat MakeAttackStat(string ip) => new()
	{
		Ip = ip,
		TotalAttempts = 10,
		Failed = 10,
		Successful = 0,
		FirstSeenUtc = Now.AddHours(-2),
		LastSeenUtc = Now,
		ThreatScore = 70,
		Top10AttemptedLogins = "[]",
		LastUpdatedUtc = Now,
	};

	private static RdpConnectionFact MakeFact(string ip) => new()
	{
		Ip = ip,
		UserName = "tester",
		LogonId = "0x9000",
		FirstSeenUtc = Now.AddMinutes(-10),
		LastSeenUtc = Now,
		FailedLogons = 2,
		ObservedEventIds = "4625",
		UserNamesAttempted = "tester",
		IsActive = false,
	};

	private static RawEvent MakeRawEvent(string ip) => new()
	{
		EventId = 4625,
		Channel = "Security",
		TimeUtc = Now.AddMinutes(-1),
		SourceIp = ip,
		SourceIpDerived = false,
		SourceIpUnresolved = false,
		UserName = "admin",
	};

	[Fact]
	public async Task GetAttackStats_StampsHighRiskFromFreshCacheRows()
	{
		(IDbContextFactory<AuditDbContext> factory, SqliteConnection conn) = await CreateDbAsync();
		try
		{
			await using (AuditDbContext db = factory.CreateDbContext())
			{
				db.AttackStats.Add(MakeAttackStat("203.0.113.7"));
				db.AttackStats.Add(MakeAttackStat("203.0.113.8"));
				db.ThreatIntelLookups.Add(MakeSuccessRow("203.0.113.7", 95, Now.AddMinutes(-5)));
				await db.SaveChangesAsync();
			}

			FakeTimeProvider time = new(Now);
			IpcDispatcher dispatcher = CreateDispatcher(factory, MakeOptions(),
				new ThreatIntelLookupStore(factory, time));

			AttackStatsDto dto = await CallAsync<AttackStatsDto>(dispatcher,
				IpcCommand.GetAttackStats, new AttackStatsRequest());

			AttackStatEntryDto risky = dto.Entries.Single(e => e.Ip == "203.0.113.7");
			Assert.True(risky.IsHighRisk);
			Assert.Equal(95, risky.ThreatIntelConfidenceScore);

			AttackStatEntryDto missing = dto.Entries.Single(e => e.Ip == "203.0.113.8");
			Assert.False(missing.IsHighRisk);
			Assert.Equal(0, missing.ThreatIntelConfidenceScore);
		}
		finally
		{
			await conn.DisposeAsync();
		}
	}

	[Fact]
	public async Task GetAttackStats_FailClosed_WhenPipelineDisabled()
	{
		(IDbContextFactory<AuditDbContext> factory, SqliteConnection conn) = await CreateDbAsync();
		try
		{
			await using (AuditDbContext db = factory.CreateDbContext())
			{
				db.AttackStats.Add(MakeAttackStat("203.0.113.7"));
				db.ThreatIntelLookups.Add(MakeSuccessRow("203.0.113.7", 95, Now.AddMinutes(-5)));
				await db.SaveChangesAsync();
			}

			FakeTimeProvider time = new(Now);
			RdpAuditOptions options = MakeOptions(pipelineEnabled: false);
			IpcDispatcher dispatcher = CreateDispatcher(factory, options,
				new ThreatIntelLookupStore(factory, time));

			AttackStatsDto dto = await CallAsync<AttackStatsDto>(dispatcher,
				IpcCommand.GetAttackStats, new AttackStatsRequest());

			AttackStatEntryDto entry = Assert.Single(dto.Entries);
			Assert.False(entry.IsHighRisk);
			Assert.Equal(0, entry.ThreatIntelConfidenceScore);
		}
		finally
		{
			await conn.DisposeAsync();
		}
	}

	[Fact]
	public async Task GetAttackStats_FailClosed_WhenRowStaleOrNonSuccess()
	{
		(IDbContextFactory<AuditDbContext> factory, SqliteConnection conn) = await CreateDbAsync();
		try
		{
			await using (AuditDbContext db = factory.CreateDbContext())
			{
				db.AttackStats.Add(MakeAttackStat("203.0.113.7"));
				db.AttackStats.Add(MakeAttackStat("203.0.113.8"));
				db.AttackStats.Add(MakeAttackStat("203.0.113.9"));
				db.ThreatIntelLookups.Add(MakeSuccessRow("203.0.113.7", 95, Now.AddDays(-40)));
				db.ThreatIntelLookups.Add(MakeRejectedRow("203.0.113.8", Now.AddMinutes(-5)));
				await db.SaveChangesAsync();
			}

			FakeTimeProvider time = new(Now);
			IpcDispatcher dispatcher = CreateDispatcher(factory, MakeOptions(),
				new ThreatIntelLookupStore(factory, time));

			AttackStatsDto dto = await CallAsync<AttackStatsDto>(dispatcher,
				IpcCommand.GetAttackStats, new AttackStatsRequest());

			Assert.All(dto.Entries, e =>
			{
				Assert.False(e.IsHighRisk);
				Assert.Equal(0, e.ThreatIntelConfidenceScore);
			});
		}
		finally
		{
			await conn.DisposeAsync();
		}
	}

	[Fact]
	public async Task ListConnectionFacts_StampsHighRiskFromFreshCacheRows()
	{
		(IDbContextFactory<AuditDbContext> factory, SqliteConnection conn) = await CreateDbAsync();
		try
		{
			await using (AuditDbContext db = factory.CreateDbContext())
			{
				db.RdpConnectionFacts.Add(MakeFact("203.0.113.7"));
				db.RdpConnectionFacts.Add(MakeFact("198.51.100.9"));
				db.ThreatIntelLookups.Add(MakeSuccessRow("203.0.113.7", 88, Now.AddMinutes(-5)));
				await db.SaveChangesAsync();
			}

			FakeTimeProvider time = new(Now);
			IpcDispatcher dispatcher = CreateDispatcher(factory, MakeOptions(),
				new ThreatIntelLookupStore(factory, time));

			ConnectionFactsDto dto = await CallAsync<ConnectionFactsDto>(dispatcher,
				IpcCommand.ListConnectionFacts, new ConnectionFactsRequest());

			ConnectionFactDto risky = dto.Facts.Single(f => f.Ip == "203.0.113.7");
			Assert.True(risky.IsHighRisk);
			Assert.Equal(88, risky.ThreatIntelConfidenceScore);

			ConnectionFactDto missing = dto.Facts.Single(f => f.Ip == "198.51.100.9");
			Assert.False(missing.IsHighRisk);
			Assert.Equal(0, missing.ThreatIntelConfidenceScore);
		}
		finally
		{
			await conn.DisposeAsync();
		}
	}

	private sealed class RecentEventRowProbe
	{
		public long id { get; set; }
		public int eventId { get; set; }
		public string? sourceIp { get; set; }
		public bool isHighRisk { get; set; }
		public int threatIntelConfidenceScore { get; set; }
	}

	[Fact]
	public async Task GetRecentEvents_StampsHighRiskFromFreshCacheRows()
	{
		(IDbContextFactory<AuditDbContext> factory, SqliteConnection conn) = await CreateDbAsync();
		try
		{
			await using (AuditDbContext db = factory.CreateDbContext())
			{
				db.RawEvents.Add(MakeRawEvent("203.0.113.7"));
				db.RawEvents.Add(MakeRawEvent("198.51.100.9"));
				db.ThreatIntelLookups.Add(MakeSuccessRow("203.0.113.7", 91, Now.AddMinutes(-5)));
				await db.SaveChangesAsync();
			}

			FakeTimeProvider time = new(Now);
			IpcDispatcher dispatcher = CreateDispatcher(factory, MakeOptions(),
				new ThreatIntelLookupStore(factory, time));

			IpcRequest req = new() { Command = IpcCommand.GetRecentEvents };
			IpcResponse response = await dispatcher.DispatchAsync(req, CancellationToken.None);
			Assert.True(response.Success, response.Error);
			Assert.NotNull(response.Payload);

			List<RecentEventRowProbe> rows =
				JsonSerializer.Deserialize<List<RecentEventRowProbe>>(response.Payload!, JsonOptions.Default)!;
			Assert.NotNull(rows);

			RecentEventRowProbe risky = rows.Single(r => r.sourceIp == "203.0.113.7");
			Assert.True(risky.isHighRisk);
			Assert.Equal(91, risky.threatIntelConfidenceScore);

			RecentEventRowProbe missing = rows.Single(r => r.sourceIp == "198.51.100.9");
			Assert.False(missing.isHighRisk);
			Assert.Equal(0, missing.threatIntelConfidenceScore);
		}
		finally
		{
			await conn.DisposeAsync();
		}
	}

	[Fact]
	public async Task GetThreatIntelStatus_ReportsCountsUsageAndPassTelemetry()
	{
		(IDbContextFactory<AuditDbContext> factory, SqliteConnection conn) = await CreateDbAsync();
		try
		{
			await using (AuditDbContext db = factory.CreateDbContext())
			{
				db.ThreatIntelLookups.Add(MakeSuccessRow("203.0.113.7", 95, Now.AddMinutes(-5)));
				db.ThreatIntelLookups.Add(MakeSuccessRow("198.51.100.9", 20, Now.AddMinutes(-5)));
				db.ThreatIntelLookups.Add(MakeRejectedRow("203.0.113.8", Now.AddMinutes(-5)));
				db.ThreatIntelUsageCounters.Add(new ThreatIntelUsageCounter
				{
					DayDateUtc = "2026-06-01",
					Count = 17,
				});
				await db.SaveChangesAsync();
			}

			FakeTimeProvider time = new(Now);
			RdpAuditOptions options = MakeOptions();
			StaticOptionsMonitorLocal<RdpAuditOptions> mon = new(options);
			ThreatIntelLookupStore store = new(factory, time);
			ThreatIntelRateLimiter rateLimiter = new(time);
			ThreatIntelEnrichmentWorker worker = new(factory, mon, new FakeThreatIntelClient(),
				store, rateLimiter, NullLogger<ThreatIntelEnrichmentWorker>.Instance, time);

			int performed = await worker.RunOnceAsync(CancellationToken.None);

			IpcDispatcher dispatcher = CreateDispatcher(factory, options, store, worker);
			ThreatIntelStatusDto dto = await CallAsync<ThreatIntelStatusDto>(dispatcher,
				IpcCommand.GetThreatIntelStatus);

			Assert.Equal(IpcResultStatus.Success, dto.Status);
			Assert.True(dto.CheckEnabled);
			Assert.Equal(3, dto.TotalCacheRows);
			Assert.Equal(2, dto.SuccessCacheRows);
			Assert.Equal(2, dto.FreshSuccessRows);
			Assert.Equal(17, dto.DailyUsage);
			Assert.Equal(500, dto.DailyBudget);
			Assert.Equal(80, dto.HighRiskThreshold);
			Assert.Equal(0, performed);
			Assert.NotNull(dto.LastPassStartedUtc);
			Assert.NotNull(dto.LastPassFinishedUtc);
			Assert.Null(dto.LastPassError);
			Assert.Equal(2, dto.OutcomeCounts.Count);
			Assert.Equal((int)ThreatIntelLookupOutcome.Success, dto.OutcomeCounts[0].Outcome);
			Assert.Equal(2, dto.OutcomeCounts[0].Count);
			Assert.Equal((int)ThreatIntelLookupOutcome.TransportError, dto.OutcomeCounts[1].Outcome);
			Assert.Equal(1, dto.OutcomeCounts[1].Count);
		}
		finally
		{
			await conn.DisposeAsync();
		}
	}

	[Fact]
	public async Task GetThreatIntelStatus_NoStore_ReturnsUnavailable()
	{
		(IDbContextFactory<AuditDbContext> factory, SqliteConnection conn) = await CreateDbAsync();
		try
		{
			IpcDispatcher dispatcher = CreateDispatcher(factory, MakeOptions());
			ThreatIntelStatusDto dto = await CallAsync<ThreatIntelStatusDto>(dispatcher,
				IpcCommand.GetThreatIntelStatus);

			Assert.Equal(IpcResultStatus.Unavailable, dto.Status);
			Assert.False(string.IsNullOrEmpty(dto.Message));
		}
		finally
		{
			await conn.DisposeAsync();
		}
	}
}
