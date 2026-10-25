// File:    tests/RdpAudit.ScenarioTests/ThreatIntelHighRiskScenarioTests.cs
// Module:  RdpAudit.ScenarioTests
// Purpose: Tier 3 scenario coverage for Backlog #5 threat-intel High-risk marking.
//          Scenario 1 (happy path): fresh cached snapshots reach GetAttackStats /
//          ListConnectionFacts / GetRecentEvents with the Configurator wire shape and
//          GetThreatIntelStatus reports counts, usage and worker-pass telemetry; a counting
//          fake provider proves the whole IPC path is cache-only (zero HTTP lookups).
//          Scenario 2 (edge): a stale Success row and a transport-error row can never
//          manufacture a High-risk mark, even when the stored abuse score is extreme.
//          Scenario 3 (off-state): with the Check switch disabled every grid row stays
//          fail-closed and the status command reports the switch state.
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
using RdpAudit.Service;
using RdpAudit.Service.Ipc;
using RdpAudit.Service.Services;
using RdpAudit.Service.ThreatIntel;
using RdpAudit.Service.Workers;
using Xunit;

namespace RdpAudit.ScenarioTests;

/// <summary>End-to-end user scenarios for the SOC operator's High-risk reputation column:
/// cached threat-intel reaches every grid and the status page, stale / failed cache rows stay
/// fail-closed, the disabled switch keeps every grid clean, and no HTTP ever runs on the IPC path.</summary>
public sealed class ThreatIntelHighRiskScenarioTests
{
	/// <summary>Attacker with a FRESH, high-confidence cached snapshot: flagged everywhere.</summary>
	private const string AttackerIp = "203.0.113.7";

	/// <summary>IP whose only snapshot is STALE (40 days old): fail-closed, never flagged.</summary>
	private const string StaleIp = "203.0.113.8";

	/// <summary>IP whose only snapshot is a transport error: fail-closed, never flagged.</summary>
	private const string FailedIp = "198.51.100.9";

	/// <summary>IP with no cache row at all: fail-closed by definition.</summary>
	private const string UncachedIp = "198.51.100.11";

	/// <summary>Fixed UTC instant shared by the fake clock, the cache rows and the daily counter key.</summary>
	private static readonly DateTime Now = new(2026, 6, 1, 12, 0, 0, DateTimeKind.Utc);

	private sealed class TestDbContextFactory : IDbContextFactory<AuditDbContext>
	{
		private readonly DbContextOptions<AuditDbContext> _options;
		public TestDbContextFactory(DbContextOptions<AuditDbContext> options) => _options = options;
		public AuditDbContext CreateDbContext() => new(_options);
	}

	private sealed class StaticOptionsMonitor : IOptionsMonitor<RdpAuditOptions>
	{
		private readonly RdpAuditOptions _value;
		public StaticOptionsMonitor(RdpAuditOptions value) => _value = value;
		public RdpAuditOptions CurrentValue => _value;
		public RdpAuditOptions Get(string? name) => _value;
		public IDisposable? OnChange(Action<RdpAuditOptions, string?> listener) => null;
	}

	private sealed class FakeTimeProvider : TimeProvider
	{
		private readonly DateTimeOffset _now;
		public FakeTimeProvider(DateTime utc) => _now = new DateTimeOffset(utc, TimeSpan.Zero);
		public override DateTimeOffset GetUtcNow() => _now;
	}

	/// <summary>Fake provider client that only counts calls. The happy-path scenario fails when
	/// the IPC path ever performs a lookup: every response must come from the seeded cache.</summary>
	private sealed class CountingThreatIntelClient : IThreatIntelligenceClient
	{
		public int CallCount { get; private set; }

		public Task<ThreatIntelLookupResult> LookupAsync(string ip, CancellationToken ct)
		{
			CallCount++;
			return Task.FromResult(new ThreatIntelLookupResult
			{
				Outcome = ThreatIntelLookupOutcome.NotConfigured,
				Ip = ip,
			});
		}
	}

	/// <summary>CamelCase JSON probe matching the Configurator's Live Events tail contract.</summary>
	private sealed class RecentEventRowProbe
	{
		public string? sourceIp { get; set; }
		public bool isHighRisk { get; set; }
		public int threatIntelConfidenceScore { get; set; }
	}

	private static async Task<(IDbContextFactory<AuditDbContext> Factory, SqliteConnection Connection)> CreateDbAsync()
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
		RdpAuditOptions options,
		ThreatIntelLookupStore? store = null,
		ThreatIntelEnrichmentWorker? worker = null)
	{
		ServiceMetrics metrics = new();
		StaticOptionsMonitor monitor = new(options);
		SettingsManager settings = new(NullLogger<SettingsManager>.Instance);
		FirewallManager firewall = new(NullLogger<FirewallManager>.Instance);
		return new IpcDispatcher(factory, metrics, monitor, settings, firewall,
			Array.Empty<IFirewallProvider>(), NullLogger<IpcDispatcher>.Instance,
			threatIntelStore: store,
			threatIntelWorker: worker);
	}

	private static async Task<T> CallAsync<T>(IpcDispatcher dispatcher, IpcCommand command, object? payload = null)
	{
		IpcRequest request = new()
		{
			Command = command,
			Payload = payload is null ? null : JsonSerializer.Serialize(payload, JsonOptions.Default),
		};

		IpcResponse response = await dispatcher.DispatchAsync(request, CancellationToken.None);
		Assert.True(response.Success, response.Error);
		Assert.NotNull(response.Payload);
		T? dto = JsonSerializer.Deserialize<T>(response.Payload!, JsonOptions.Default);
		Assert.NotNull(dto);
		return dto!;
	}

	private static ThreatIntelLookup MakeSuccessRow(
		string ip,
		int score,
		DateTime lookedUpUtc) => new()
	{
		Ip = ip,
		LookedUpUtc = lookedUpUtc,
		Outcome = (int)ThreatIntelLookupOutcome.Success,
		Score = score,
		TotalReports = 42,
		IsWhitelisted = false,
		IsPublic = true,
		UsageType = "Data Center",
		CountryCode = "US",
	};

	private static ThreatIntelLookup MakeTransportErrorRow(string ip, DateTime lookedUpUtc) => new()
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

	/// <summary>Seeds the happy-path cache state: fresh / stale Success rows, one transport-error
	/// row and today's persisted usage counter.</summary>
	private static async Task SeedFullCacheAsync(IDbContextFactory<AuditDbContext> factory)
	{
		await using AuditDbContext db = factory.CreateDbContext();
		db.ThreatIntelLookups.Add(MakeSuccessRow(AttackerIp, 95, Now.AddMinutes(-5)));
		db.ThreatIntelLookups.Add(MakeSuccessRow(StaleIp, 97, Now.AddDays(-40)));
		db.ThreatIntelLookups.Add(MakeTransportErrorRow(FailedIp, Now.AddMinutes(-5)));
		db.ThreatIntelUsageCounters.Add(new ThreatIntelUsageCounter { DayDateUtc = "2026-06-01", Count = 17 });
		await db.SaveChangesAsync();
	}

	/// <summary>Seeds the edge-case cache state: one stale Success and one transport-error row.</summary>
	private static async Task SeedStaleCacheAsync(IDbContextFactory<AuditDbContext> factory)
	{
		await using AuditDbContext db = factory.CreateDbContext();
		db.ThreatIntelLookups.Add(MakeSuccessRow(StaleIp, 97, Now.AddDays(-40)));
		db.ThreatIntelLookups.Add(MakeTransportErrorRow(FailedIp, Now.AddMinutes(-5)));
		await db.SaveChangesAsync();
	}

	/// <summary>Seeds exactly one fresh attacker snapshot used by the disabled-switch scenario.</summary>
	private static async Task SeedFreshAttackerCacheAsync(IDbContextFactory<AuditDbContext> factory)
	{
		await using AuditDbContext db = factory.CreateDbContext();
		db.ThreatIntelLookups.Add(MakeSuccessRow(AttackerIp, 95, Now.AddMinutes(-5)));
		await db.SaveChangesAsync();
	}

	/// <summary>Seeds one AttackStat, one connection fact and one raw event per supplied IP.</summary>
	private static async Task SeedActivityAsync(IDbContextFactory<AuditDbContext> factory, params string[] ips)
	{
		await using AuditDbContext db = factory.CreateDbContext();
		foreach (string ip in ips)
		{
			db.AttackStats.Add(MakeAttackStat(ip));
			db.RawEvents.Add(MakeRawEvent(ip));
			db.RdpConnectionFacts.Add(MakeFact(ip));
		}

		await db.SaveChangesAsync();
	}

	private static void AssertFailClosed(bool isHighRisk, int score)
	{
		Assert.False(isHighRisk);
		Assert.Equal(0, score);
	}

	[Fact]
	public async Task FreshSnapshot_StampsAllGrids_StatusCounts_AndZeroHttp()
	{
		(IDbContextFactory<AuditDbContext> factory, SqliteConnection conn) = await CreateDbAsync();
		try
		{
			await SeedFullCacheAsync(factory);

			FakeTimeProvider time = new(Now);
			RdpAuditOptions options = MakeOptions();
			StaticOptionsMonitor monitor = new(options);
			CountingThreatIntelClient client = new();
			ThreatIntelLookupStore store = new(factory, time);
			ThreatIntelRateLimiter rateLimiter = new(time);
			ThreatIntelEnrichmentWorker worker = new(factory, monitor, client, store, rateLimiter,
				NullLogger<ThreatIntelEnrichmentWorker>.Instance, time);

			// One background pass over the still-empty candidate set records telemetry
			// without a single provider call.
			int performed = await worker.RunOnceAsync(CancellationToken.None);
			Assert.Equal(0, performed);
			Assert.Equal(0, client.CallCount);

			await SeedActivityAsync(factory, AttackerIp, StaleIp, FailedIp);
			IpcDispatcher dispatcher = CreateDispatcher(factory, options, store, worker);

			AttackStatsDto stats = await CallAsync<AttackStatsDto>(dispatcher,
				IpcCommand.GetAttackStats, new AttackStatsRequest());
			Assert.Equal(IpcResultStatus.Success, stats.Status);
			Assert.Equal(3, stats.Entries.Count);
			AttackStatEntryDto flaggedStat = stats.Entries.Single(e => e.Ip == AttackerIp);
			Assert.True(flaggedStat.IsHighRisk);
			Assert.Equal(95, flaggedStat.ThreatIntelConfidenceScore);
			AssertFailClosed(stats.Entries.Single(e => e.Ip == StaleIp).IsHighRisk,
				stats.Entries.Single(e => e.Ip == StaleIp).ThreatIntelConfidenceScore);
			AssertFailClosed(stats.Entries.Single(e => e.Ip == FailedIp).IsHighRisk,
				stats.Entries.Single(e => e.Ip == FailedIp).ThreatIntelConfidenceScore);

			ConnectionFactsDto facts = await CallAsync<ConnectionFactsDto>(dispatcher,
				IpcCommand.ListConnectionFacts, new ConnectionFactsRequest());
			Assert.Equal(IpcResultStatus.Success, facts.Status);
			Assert.Equal(3, facts.Facts.Count);
			ConnectionFactDto flaggedFact = facts.Facts.Single(f => f.Ip == AttackerIp);
			Assert.True(flaggedFact.IsHighRisk);
			Assert.Equal(95, flaggedFact.ThreatIntelConfidenceScore);
			AssertFailClosed(facts.Facts.Single(f => f.Ip == StaleIp).IsHighRisk,
				facts.Facts.Single(f => f.Ip == StaleIp).ThreatIntelConfidenceScore);
			AssertFailClosed(facts.Facts.Single(f => f.Ip == FailedIp).IsHighRisk,
				facts.Facts.Single(f => f.Ip == FailedIp).ThreatIntelConfidenceScore);

			IpcRequest tailRequest = new() { Command = IpcCommand.GetRecentEvents };
			IpcResponse tailResponse = await dispatcher.DispatchAsync(tailRequest, CancellationToken.None);
			Assert.True(tailResponse.Success, tailResponse.Error);
			Assert.NotNull(tailResponse.Payload);
			List<RecentEventRowProbe> liveRows = JsonSerializer
				.Deserialize<List<RecentEventRowProbe>>(tailResponse.Payload!, JsonOptions.Default)!;
			Assert.NotNull(liveRows);
			Assert.Equal(3, liveRows.Count);
			RecentEventRowProbe flaggedLive = liveRows.Single(r => r.sourceIp == AttackerIp);
			Assert.True(flaggedLive.isHighRisk);
			Assert.Equal(95, flaggedLive.threatIntelConfidenceScore);
			AssertFailClosed(liveRows.Single(r => r.sourceIp == StaleIp).isHighRisk,
				liveRows.Single(r => r.sourceIp == StaleIp).threatIntelConfidenceScore);
			AssertFailClosed(liveRows.Single(r => r.sourceIp == FailedIp).isHighRisk,
				liveRows.Single(r => r.sourceIp == FailedIp).threatIntelConfidenceScore);

			ThreatIntelStatusDto status = await CallAsync<ThreatIntelStatusDto>(dispatcher,
				IpcCommand.GetThreatIntelStatus);
			Assert.Equal(IpcResultStatus.Success, status.Status);
			Assert.True(status.CheckEnabled);
			Assert.Equal(3, status.TotalCacheRows);
			Assert.Equal(2, status.SuccessCacheRows);
			Assert.Equal(1, status.FreshSuccessRows);
			Assert.Equal(17, status.DailyUsage);
			Assert.Equal(500, status.DailyBudget);
			Assert.Equal(80, status.HighRiskThreshold);
			Assert.NotNull(status.LastPassStartedUtc);
			Assert.NotNull(status.LastPassFinishedUtc);
			Assert.Null(status.LastPassError);
			Assert.Equal(2, status.OutcomeCounts.Count);
			Assert.Equal((int)ThreatIntelLookupOutcome.Success, status.OutcomeCounts[0].Outcome);
			Assert.Equal(2, status.OutcomeCounts[0].Count);
			Assert.Equal((int)ThreatIntelLookupOutcome.TransportError, status.OutcomeCounts[1].Outcome);
			Assert.Equal(1, status.OutcomeCounts[1].Count);

			// The counting client must still be at zero: cache-only end to end.
			Assert.Equal(0, client.CallCount);
		}
		finally
		{
			await conn.DisposeAsync();
		}
	}

	[Fact]
	public async Task StaleOrFailedSnapshots_NeverManufactureHighRisk()
	{
		(IDbContextFactory<AuditDbContext> factory, SqliteConnection conn) = await CreateDbAsync();
		try
		{
			await SeedStaleCacheAsync(factory);
			await SeedActivityAsync(factory, StaleIp, FailedIp);

			FakeTimeProvider time = new(Now);
			IpcDispatcher dispatcher = CreateDispatcher(factory, MakeOptions(), new ThreatIntelLookupStore(factory, time));

			AttackStatsDto stats = await CallAsync<AttackStatsDto>(dispatcher,
				IpcCommand.GetAttackStats, new AttackStatsRequest());
			Assert.Equal(2, stats.Entries.Count);
			Assert.All(stats.Entries,
				e => AssertFailClosed(e.IsHighRisk, e.ThreatIntelConfidenceScore));

			IpcRequest tailRequest = new() { Command = IpcCommand.GetRecentEvents };
			IpcResponse tailResponse = await dispatcher.DispatchAsync(tailRequest, CancellationToken.None);
			Assert.True(tailResponse.Success, tailResponse.Error);
			List<RecentEventRowProbe> liveRows = JsonSerializer
				.Deserialize<List<RecentEventRowProbe>>(tailResponse.Payload!, JsonOptions.Default)!;
			Assert.Equal(2, liveRows.Count);
			Assert.All(liveRows,
				r => AssertFailClosed(r.isHighRisk, r.threatIntelConfidenceScore));

			ThreatIntelStatusDto status = await CallAsync<ThreatIntelStatusDto>(dispatcher,
				IpcCommand.GetThreatIntelStatus);
			Assert.Equal(IpcResultStatus.Success, status.Status);
			Assert.Equal(2, status.TotalCacheRows);
			Assert.Equal(1, status.SuccessCacheRows);
			Assert.Equal(0, status.FreshSuccessRows);
		}
		finally
		{
			await conn.DisposeAsync();
		}
	}

	[Fact]
	public async Task DisabledSwitch_KeepsEveryGridFailClosed_AndStatusReportsOff()
	{
		(IDbContextFactory<AuditDbContext> factory, SqliteConnection conn) = await CreateDbAsync();
		try
		{
			await SeedFreshAttackerCacheAsync(factory);
			await SeedActivityAsync(factory, AttackerIp, UncachedIp);

			FakeTimeProvider time = new(Now);
			RdpAuditOptions options = MakeOptions(pipelineEnabled: false);
			IpcDispatcher dispatcher = CreateDispatcher(factory, options, new ThreatIntelLookupStore(factory, time));

			AttackStatsDto stats = await CallAsync<AttackStatsDto>(dispatcher,
				IpcCommand.GetAttackStats, new AttackStatsRequest());
			Assert.Equal(2, stats.Entries.Count);
			Assert.All(stats.Entries,
				e => AssertFailClosed(e.IsHighRisk, e.ThreatIntelConfidenceScore));

			ConnectionFactsDto facts = await CallAsync<ConnectionFactsDto>(dispatcher,
				IpcCommand.ListConnectionFacts, new ConnectionFactsRequest());
			Assert.Equal(2, facts.Facts.Count);
			Assert.All(facts.Facts,
				f => AssertFailClosed(f.IsHighRisk, f.ThreatIntelConfidenceScore));

			IpcRequest tailRequest = new() { Command = IpcCommand.GetRecentEvents };
			IpcResponse tailResponse = await dispatcher.DispatchAsync(tailRequest, CancellationToken.None);
			Assert.True(tailResponse.Success, tailResponse.Error);
			List<RecentEventRowProbe> liveRows = JsonSerializer
				.Deserialize<List<RecentEventRowProbe>>(tailResponse.Payload!, JsonOptions.Default)!;
			Assert.Equal(2, liveRows.Count);
			Assert.All(liveRows,
				r => AssertFailClosed(r.isHighRisk, r.threatIntelConfidenceScore));

			ThreatIntelStatusDto status = await CallAsync<ThreatIntelStatusDto>(dispatcher,
				IpcCommand.GetThreatIntelStatus);
			Assert.Equal(IpcResultStatus.Success, status.Status);
			Assert.False(status.CheckEnabled);
		}
		finally
		{
			await conn.DisposeAsync();
		}
	}
}
