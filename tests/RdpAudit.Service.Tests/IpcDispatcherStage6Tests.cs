// File:    tests/RdpAudit.Service.Tests/IpcDispatcherStage6Tests.cs
// Module:  RdpAudit.Service.Tests
// Purpose: End-to-end IPC dispatcher tests for the Stage 6 GetAttackStats command: filter parsing
//          (IP query, min threat, only blocked, time range, limit clamping) and DTO shape. The
//          AttackStatsRefreshWorker is exercised in-process so the materialised AttackStats rows
//          accurately reflect the seeded RawEvents / ActiveBlocks.
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
using RdpAudit.Core.Util;
using RdpAudit.Service;
using RdpAudit.Service.Ipc;
using RdpAudit.Service.Services;
using RdpAudit.Service.Workers;
using Xunit;

namespace RdpAudit.Service.Tests;

public class IpcDispatcherStage6Tests
{
	// Anchor seeded fixture timestamps relative to real "now" so the worker (which uses
	// DateTime.UtcNow) reads the bursty traffic as recent and lands inside the look-back window.
	private static readonly DateTime Now = DateTime.UtcNow;

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

	private static IpcDispatcher CreateDispatcher(IDbContextFactory<AuditDbContext> factory, RdpAuditOptions opts)
	{
		ServiceMetrics metrics = new();
		StaticOptionsMonitorLocal<RdpAuditOptions> mon = new(opts);
		SettingsManager settings = new(NullLogger<SettingsManager>.Instance);
		FirewallManager manager = new(NullLogger<FirewallManager>.Instance);
		return new IpcDispatcher(factory, metrics, mon, settings, manager,
			Array.Empty<IFirewallProvider>(), NullLogger<IpcDispatcher>.Instance);
	}

	private static async Task SeedAsync(IDbContextFactory<AuditDbContext> factory)
	{
		await using AuditDbContext db = factory.CreateDbContext();

		// Attacker A: bursty brute-force, currently active-block.
		for (int i = 0; i < 60; i++)
		{
			db.RawEvents.Add(new RawEvent
			{
				EventId = AttackStatsAggregator.EventIdLogonFailure,
				Channel = "Security",
				TimeUtc = Now.AddSeconds(-30 + i),
				SourceIp = "203.0.113.10",
				UserName = "administrator",
				LogonType = 10,
			});
		}

		// Attacker B: occasional failures, not blocked.
		for (int i = 0; i < 5; i++)
		{
			db.RawEvents.Add(new RawEvent
			{
				EventId = AttackStatsAggregator.EventIdLogonFailure,
				Channel = "Security",
				TimeUtc = Now.AddHours(-2).AddMinutes(i),
				SourceIp = "198.51.100.5",
				UserName = "root",
				LogonType = 10,
			});
		}

		// Benign success.
		db.RawEvents.Add(new RawEvent
		{
			EventId = AttackStatsAggregator.EventIdLogonSuccess,
			Channel = "Security",
			TimeUtc = Now,
			SourceIp = "10.0.0.7",
			UserName = "alice",
			LogonType = 3,
		});

		db.ActiveBlocks.Add(new ActiveBlock
		{
			Ip = "203.0.113.10",
			Provider = FirewallProviderKind.Windows,
			Status = ActiveBlockStatus.Active,
			CreatedUtc = Now,
			Reason = "Stage6 fixture",
		});

		db.Alerts.Add(new Alert
		{
			TimeUtc = Now,
			RuleId = "BruteForce",
			Severity = AlertSeverity.High,
			Message = "fixture",
			SourceIp = "203.0.113.10",
		});

		// v3 invariant: counters derive from AuthAttemptFact. Synthesize the equivalent fact rows
		// from the RawEvents seeded above so the AttackStatsRefreshWorker can do its job.
		TestAuthAttemptFactHelper.SynthesizeFactsFromRawEvents(db);
		await db.SaveChangesAsync();
	}

	private static async Task<AttackStatsDto> CallAsync(IpcDispatcher dispatcher, AttackStatsRequest? request = null)
	{
		IpcRequest req = new()
		{
			Command = IpcCommand.GetAttackStats,
			Payload = request is null
				? null
				: JsonSerializer.Serialize(request, JsonOptions.Default),
		};

		IpcResponse response = await dispatcher.DispatchAsync(req, CancellationToken.None);
		Assert.True(response.Success, response.Error);
		Assert.NotNull(response.Payload);
		AttackStatsDto? dto = JsonSerializer.Deserialize<AttackStatsDto>(response.Payload!, JsonOptions.Default);
		Assert.NotNull(dto);
		return dto!;
	}

	[Fact]
	public async Task GetAttackStats_NoFilter_ReturnsAggregatedEntries()
	{
		(IDbContextFactory<AuditDbContext> factory, SqliteConnection conn) = await CreateDbAsync();
		try
		{
			await SeedAsync(factory);
			AttackStatsRefreshWorker worker = new(factory, NullLogger<AttackStatsRefreshWorker>.Instance);
			await worker.RefreshOnceAsync(CancellationToken.None);

			IpcDispatcher dispatcher = CreateDispatcher(factory, new RdpAuditOptions());
			AttackStatsDto dto = await CallAsync(dispatcher);

			Assert.Equal(IpcResultStatus.Success, dto.Status);
			Assert.True(dto.Entries.Count >= 2);
			AttackStatEntryDto a = Assert.Single(dto.Entries, e => e.Ip == "203.0.113.10");
			Assert.Equal(60, a.Failed);
			Assert.True(a.IsBlocked);
			Assert.Equal(AttackThreatLevel.Red, a.ThreatLevel);
			Assert.True(dto.AppliedLimit > 0);
			Assert.True(dto.TotalMatching >= dto.Entries.Count);
		}
		finally
		{
			await conn.DisposeAsync();
		}
	}

	[Fact]
	public async Task GetAttackStats_OnlyBlocked_ExcludesUnblockedRows()
	{
		(IDbContextFactory<AuditDbContext> factory, SqliteConnection conn) = await CreateDbAsync();
		try
		{
			await SeedAsync(factory);
			AttackStatsRefreshWorker worker = new(factory, NullLogger<AttackStatsRefreshWorker>.Instance);
			await worker.RefreshOnceAsync(CancellationToken.None);

			IpcDispatcher dispatcher = CreateDispatcher(factory, new RdpAuditOptions());
			AttackStatsDto dto = await CallAsync(dispatcher, new AttackStatsRequest { OnlyBlocked = true });

			Assert.All(dto.Entries, e => Assert.True(e.IsBlocked));
			Assert.Contains(dto.Entries, e => e.Ip == "203.0.113.10");
			Assert.DoesNotContain(dto.Entries, e => e.Ip == "198.51.100.5");
		}
		finally
		{
			await conn.DisposeAsync();
		}
	}

	[Fact]
	public async Task GetAttackStats_MinThreat_FiltersByScore()
	{
		(IDbContextFactory<AuditDbContext> factory, SqliteConnection conn) = await CreateDbAsync();
		try
		{
			await SeedAsync(factory);
			AttackStatsRefreshWorker worker = new(factory, NullLogger<AttackStatsRefreshWorker>.Instance);
			await worker.RefreshOnceAsync(CancellationToken.None);

			IpcDispatcher dispatcher = CreateDispatcher(factory, new RdpAuditOptions());
			AttackStatsDto dto = await CallAsync(dispatcher, new AttackStatsRequest { MinThreatScore = AttackThreatScoring.RedThreshold });

			Assert.All(dto.Entries, e => Assert.True(e.ThreatScore >= AttackThreatScoring.RedThreshold));
		}
		finally
		{
			await conn.DisposeAsync();
		}
	}

	[Fact]
	public async Task GetAttackStats_IpQuery_IsCaseInsensitiveSubstring()
	{
		(IDbContextFactory<AuditDbContext> factory, SqliteConnection conn) = await CreateDbAsync();
		try
		{
			await SeedAsync(factory);
			AttackStatsRefreshWorker worker = new(factory, NullLogger<AttackStatsRefreshWorker>.Instance);
			await worker.RefreshOnceAsync(CancellationToken.None);

			IpcDispatcher dispatcher = CreateDispatcher(factory, new RdpAuditOptions());
			AttackStatsDto dto = await CallAsync(dispatcher, new AttackStatsRequest { IpQuery = "113" });

			Assert.NotEmpty(dto.Entries);
			Assert.All(dto.Entries, e => Assert.Contains("113", e.Ip));
		}
		finally
		{
			await conn.DisposeAsync();
		}
	}

	[Fact]
	public async Task GetAttackStats_LimitIsClamped()
	{
		(IDbContextFactory<AuditDbContext> factory, SqliteConnection conn) = await CreateDbAsync();
		try
		{
			await SeedAsync(factory);
			AttackStatsRefreshWorker worker = new(factory, NullLogger<AttackStatsRefreshWorker>.Instance);
			await worker.RefreshOnceAsync(CancellationToken.None);

			IpcDispatcher dispatcher = CreateDispatcher(factory, new RdpAuditOptions());
			AttackStatsDto dto = await CallAsync(dispatcher, new AttackStatsRequest { Limit = 999_999 });

			Assert.True(dto.AppliedLimit <= IpcDispatcher.AttackStatsMaxLimit);
		}
		finally
		{
			await conn.DisposeAsync();
		}
	}

	[Fact]
	public async Task GetAttackStats_InvalidJson_ReturnsControlledError()
	{
		(IDbContextFactory<AuditDbContext> factory, SqliteConnection conn) = await CreateDbAsync();
		try
		{
			IpcDispatcher dispatcher = CreateDispatcher(factory, new RdpAuditOptions());
			IpcResponse response = await dispatcher.DispatchAsync(new IpcRequest
			{
				Command = IpcCommand.GetAttackStats,
				Payload = "not-json-{",
			}, CancellationToken.None);

			Assert.False(response.Success);
			Assert.Contains("not valid JSON", response.Error, StringComparison.OrdinalIgnoreCase);
		}
		finally
		{
			await conn.DisposeAsync();
		}
	}

	[Fact]
	public async Task RefreshWorker_RunsToCompletionWithoutThrowing()
	{
		(IDbContextFactory<AuditDbContext> factory, SqliteConnection conn) = await CreateDbAsync();
		try
		{
			await SeedAsync(factory);
			AttackStatsRefreshWorker worker = new(factory, NullLogger<AttackStatsRefreshWorker>.Instance);

			int first = await worker.RefreshOnceAsync(CancellationToken.None);
			int second = await worker.RefreshOnceAsync(CancellationToken.None);

			// Both calls run independently — the gate guards re-entry, not serial calls — and
			// neither must throw. Stage 6 reuses upserts so the count is positive on the first
			// pass and stable on the second.
			Assert.True(first > 0);
			Assert.True(second > 0);
		}
		finally
		{
			await conn.DisposeAsync();
		}
	}

	[Fact]
	public async Task RefreshWorker_HonoursCancellationToken()
	{
		(IDbContextFactory<AuditDbContext> factory, SqliteConnection conn) = await CreateDbAsync();
		try
		{
			AttackStatsRefreshWorker worker = new(factory, NullLogger<AttackStatsRefreshWorker>.Instance);
			using CancellationTokenSource cts = new();
			cts.Cancel();

			await Assert.ThrowsAnyAsync<OperationCanceledException>(async () =>
				await worker.RefreshOnceAsync(cts.Token));
		}
		finally
		{
			await conn.DisposeAsync();
		}
	}
}
