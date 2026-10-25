// File:    tests/RdpAudit.Service.Tests/IpcDispatcherStageATests.cs
// Module:  RdpAudit.Service.Tests
// Purpose: End-to-end IPC dispatcher coverage for Stage A: GetOverviewSummary (38) and
//          GetEventsForIp (39). Seeds an in-memory SQLite database, drives the dispatcher
//          directly, and asserts DTO shape, counter accuracy, and validation paths.
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
using RdpAudit.Service.Ipc;
using RdpAudit.Service.Services;
using Xunit;

namespace RdpAudit.Service.Tests;

public class IpcDispatcherStageATests
{
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

		// Failures from the attacker within the trailing 24 hours.
		for (int i = 0; i < 12; i++)
		{
			db.RawEvents.Add(new RawEvent
			{
				EventId = AttackStatsAggregator.EventIdLogonFailure,
				Channel = "Security",
				TimeUtc = Now.AddMinutes(-30 + i),
				SourceIp = "203.0.113.7",
				UserName = i % 2 == 0 ? "administrator" : "root",
				LogonType = 10,
				AuthPackage = "NTLM",
				ProcessName = "C:\\Windows\\System32\\svchost.exe",
				Status = "0xC000006A",
			});
		}

		// One successful logon from a benign IP — verifies FailedLogins24h excludes it.
		db.RawEvents.Add(new RawEvent
		{
			EventId = AttackStatsAggregator.EventIdLogonSuccess,
			Channel = "Security",
			TimeUtc = Now,
			SourceIp = "10.0.0.7",
			UserName = "alice",
			LogonType = 3,
		});

		// Active block tied to the attacker IP — drives BlockedIps and IsBlocked.
		db.ActiveBlocks.Add(new ActiveBlock
		{
			Ip = "203.0.113.7",
			Provider = FirewallProviderKind.Windows,
			Status = ActiveBlockStatus.Active,
			CreatedUtc = Now,
			Reason = "StageA fixture",
		});

		// Two alerts today (within the UTC-day window).
		db.Alerts.Add(new Alert
		{
			TimeUtc = Now,
			RuleId = "BruteForce",
			Severity = AlertSeverity.High,
			Message = "fixture-1",
			SourceIp = "203.0.113.7",
		});
		db.Alerts.Add(new Alert
		{
			TimeUtc = Now,
			RuleId = "BruteForce",
			Severity = AlertSeverity.High,
			Message = "fixture-2",
			SourceIp = "203.0.113.7",
		});

		// Pre-populate AttackStats so the GetEventsForIp threat-level projection is exercised.
		db.AttackStats.Add(new AttackStat
		{
			Ip = "203.0.113.7",
			TotalAttempts = 12,
			Failed = 12,
			Successful = 0,
			FirstSeenUtc = Now.AddMinutes(-30),
			LastSeenUtc = Now,
			DurationSeconds = 1800,
			ThreatScore = 90,
			IsBlocked = true,
			LastUpdatedUtc = Now,
		});

		await db.SaveChangesAsync();
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

	[Fact]
	public async Task GetOverviewSummary_AggregatesAlertsBlocksAndFailedLogins()
	{
		(IDbContextFactory<AuditDbContext> factory, SqliteConnection conn) = await CreateDbAsync();
		try
		{
			await SeedAsync(factory);
			IpcDispatcher dispatcher = CreateDispatcher(factory, new RdpAuditOptions());

			OverviewSummaryDto dto = await CallAsync<OverviewSummaryDto>(dispatcher, IpcCommand.GetOverviewSummary);

			Assert.Equal(IpcResultStatus.Success, dto.Status);
			Assert.Equal(2, dto.AttacksToday);
			Assert.Equal(1, dto.BlockedIps);
			Assert.Equal(12, dto.FailedLogins24h);
			Assert.Equal(0, dto.ActiveSessions); // non-Windows host / no session manager.
			Assert.Equal("Running", dto.ServiceHealth);
		}
		finally
		{
			await conn.DisposeAsync();
		}
	}

	[Fact]
	public async Task GetEventsForIp_ReturnsBoundedEventsAndSummaryMetadata()
	{
		(IDbContextFactory<AuditDbContext> factory, SqliteConnection conn) = await CreateDbAsync();
		try
		{
			await SeedAsync(factory);
			IpcDispatcher dispatcher = CreateDispatcher(factory, new RdpAuditOptions());

			EventsForIpRequest req = new() { Ip = "203.0.113.7", Limit = 0 };
			EventsForIpDto dto = await CallAsync<EventsForIpDto>(dispatcher, IpcCommand.GetEventsForIp, req);

			Assert.Equal(IpcResultStatus.Success, dto.Status);
			Assert.Equal("203.0.113.7", dto.Ip);
			Assert.Equal(12, dto.TotalEvents);
			Assert.Equal(12, dto.FailedCount);
			Assert.Equal(0, dto.SuccessCount);
			Assert.NotNull(dto.FirstSeenUtc);
			Assert.NotNull(dto.LastSeenUtc);
			Assert.True(dto.DurationSeconds > 0);
			Assert.Contains("administrator", dto.AttemptedUserNames);
			Assert.Contains("root", dto.AttemptedUserNames);
			Assert.True(dto.IsBlocked);
			Assert.False(string.IsNullOrEmpty(dto.AttackType));
			Assert.False(string.IsNullOrEmpty(dto.ThreatLevel));
			Assert.Equal(12, dto.Events.Count);
			// Newest first ordering check: the first event has TimeUtc >= the last event.
			Assert.True(dto.Events.First().TimeUtc >= dto.Events.Last().TimeUtc);
		}
		finally
		{
			await conn.DisposeAsync();
		}
	}

	[Fact]
	public async Task GetEventsForIp_ClampsRequestedLimit()
	{
		(IDbContextFactory<AuditDbContext> factory, SqliteConnection conn) = await CreateDbAsync();
		try
		{
			await SeedAsync(factory);
			IpcDispatcher dispatcher = CreateDispatcher(factory, new RdpAuditOptions());

			EventsForIpRequest req = new() { Ip = "203.0.113.7", Limit = 3 };
			EventsForIpDto dto = await CallAsync<EventsForIpDto>(dispatcher, IpcCommand.GetEventsForIp, req);

			Assert.Equal(3, dto.Events.Count);
			Assert.Equal(12, dto.TotalEvents);
		}
		finally
		{
			await conn.DisposeAsync();
		}
	}

	[Fact]
	public async Task GetEventsForIp_ReturnsErrorOnInvalidIp()
	{
		(IDbContextFactory<AuditDbContext> factory, SqliteConnection conn) = await CreateDbAsync();
		try
		{
			IpcDispatcher dispatcher = CreateDispatcher(factory, new RdpAuditOptions());

			IpcRequest req = new()
			{
				Command = IpcCommand.GetEventsForIp,
				Payload = JsonSerializer.Serialize(new EventsForIpRequest { Ip = "not-an-ip", Limit = 0 }, JsonOptions.Default),
			};

			IpcResponse response = await dispatcher.DispatchAsync(req, CancellationToken.None);
			Assert.False(response.Success);
			Assert.False(string.IsNullOrEmpty(response.Error));
		}
		finally
		{
			await conn.DisposeAsync();
		}
	}

	[Fact]
	public async Task GetEventsForIp_RejectsEmptyPayload()
	{
		(IDbContextFactory<AuditDbContext> factory, SqliteConnection conn) = await CreateDbAsync();
		try
		{
			IpcDispatcher dispatcher = CreateDispatcher(factory, new RdpAuditOptions());

			IpcRequest req = new() { Command = IpcCommand.GetEventsForIp };
			IpcResponse response = await dispatcher.DispatchAsync(req, CancellationToken.None);
			Assert.False(response.Success);
			Assert.False(string.IsNullOrEmpty(response.Error));
		}
		finally
		{
			await conn.DisposeAsync();
		}
	}
}
