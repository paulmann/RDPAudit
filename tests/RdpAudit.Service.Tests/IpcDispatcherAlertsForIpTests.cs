// File:    tests/RdpAudit.Service.Tests/IpcDispatcherAlertsForIpTests.cs
// Module:  RdpAudit.Service.Tests
// Purpose: End-to-end IPC dispatcher coverage for GetAlertsForIp (70): bounded newest-first
//          correlated alerts for one IP plus a total counter. Seeds an in-memory SQLite database,
//          drives the dispatcher directly, and asserts DTO shape, IP filtering, caps and
//          validation paths.
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

public class IpcDispatcherAlertsForIpTests
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

	private static async Task SeedAlertsAsync(IDbContextFactory<AuditDbContext> factory, string ip, int count)
	{
		await using AuditDbContext db = factory.CreateDbContext();
		for (int i = 0; i < count; i++)
		{
			db.Alerts.Add(new Alert
			{
				TimeUtc = Now.AddMinutes(-i),
				RuleId = "BruteForce",
				Severity = AlertSeverity.High,
				Message = "fixture-" + i.ToString(System.Globalization.CultureInfo.InvariantCulture),
				SourceIp = ip,
				UserName = "attacker",
				Acknowledged = i == 0,
				TriggerEventId = 1000L + i,
			});
		}

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
	public async Task GetAlertsForIp_ReturnsNewestFirstAlertsOnlyForRequestedIp()
	{
		(IDbContextFactory<AuditDbContext> factory, SqliteConnection conn) = await CreateDbAsync();
		try
		{
			await SeedAlertsAsync(factory, "203.0.113.7", 3);
			await SeedAlertsAsync(factory, "198.51.100.4", 2);
			IpcDispatcher dispatcher = CreateDispatcher(factory, new RdpAuditOptions());

			AlertsForIpRequest req = new() { Ip = "203.0.113.7", Limit = 0 };
			AlertsForIpDto dto = await CallAsync<AlertsForIpDto>(dispatcher, IpcCommand.GetAlertsForIp, req);

			Assert.Equal(IpcResultStatus.Success, dto.Status);
			Assert.Equal("203.0.113.7", dto.Ip);
			Assert.Equal(3, dto.TotalAlerts);
			Assert.Equal(3, dto.Alerts.Count);
			Assert.All(dto.Alerts, a => Assert.Equal("203.0.113.7", a.SourceIp));
			Assert.True(dto.Alerts[0].TimeUtc >= dto.Alerts[^1].TimeUtc);
			Assert.Equal("BruteForce", dto.Alerts[0].RuleId);
			Assert.Equal(AlertSeverity.High, dto.Alerts[0].Severity);
			Assert.Equal("fixture-0", dto.Alerts[0].Message);
			Assert.Equal("attacker", dto.Alerts[0].UserName);
			Assert.True(dto.Alerts[0].Acknowledged);
			Assert.Equal(1000L, dto.Alerts[0].TriggerEventId);
			Assert.False(dto.Alerts[1].Acknowledged);
			Assert.Equal(1001L, dto.Alerts[1].TriggerEventId);
		}
		finally
		{
			await conn.DisposeAsync();
		}
	}

	[Fact]
	public async Task GetAlertsForIp_AppliesDefaultCapAndReportsTotal()
	{
		(IDbContextFactory<AuditDbContext> factory, SqliteConnection conn) = await CreateDbAsync();
		try
		{
			await SeedAlertsAsync(factory, "203.0.113.7", 205);
			IpcDispatcher dispatcher = CreateDispatcher(factory, new RdpAuditOptions());

			AlertsForIpRequest req = new() { Ip = "203.0.113.7", Limit = 0 };
			AlertsForIpDto dto = await CallAsync<AlertsForIpDto>(dispatcher, IpcCommand.GetAlertsForIp, req);

			Assert.Equal(200, dto.Alerts.Count);
			Assert.Equal(205, dto.TotalAlerts);
		}
		finally
		{
			await conn.DisposeAsync();
		}
	}

	[Fact]
	public async Task GetAlertsForIp_ClampsRequestedLimit()
	{
		(IDbContextFactory<AuditDbContext> factory, SqliteConnection conn) = await CreateDbAsync();
		try
		{
			await SeedAlertsAsync(factory, "203.0.113.7", 5);
			IpcDispatcher dispatcher = CreateDispatcher(factory, new RdpAuditOptions());

			AlertsForIpRequest req = new() { Ip = "203.0.113.7", Limit = 2 };
			AlertsForIpDto dto = await CallAsync<AlertsForIpDto>(dispatcher, IpcCommand.GetAlertsForIp, req);

			Assert.Equal(2, dto.Alerts.Count);
			Assert.Equal(5, dto.TotalAlerts);
		}
		finally
		{
			await conn.DisposeAsync();
		}
	}

	[Fact]
	public async Task GetAlertsForIp_ReturnsErrorOnInvalidIp()
	{
		(IDbContextFactory<AuditDbContext> factory, SqliteConnection conn) = await CreateDbAsync();
		try
		{
			IpcDispatcher dispatcher = CreateDispatcher(factory, new RdpAuditOptions());

			IpcRequest req = new()
			{
				Command = IpcCommand.GetAlertsForIp,
				Payload = JsonSerializer.Serialize(new AlertsForIpRequest { Ip = "not-an-ip", Limit = 0 }, JsonOptions.Default),
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
	public async Task GetAlertsForIp_RejectsEmptyPayload()
	{
		(IDbContextFactory<AuditDbContext> factory, SqliteConnection conn) = await CreateDbAsync();
		try
		{
			IpcDispatcher dispatcher = CreateDispatcher(factory, new RdpAuditOptions());

			IpcRequest req = new() { Command = IpcCommand.GetAlertsForIp };
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
	public async Task GetAlertsForIp_RejectsMalformedJson()
	{
		(IDbContextFactory<AuditDbContext> factory, SqliteConnection conn) = await CreateDbAsync();
		try
		{
			IpcDispatcher dispatcher = CreateDispatcher(factory, new RdpAuditOptions());

			IpcRequest req = new()
			{
				Command = IpcCommand.GetAlertsForIp,
				Payload = "{not-json",
			};

			IpcResponse response = await dispatcher.DispatchAsync(req, CancellationToken.None);
			Assert.False(response.Success);
			Assert.Contains("not valid JSON", response.Error, StringComparison.OrdinalIgnoreCase);
		}
		finally
		{
			await conn.DisposeAsync();
		}
	}
}
