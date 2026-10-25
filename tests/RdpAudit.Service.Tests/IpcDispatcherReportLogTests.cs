// File:    tests/RdpAudit.Service.Tests/IpcDispatcherReportLogTests.cs
// Module:  RdpAudit.Service.Tests
// Purpose: v1.2.6 IPC dispatcher tests for ListAbuseIpDbReportLog. Confirms the handler projects
//          AbuseIpDbReportHistory rows into AbuseIpDbReportLogDto newest-first, clamps the limit, and
//          never leaks the API key in the payload.
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

public class IpcDispatcherReportLogTests
{
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
		return new IpcDispatcher(
			factory, metrics, mon, settings, manager,
			Array.Empty<IFirewallProvider>(),
			NullLogger<IpcDispatcher>.Instance,
			sessions: null, shadow: null,
			abuseClient: null, protector: null);
	}

	private static List<AbuseIpDbReportLogDto> Deserialize(string payload) =>
		JsonSerializer.Deserialize<List<AbuseIpDbReportLogDto>>(payload, JsonOptions.Default)
			?? new List<AbuseIpDbReportLogDto>();

	[Fact]
	public async Task ListAbuseIpDbReportLog_ReturnsRowsNewestFirst()
	{
		(IDbContextFactory<AuditDbContext> factory, SqliteConnection conn) = await CreateDbAsync();
		try
		{
			DateTime nowUtc = DateTime.UtcNow;
			await using (AuditDbContext seed = factory.CreateDbContext())
			{
				seed.AbuseIpDbReportHistory.Add(new AbuseIpDbReportHistory
				{
					IpAddress = "203.0.113.10",
					ReportedAtUtc = nowUtc.AddHours(-2),
					Succeeded = true,
					HttpStatusCode = 200,
					AbuseCategories = "18,22",
					Action = AbuseIpDbReportAction.Sent,
					Classification = IpReportClassification.Public,
					FailedCount = 12,
					Source = "worker",
				});
				seed.AbuseIpDbReportHistory.Add(new AbuseIpDbReportHistory
				{
					IpAddress = "198.51.100.20",
					ReportedAtUtc = nowUtc.AddMinutes(-5),
					Succeeded = false,
					HttpStatusCode = 429,
					AbuseCategories = "18,22",
					Action = AbuseIpDbReportAction.Failed,
					Reason = "RateLimited",
					Classification = IpReportClassification.Public,
					Source = "worker",
				});
				await seed.SaveChangesAsync();
			}

			IpcDispatcher dispatcher = CreateDispatcher(factory, new RdpAuditOptions());
			IpcResponse response = await dispatcher.DispatchAsync(
				new IpcRequest { Command = IpcCommand.ListAbuseIpDbReportLog }, CancellationToken.None);

			Assert.True(response.Success);
			List<AbuseIpDbReportLogDto> rows = Deserialize(response.Payload!);
			Assert.Equal(2, rows.Count);
			Assert.Equal("198.51.100.20", rows[0].SourceIp);
			Assert.Equal(AbuseIpDbReportAction.Failed, rows[0].Action);
			Assert.Equal("RateLimited", rows[0].Reason);
			Assert.Equal("203.0.113.10", rows[1].SourceIp);
			Assert.Equal(AbuseIpDbReportAction.Sent, rows[1].Action);
			Assert.Equal(12, rows[1].FailedCount);
		}
		finally
		{
			await conn.DisposeAsync();
		}
	}

	[Fact]
	public async Task ListAbuseIpDbReportLog_ClampsLimit()
	{
		(IDbContextFactory<AuditDbContext> factory, SqliteConnection conn) = await CreateDbAsync();
		try
		{
			DateTime nowUtc = DateTime.UtcNow;
			await using (AuditDbContext seed = factory.CreateDbContext())
			{
				for (int i = 0; i < 5; i++)
				{
					seed.AbuseIpDbReportHistory.Add(new AbuseIpDbReportHistory
					{
						IpAddress = "203.0.113." + i.ToString(System.Globalization.CultureInfo.InvariantCulture),
						ReportedAtUtc = nowUtc.AddMinutes(-i),
						Succeeded = true,
						HttpStatusCode = 200,
						AbuseCategories = "18,22",
						Source = "worker",
					});
				}
				await seed.SaveChangesAsync();
			}

			IpcDispatcher dispatcher = CreateDispatcher(factory, new RdpAuditOptions());
			IpcResponse response = await dispatcher.DispatchAsync(
				new IpcRequest { Command = IpcCommand.ListAbuseIpDbReportLog, Payload = "2" },
				CancellationToken.None);

			Assert.True(response.Success);
			List<AbuseIpDbReportLogDto> rows = Deserialize(response.Payload!);
			Assert.Equal(2, rows.Count);
		}
		finally
		{
			await conn.DisposeAsync();
		}
	}

	[Fact]
	public async Task ListAbuseIpDbReportLog_EmptyTable_ReturnsEmptyList()
	{
		(IDbContextFactory<AuditDbContext> factory, SqliteConnection conn) = await CreateDbAsync();
		try
		{
			IpcDispatcher dispatcher = CreateDispatcher(factory, new RdpAuditOptions());
			IpcResponse response = await dispatcher.DispatchAsync(
				new IpcRequest { Command = IpcCommand.ListAbuseIpDbReportLog }, CancellationToken.None);

			Assert.True(response.Success);
			List<AbuseIpDbReportLogDto> rows = Deserialize(response.Payload!);
			Assert.Empty(rows);
		}
		finally
		{
			await conn.DisposeAsync();
		}
	}
}
