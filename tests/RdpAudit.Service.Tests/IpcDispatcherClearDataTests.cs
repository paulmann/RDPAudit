// File:    tests/RdpAudit.Service.Tests/IpcDispatcherClearDataTests.cs
// Module:  RdpAudit.Service.Tests
// Purpose: Tests for the v1.3.2 ClearAllApplicationData IPC command guard. Confirms the dispatcher
//          REFUSES the destructive purge unless the exact typed confirmation phrase is supplied in the
//          payload, and that with the correct phrase the purge runs and clears the seeded operational
//          data. This is the server-side barrier behind the DEBUG gate and the typed-confirmation dialog.
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

public class IpcDispatcherClearDataTests
{
	private const string ConfirmationPhrase = "CLEAR ALL RDP AUDIT DATA";

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

	private static IpcDispatcher CreateDispatcher(IDbContextFactory<AuditDbContext> factory)
	{
		ServiceMetrics metrics = new();
		StaticOptionsMonitorLocal<RdpAuditOptions> mon = new(new RdpAuditOptions());
		SettingsManager settings = new(NullLogger<SettingsManager>.Instance);
		FirewallManager manager = new(NullLogger<FirewallManager>.Instance);
		ApplicationDataPurgeService purge = new(
			factory, NullLogger<ApplicationDataPurgeService>.Instance, TimeProvider.System);
		return new IpcDispatcher(
			factory, metrics, mon, settings, manager,
			Array.Empty<IFirewallProvider>(),
			NullLogger<IpcDispatcher>.Instance,
			sessions: null, shadow: null,
			abuseClient: null, protector: null,
			mikroTikClient: null,
			dataPurge: purge);
	}

	private static async Task SeedRawEventAsync(IDbContextFactory<AuditDbContext> factory)
	{
		await using AuditDbContext db = factory.CreateDbContext();
		db.RawEvents.Add(new RawEvent { Channel = "Security", EventId = 4625, TimeUtc = DateTime.UtcNow });
		await db.SaveChangesAsync();
	}

	private static async Task<AppDataPurgeResultDto> DispatchAsync(IpcDispatcher dispatcher, string? payloadPhrase)
	{
		string? payload = payloadPhrase is null
			? null
			: JsonSerializer.Serialize(payloadPhrase, JsonOptions.Default);
		IpcResponse response = await dispatcher.DispatchAsync(
			new IpcRequest { Command = IpcCommand.ClearAllApplicationData, Payload = payload },
			CancellationToken.None);
		Assert.True(response.Success);
		AppDataPurgeResultDto? dto = JsonSerializer.Deserialize<AppDataPurgeResultDto>(response.Payload!, JsonOptions.Default);
		Assert.NotNull(dto);
		return dto!;
	}

	[Fact]
	public async Task ClearAllApplicationData_WrongPhrase_IsRefused_AndPreservesData()
	{
		(IDbContextFactory<AuditDbContext> factory, SqliteConnection conn) = await CreateDbAsync();
		try
		{
			await SeedRawEventAsync(factory);
			IpcDispatcher dispatcher = CreateDispatcher(factory);

			AppDataPurgeResultDto result = await DispatchAsync(dispatcher, "not the phrase");

			Assert.Equal(IpcResultStatus.Refused, result.Status);
			Assert.Empty(result.TablesCleared);

			await using AuditDbContext verify = factory.CreateDbContext();
			Assert.Equal(1, await verify.RawEvents.CountAsync());
		}
		finally
		{
			await conn.DisposeAsync();
		}
	}

	[Fact]
	public async Task ClearAllApplicationData_MissingPayload_IsRefused()
	{
		(IDbContextFactory<AuditDbContext> factory, SqliteConnection conn) = await CreateDbAsync();
		try
		{
			await SeedRawEventAsync(factory);
			IpcDispatcher dispatcher = CreateDispatcher(factory);

			AppDataPurgeResultDto result = await DispatchAsync(dispatcher, null);

			Assert.Equal(IpcResultStatus.Refused, result.Status);

			await using AuditDbContext verify = factory.CreateDbContext();
			Assert.Equal(1, await verify.RawEvents.CountAsync());
		}
		finally
		{
			await conn.DisposeAsync();
		}
	}

	[Fact]
	public async Task ClearAllApplicationData_CorrectPhrase_PurgesData()
	{
		(IDbContextFactory<AuditDbContext> factory, SqliteConnection conn) = await CreateDbAsync();
		try
		{
			await SeedRawEventAsync(factory);
			IpcDispatcher dispatcher = CreateDispatcher(factory);

			AppDataPurgeResultDto result = await DispatchAsync(dispatcher, ConfirmationPhrase);

			Assert.Equal(IpcResultStatus.Success, result.Status);
			Assert.Equal(1, Assert.Single(result.TablesCleared, t => t.Table == "RawEvents").RowsCleared);

			await using AuditDbContext verify = factory.CreateDbContext();
			Assert.Equal(0, await verify.RawEvents.CountAsync());
		}
		finally
		{
			await conn.DisposeAsync();
		}
	}
}
