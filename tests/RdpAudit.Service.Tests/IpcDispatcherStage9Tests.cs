// File:    tests/RdpAudit.Service.Tests/IpcDispatcherStage9Tests.cs
// Module:  RdpAudit.Service.Tests
// Purpose: Stage 9 IPC dispatcher tests. Exercises GetMikroTikStatus and TestMikroTik against an
//          in-memory SQLite database with a stubbed MikroTik client. Confirms:
//            • status DTOs never contain plaintext passwords or envelope payloads,
//            • CredentialPresent / Configured reflect the configured fields,
//            • TestMikroTik rejects missing fields, accepts successful probes, and returns
//              Refused when the remote rejects credentials.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System.Text.Json;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using RdpAudit.Core.AbuseIpDb;
using RdpAudit.Core.Config;
using RdpAudit.Core.Data;
using RdpAudit.Core.Firewall;
using RdpAudit.Core.Ipc;
using RdpAudit.Core.Ipc.Contracts;
using RdpAudit.Core.MikroTik;
using RdpAudit.Core.Models;
using RdpAudit.Core.Security;
using RdpAudit.Core.Util;
using RdpAudit.Service.Ipc;
using RdpAudit.Service.Services;
using Xunit;

namespace RdpAudit.Service.Tests;

public class IpcDispatcherStage9Tests
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

	private sealed class FakeMikroTikClient : IMikroTikClient
	{
		public MikroTikOperationResult PingResult { get; set; } = new() { Outcome = MikroTikOutcome.Accepted, ResponseCode = 200, Message = "ok" };

		public Task<MikroTikOperationResult> AddBlockAsync(MikroTikBlockRequest request, CancellationToken ct)
			=> Task.FromResult(new MikroTikOperationResult { Outcome = MikroTikOutcome.Accepted });

		public Task<(MikroTikOperationResult Result, IReadOnlyList<MikroTikRule> Rules)> ListOwnedRulesAsync(CancellationToken ct)
			=> Task.FromResult((new MikroTikOperationResult { Outcome = MikroTikOutcome.Accepted }, (IReadOnlyList<MikroTikRule>)Array.Empty<MikroTikRule>()));

		public Task<MikroTikOperationResult> PingAsync(CancellationToken ct) => Task.FromResult(PingResult);

		public Task<MikroTikOperationResult> RemoveBlockAsync(string? ruleId, string ip, CancellationToken ct)
			=> Task.FromResult(new MikroTikOperationResult { Outcome = MikroTikOutcome.Accepted });
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

	private static IpcDispatcher CreateDispatcher(
		IDbContextFactory<AuditDbContext> factory,
		RdpAuditOptions opts,
		IMikroTikClient? mikroTik = null,
		IAbuseIpDbClient? abuse = null,
		ISecretProtector? protector = null)
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
			abuseClient: abuse, protector: protector,
			mikroTikClient: mikroTik);
	}

	[Fact]
	public async Task GetMikroTikStatus_NoConfig_ReportsUnconfigured()
	{
		(IDbContextFactory<AuditDbContext> factory, SqliteConnection conn) = await CreateDbAsync();
		try
		{
			RdpAuditOptions opts = new();
			IpcDispatcher dispatcher = CreateDispatcher(factory, opts);

			IpcResponse response = await dispatcher.DispatchAsync(
				new IpcRequest { Command = IpcCommand.GetMikroTikStatus }, CancellationToken.None);

			Assert.True(response.Success);
			MikroTikStatusDto? dto = JsonSerializer.Deserialize<MikroTikStatusDto>(response.Payload!, JsonOptions.Default);
			Assert.NotNull(dto);
			Assert.False(dto!.Configured);
			Assert.False(dto.CredentialPresent);
			Assert.False(dto.Enabled);
		}
		finally
		{
			await conn.DisposeAsync();
		}
	}

	[Fact]
	public async Task GetMikroTikStatus_WithCredential_DoesNotEchoPassword()
	{
		(IDbContextFactory<AuditDbContext> factory, SqliteConnection conn) = await CreateDbAsync();
		try
		{
			RdpAuditOptions opts = new();
			opts.MikroTik.Enabled = true;
			opts.MikroTik.AddAttackerRules = true;
			opts.MikroTik.Host = "router.lab";
			opts.MikroTik.UseHttps = true;
			opts.MikroTik.UserName = "rdpaudit";
			opts.MikroTik.Password = "{\"$protected\":\"VOPxX0\",\"scope\":\"LocalMachine\"}";

			IpcDispatcher dispatcher = CreateDispatcher(factory, opts);

			IpcResponse response = await dispatcher.DispatchAsync(
				new IpcRequest { Command = IpcCommand.GetMikroTikStatus }, CancellationToken.None);

			Assert.True(response.Success);
			Assert.NotNull(response.Payload);
			Assert.DoesNotContain("VOPxX0", response.Payload!, StringComparison.Ordinal);
			Assert.DoesNotContain("$protected", response.Payload!, StringComparison.Ordinal);

			MikroTikStatusDto? dto = JsonSerializer.Deserialize<MikroTikStatusDto>(response.Payload!, JsonOptions.Default);
			Assert.NotNull(dto);
			Assert.True(dto!.Configured);
			Assert.True(dto.CredentialPresent);
			Assert.True(dto.Enabled);
			Assert.Equal("router.lab", dto.Host);
			Assert.Equal("https", dto.Scheme);
		}
		finally
		{
			await conn.DisposeAsync();
		}
	}

	[Fact]
	public async Task GetMikroTikStatus_CountsOnlyMikroTikActiveBlocks()
	{
		(IDbContextFactory<AuditDbContext> factory, SqliteConnection conn) = await CreateDbAsync();
		try
		{
			await using (AuditDbContext seed = factory.CreateDbContext())
			{
				DateTime nowUtc = DateTime.UtcNow;
				seed.ActiveBlocks.Add(new ActiveBlock
				{
					Ip = "203.0.113.1",
					Provider = FirewallProviderKind.MikroTik,
					Status = ActiveBlockStatus.Active,
					CreatedUtc = nowUtc,
					Reason = "x",
				});
				seed.ActiveBlocks.Add(new ActiveBlock
				{
					Ip = "203.0.113.2",
					Provider = FirewallProviderKind.Windows,
					Status = ActiveBlockStatus.Active,
					CreatedUtc = nowUtc,
					Reason = "y",
				});
				await seed.SaveChangesAsync();
			}

			RdpAuditOptions opts = new();
			IpcDispatcher dispatcher = CreateDispatcher(factory, opts);
			IpcResponse response = await dispatcher.DispatchAsync(
				new IpcRequest { Command = IpcCommand.GetMikroTikStatus }, CancellationToken.None);

			Assert.True(response.Success);
			MikroTikStatusDto? dto = JsonSerializer.Deserialize<MikroTikStatusDto>(response.Payload!, JsonOptions.Default);
			Assert.NotNull(dto);
			Assert.Equal(1L, dto!.ActiveBlockCount);
		}
		finally
		{
			await conn.DisposeAsync();
		}
	}

	[Fact]
	public async Task TestMikroTik_NoConfig_ReturnsInvalidRequest()
	{
		(IDbContextFactory<AuditDbContext> factory, SqliteConnection conn) = await CreateDbAsync();
		try
		{
			RdpAuditOptions opts = new();
			IpcDispatcher dispatcher = CreateDispatcher(factory, opts);

			IpcResponse response = await dispatcher.DispatchAsync(
				new IpcRequest { Command = IpcCommand.TestMikroTik }, CancellationToken.None);

			Assert.True(response.Success);
			MikroTikTestResult? r = JsonSerializer.Deserialize<MikroTikTestResult>(response.Payload!, JsonOptions.Default);
			Assert.NotNull(r);
			Assert.Equal(IpcResultStatus.InvalidRequest, r!.Status);
			Assert.False(r.RemoteVerified);
		}
		finally
		{
			await conn.DisposeAsync();
		}
	}

	[Fact]
	public async Task TestMikroTik_NoClientRegistered_ReturnsUnavailable()
	{
		(IDbContextFactory<AuditDbContext> factory, SqliteConnection conn) = await CreateDbAsync();
		try
		{
			RdpAuditOptions opts = new();
			opts.MikroTik.Host = "router.lab";
			opts.MikroTik.UserName = "u";
			opts.MikroTik.Password = "p";
			IpcDispatcher dispatcher = CreateDispatcher(factory, opts);

			IpcResponse response = await dispatcher.DispatchAsync(
				new IpcRequest { Command = IpcCommand.TestMikroTik }, CancellationToken.None);

			Assert.True(response.Success);
			MikroTikTestResult? r = JsonSerializer.Deserialize<MikroTikTestResult>(response.Payload!, JsonOptions.Default);
			Assert.NotNull(r);
			Assert.Equal(IpcResultStatus.Unavailable, r!.Status);
			Assert.True(r.CredentialFormatValid);
		}
		finally
		{
			await conn.DisposeAsync();
		}
	}

	[Fact]
	public async Task TestMikroTik_ClientAccepts_ReturnsSuccess()
	{
		(IDbContextFactory<AuditDbContext> factory, SqliteConnection conn) = await CreateDbAsync();
		try
		{
			RdpAuditOptions opts = new();
			opts.MikroTik.Host = "router.lab";
			opts.MikroTik.UserName = "u";
			opts.MikroTik.Password = "p";
			FakeMikroTikClient fake = new() { PingResult = new() { Outcome = MikroTikOutcome.Accepted, ResponseCode = 200 } };

			IpcDispatcher dispatcher = CreateDispatcher(factory, opts, mikroTik: fake);
			IpcResponse response = await dispatcher.DispatchAsync(
				new IpcRequest { Command = IpcCommand.TestMikroTik }, CancellationToken.None);

			Assert.True(response.Success);
			MikroTikTestResult? r = JsonSerializer.Deserialize<MikroTikTestResult>(response.Payload!, JsonOptions.Default);
			Assert.NotNull(r);
			Assert.Equal(IpcResultStatus.Success, r!.Status);
			Assert.True(r.RemoteVerified);
		}
		finally
		{
			await conn.DisposeAsync();
		}
	}

	[Fact]
	public async Task TestMikroTik_ClientRejects_ReturnsRefused()
	{
		(IDbContextFactory<AuditDbContext> factory, SqliteConnection conn) = await CreateDbAsync();
		try
		{
			RdpAuditOptions opts = new();
			opts.MikroTik.Host = "router.lab";
			opts.MikroTik.UserName = "u";
			opts.MikroTik.Password = "p";
			FakeMikroTikClient fake = new() { PingResult = new() { Outcome = MikroTikOutcome.Rejected, ResponseCode = 401 } };

			IpcDispatcher dispatcher = CreateDispatcher(factory, opts, mikroTik: fake);
			IpcResponse response = await dispatcher.DispatchAsync(
				new IpcRequest { Command = IpcCommand.TestMikroTik }, CancellationToken.None);

			Assert.True(response.Success);
			MikroTikTestResult? r = JsonSerializer.Deserialize<MikroTikTestResult>(response.Payload!, JsonOptions.Default);
			Assert.NotNull(r);
			Assert.Equal(IpcResultStatus.Refused, r!.Status);
			Assert.False(r.RemoteVerified);
			Assert.Equal(401, r.ResponseCode);
		}
		finally
		{
			await conn.DisposeAsync();
		}
	}
}
