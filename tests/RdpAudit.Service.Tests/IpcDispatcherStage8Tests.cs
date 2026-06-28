// File:    tests/RdpAudit.Service.Tests/IpcDispatcherStage8Tests.cs
// Module:  RdpAudit.Service.Tests
// Purpose: Stage 8 IPC dispatcher tests. Exercises GetAbuseIpDbStatus and TestAbuseIpDbKey against
//          an in-memory SQLite database with a stubbed AbuseIPDB client. Confirms:
//            • status DTOs never contain plaintext API keys,
//            • CredentialPresent reflects the configured key,
//            • TestAbuseIpDbKey rejects malformed keys, accepts good keys, and returns Refused
//              when the remote probe rejects them.
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
using RdpAudit.Core.Models;
using RdpAudit.Core.Security;
using RdpAudit.Core.Util;
using RdpAudit.Service.Ipc;
using RdpAudit.Service.Services;
using Xunit;

namespace RdpAudit.Service.Tests;

public class IpcDispatcherStage8Tests
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

	private sealed class FakeAbuseClient : IAbuseIpDbClient
	{
		public AbuseIpDbReportResult ValidateResult { get; set; } = new()
		{
			Outcome = AbuseIpDbReportOutcome.Accepted,
			ResponseCode = 200,
			Message = "ok",
		};

		public AbuseIpDbReportResult ReportResult { get; set; } = new()
		{
			Outcome = AbuseIpDbReportOutcome.Accepted,
			ResponseCode = 200,
			Message = "ok",
		};

		public int ReportCount { get; private set; }

		public Task<AbuseIpDbReportResult> ReportAsync(AbuseIpDbReportRequest request, CancellationToken ct)
		{
			ReportCount++;
			return Task.FromResult(ReportResult);
		}

		public Task<AbuseIpDbReportResult> ValidateKeyAsync(CancellationToken ct) =>
			Task.FromResult(ValidateResult);
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
			abuseClient: abuse, protector: protector);
	}

	[Fact]
	public async Task GetAbuseIpDbStatus_NoCredential_ReportsNotConfigured()
	{
		(IDbContextFactory<AuditDbContext> factory, SqliteConnection conn) = await CreateDbAsync();
		try
		{
			RdpAuditOptions opts = new();
			IpcDispatcher dispatcher = CreateDispatcher(factory, opts);

			IpcResponse response = await dispatcher.DispatchAsync(
				new IpcRequest { Command = IpcCommand.GetAbuseIpDbStatus }, CancellationToken.None);

			Assert.True(response.Success);
			AbuseIpDbStatusDto? dto = JsonSerializer.Deserialize<AbuseIpDbStatusDto>(response.Payload!, JsonOptions.Default);
			Assert.NotNull(dto);
			Assert.False(dto!.CredentialPresent);
			Assert.False(dto.ReportingEnabled);
			Assert.Equal(IpcResultStatus.Success, dto.Status);
		}
		finally
		{
			await conn.DisposeAsync();
		}
	}

	[Fact]
	public async Task GetAbuseIpDbStatus_WithCredential_ReportsConfiguredAndNoKeyInPayload()
	{
		(IDbContextFactory<AuditDbContext> factory, SqliteConnection conn) = await CreateDbAsync();
		try
		{
			RdpAuditOptions opts = new();
			opts.AbuseIpDb.Enabled = true;
			opts.AbuseIpDb.ReportAttacks = true;
			opts.AbuseIpDb.ApiKey = "{\"$protected\":\"YWJjZA==\",\"scope\":\"LocalMachine\"}";
			IpcDispatcher dispatcher = CreateDispatcher(factory, opts);

			IpcResponse response = await dispatcher.DispatchAsync(
				new IpcRequest { Command = IpcCommand.GetAbuseIpDbStatus }, CancellationToken.None);

			Assert.True(response.Success);
			Assert.NotNull(response.Payload);
			Assert.DoesNotContain("YWJjZA", response.Payload!, StringComparison.Ordinal);

			AbuseIpDbStatusDto? dto = JsonSerializer.Deserialize<AbuseIpDbStatusDto>(response.Payload!, JsonOptions.Default);
			Assert.NotNull(dto);
			Assert.True(dto!.CredentialPresent);
			Assert.True(dto.ReportingEnabled);
		}
		finally
		{
			await conn.DisposeAsync();
		}
	}

	[Fact]
	public async Task GetAbuseIpDbStatus_ReportsExistingCountsFromDatabase()
	{
		(IDbContextFactory<AuditDbContext> factory, SqliteConnection conn) = await CreateDbAsync();
		try
		{
			await using (AuditDbContext seed = factory.CreateDbContext())
			{
				DateTime nowUtc = DateTime.UtcNow;
				seed.AbuseReports.Add(new AbuseReport
				{
					Ip = "203.0.113.7",
					ReportedUtc = nowUtc.AddMinutes(-2),
					Categories = "18,22",
					ResponseCode = 200,
					Error = null,
				});
				seed.AbuseReports.Add(new AbuseReport
				{
					Ip = "198.51.100.7",
					ReportedUtc = nowUtc.AddHours(-3),
					Categories = "18,22",
					ResponseCode = 429,
					Error = "Rate limited",
				});
				await seed.SaveChangesAsync();
			}

			RdpAuditOptions opts = new();
			opts.AbuseIpDb.ApiKey = "envelope";
			IpcDispatcher dispatcher = CreateDispatcher(factory, opts);

			IpcResponse response = await dispatcher.DispatchAsync(
				new IpcRequest { Command = IpcCommand.GetAbuseIpDbStatus }, CancellationToken.None);

			Assert.True(response.Success);
			AbuseIpDbStatusDto? dto = JsonSerializer.Deserialize<AbuseIpDbStatusDto>(response.Payload!, JsonOptions.Default);
			Assert.NotNull(dto);
			Assert.Equal(2L, dto!.TotalReports);
			Assert.Equal(1L, dto.ReportsLastHour);
			Assert.Equal("203.0.113.7", dto.LastReportedIp);
			Assert.Equal(200, dto.LastResponseCode);
		}
		finally
		{
			await conn.DisposeAsync();
		}
	}

	[Fact]
	public async Task TestAbuseIpDbKey_NoKey_ReturnsInvalidRequest()
	{
		(IDbContextFactory<AuditDbContext> factory, SqliteConnection conn) = await CreateDbAsync();
		try
		{
			RdpAuditOptions opts = new();
			IpcDispatcher dispatcher = CreateDispatcher(factory, opts);

			IpcResponse response = await dispatcher.DispatchAsync(
				new IpcRequest { Command = IpcCommand.TestAbuseIpDbKey }, CancellationToken.None);

			Assert.True(response.Success);
			AbuseIpDbTestResult? result = JsonSerializer.Deserialize<AbuseIpDbTestResult>(response.Payload!, JsonOptions.Default);
			Assert.NotNull(result);
			Assert.False(result!.KeyFormatValid);
			Assert.False(result.RemoteVerified);
			Assert.Equal(IpcResultStatus.InvalidRequest, result.Status);
		}
		finally
		{
			await conn.DisposeAsync();
		}
	}

	[Fact]
	public async Task TestAbuseIpDbKey_BadFormat_ReturnsRefused()
	{
		(IDbContextFactory<AuditDbContext> factory, SqliteConnection conn) = await CreateDbAsync();
		try
		{
			InMemorySecretProtector protector = new();
			string envelope = protector.Protect("not-hex-and-too-short");
			RdpAuditOptions opts = new();
			opts.AbuseIpDb.ApiKey = envelope;
			FakeAbuseClient fake = new();
			IpcDispatcher dispatcher = CreateDispatcher(factory, opts, fake, protector);

			IpcResponse response = await dispatcher.DispatchAsync(
				new IpcRequest { Command = IpcCommand.TestAbuseIpDbKey }, CancellationToken.None);

			Assert.True(response.Success);
			AbuseIpDbTestResult? result = JsonSerializer.Deserialize<AbuseIpDbTestResult>(response.Payload!, JsonOptions.Default);
			Assert.NotNull(result);
			Assert.False(result!.KeyFormatValid);
			Assert.Equal(IpcResultStatus.Refused, result.Status);
		}
		finally
		{
			await conn.DisposeAsync();
		}
	}

	[Fact]
	public async Task TestAbuseIpDbKey_GoodFormat_RemoteAccepts_ReturnsSuccess()
	{
		(IDbContextFactory<AuditDbContext> factory, SqliteConnection conn) = await CreateDbAsync();
		try
		{
			string goodKey = new('a', AbuseIpDbApiKeyValidator.CanonicalKeyLength);
			InMemorySecretProtector protector = new();
			string envelope = protector.Protect(goodKey);
			RdpAuditOptions opts = new();
			opts.AbuseIpDb.ApiKey = envelope;
			FakeAbuseClient fake = new()
			{
				ValidateResult = new AbuseIpDbReportResult
				{
					Outcome = AbuseIpDbReportOutcome.Accepted,
					ResponseCode = 200,
					Message = "ok",
				},
			};
			IpcDispatcher dispatcher = CreateDispatcher(factory, opts, fake, protector);

			IpcResponse response = await dispatcher.DispatchAsync(
				new IpcRequest { Command = IpcCommand.TestAbuseIpDbKey }, CancellationToken.None);

			Assert.True(response.Success);
			AbuseIpDbTestResult? result = JsonSerializer.Deserialize<AbuseIpDbTestResult>(response.Payload!, JsonOptions.Default);
			Assert.NotNull(result);
			Assert.True(result!.KeyFormatValid);
			Assert.True(result.RemoteVerified);
			Assert.Equal(IpcResultStatus.Success, result.Status);
		}
		finally
		{
			await conn.DisposeAsync();
		}
	}

	[Fact]
	public async Task TestAbuseIpDbKey_GoodFormat_RemoteRejects_ReturnsRefused()
	{
		(IDbContextFactory<AuditDbContext> factory, SqliteConnection conn) = await CreateDbAsync();
		try
		{
			string goodKey = new('a', AbuseIpDbApiKeyValidator.CanonicalKeyLength);
			InMemorySecretProtector protector = new();
			RdpAuditOptions opts = new();
			opts.AbuseIpDb.ApiKey = protector.Protect(goodKey);
			FakeAbuseClient fake = new()
			{
				ValidateResult = new AbuseIpDbReportResult
				{
					Outcome = AbuseIpDbReportOutcome.Rejected,
					ResponseCode = 401,
					Message = "AbuseIPDB rejected the API key.",
				},
			};
			IpcDispatcher dispatcher = CreateDispatcher(factory, opts, fake, protector);

			IpcResponse response = await dispatcher.DispatchAsync(
				new IpcRequest { Command = IpcCommand.TestAbuseIpDbKey }, CancellationToken.None);

			Assert.True(response.Success);
			AbuseIpDbTestResult? result = JsonSerializer.Deserialize<AbuseIpDbTestResult>(response.Payload!, JsonOptions.Default);
			Assert.NotNull(result);
			Assert.True(result!.KeyFormatValid);
			Assert.False(result.RemoteVerified);
			Assert.Equal(IpcResultStatus.Refused, result.Status);
			Assert.Equal(401, result.ResponseCode);
		}
		finally
		{
			await conn.DisposeAsync();
		}
	}

	[Fact]
	public async Task GetSettings_MasksApiKey()
	{
		(IDbContextFactory<AuditDbContext> factory, SqliteConnection conn) = await CreateDbAsync();
		try
		{
			RdpAuditOptions opts = new();
			opts.AbuseIpDb.ApiKey = "{\"$protected\":\"SECRETBASE64\",\"scope\":\"LocalMachine\"}";
			opts.MikroTik.Password = "{\"$protected\":\"PASSWORDBASE64\",\"scope\":\"LocalMachine\"}";
			IpcDispatcher dispatcher = CreateDispatcher(factory, opts);

			IpcResponse response = await dispatcher.DispatchAsync(
				new IpcRequest { Command = IpcCommand.GetSettings }, CancellationToken.None);

			Assert.True(response.Success);
			Assert.NotNull(response.Payload);
			Assert.DoesNotContain("SECRETBASE64", response.Payload!, StringComparison.Ordinal);
			Assert.DoesNotContain("PASSWORDBASE64", response.Payload!, StringComparison.Ordinal);
		}
		finally
		{
			await conn.DisposeAsync();
		}
	}
}
