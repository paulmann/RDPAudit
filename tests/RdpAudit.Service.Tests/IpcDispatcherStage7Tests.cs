// File:    tests/RdpAudit.Service.Tests/IpcDispatcherStage7Tests.cs
// Module:  RdpAudit.Service.Tests
// Purpose: IPC dispatcher tests for Stage 7 — Remote RDP Clients. Validates that all
//          new commands return controlled "Unavailable" responses on non-Windows test
//          hosts (the dispatcher is constructed without the Windows-specific managers),
//          rejects malformed payloads with controlled errors, and validates session ids.
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
using RdpAudit.Core.Util;
using RdpAudit.Service.Ipc;
using RdpAudit.Service.Services;
using Xunit;

namespace RdpAudit.Service.Tests;

public class IpcDispatcherStage7Tests
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
		// Pass null for sessions / shadow — emulates non-Windows host wiring.
		return new IpcDispatcher(factory, metrics, mon, settings, manager,
			Array.Empty<IFirewallProvider>(), NullLogger<IpcDispatcher>.Instance, sessions: null, shadow: null);
	}

	[Fact]
	public async Task ListRdpSessions_OnNonWindowsHost_ReturnsUnavailable()
	{
		(IDbContextFactory<AuditDbContext> factory, SqliteConnection conn) = await CreateDbAsync();
		try
		{
			IpcDispatcher dispatcher = CreateDispatcher(factory, new RdpAuditOptions());
			IpcResponse response = await dispatcher.DispatchAsync(
				new IpcRequest { Command = IpcCommand.ListRdpSessions },
				CancellationToken.None);

			Assert.True(response.Success);
			RdpSessionListDto? dto = JsonSerializer.Deserialize<RdpSessionListDto>(response.Payload!, JsonOptions.Default);
			Assert.NotNull(dto);
			Assert.Equal(IpcResultStatus.Unavailable, dto!.Status);
			Assert.Empty(dto.Sessions);
		}
		finally
		{
			await conn.DisposeAsync();
		}
	}

	[Fact]
	public async Task DisconnectSession_InvalidId_ReturnsControlledError()
	{
		(IDbContextFactory<AuditDbContext> factory, SqliteConnection conn) = await CreateDbAsync();
		try
		{
			IpcDispatcher dispatcher = CreateDispatcher(factory, new RdpAuditOptions());
			SessionActionRequest req = new() { SessionId = -5, Reason = "test" };
			IpcResponse response = await dispatcher.DispatchAsync(new IpcRequest
			{
				Command = IpcCommand.DisconnectSession,
				Payload = JsonSerializer.Serialize(req, JsonOptions.Default),
			}, CancellationToken.None);

			Assert.False(response.Success);
			Assert.NotNull(response.Error);
			Assert.Contains("non-negative", response.Error!, StringComparison.OrdinalIgnoreCase);
		}
		finally
		{
			await conn.DisposeAsync();
		}
	}

	[Fact]
	public async Task LogoffSession_MissingPayload_ReturnsControlledError()
	{
		(IDbContextFactory<AuditDbContext> factory, SqliteConnection conn) = await CreateDbAsync();
		try
		{
			IpcDispatcher dispatcher = CreateDispatcher(factory, new RdpAuditOptions());
			IpcResponse response = await dispatcher.DispatchAsync(
				new IpcRequest { Command = IpcCommand.LogoffSession, Payload = null },
				CancellationToken.None);

			Assert.False(response.Success);
			Assert.Contains("requires", response.Error ?? string.Empty, StringComparison.OrdinalIgnoreCase);
		}
		finally
		{
			await conn.DisposeAsync();
		}
	}

	[Fact]
	public async Task ShadowSession_OnNonWindowsHost_ReturnsUnavailable()
	{
		(IDbContextFactory<AuditDbContext> factory, SqliteConnection conn) = await CreateDbAsync();
		try
		{
			// Deterministic across hosts: AllowShadow=false forces the controlled-rejection
			// path on Windows (Refused), while non-Windows hosts still hit the early
			// IsWindows() gate (Unavailable). Both outcomes satisfy the contract this test
			// guards — the dispatcher must never return Success when the shadow manager is
			// not wired in. AllowShadow defaults to true since b2d1c4e, so the test must
			// override it explicitly rather than rely on the default.
			RdpAuditOptions opts = new();
			opts.SessionControl.AllowShadow = false;
			IpcDispatcher dispatcher = CreateDispatcher(factory, opts);
			SessionActionRequest req = new() { SessionId = 1, ShadowMode = 0 };
			IpcResponse response = await dispatcher.DispatchAsync(new IpcRequest
			{
				Command = IpcCommand.ShadowSession,
				Payload = JsonSerializer.Serialize(req, JsonOptions.Default),
			}, CancellationToken.None);

			Assert.True(response.Success);
			SessionActionResult? result = JsonSerializer.Deserialize<SessionActionResult>(response.Payload!, JsonOptions.Default);
			Assert.NotNull(result);
			Assert.True(result!.Status == IpcResultStatus.Unavailable
				|| result.Status == IpcResultStatus.Refused);
		}
		finally
		{
			await conn.DisposeAsync();
		}
	}

	[Fact]
	public async Task GetShadowPolicyStatus_OnNonWindowsHost_ReturnsUnavailable()
	{
		(IDbContextFactory<AuditDbContext> factory, SqliteConnection conn) = await CreateDbAsync();
		try
		{
			IpcDispatcher dispatcher = CreateDispatcher(factory, new RdpAuditOptions());
			IpcResponse response = await dispatcher.DispatchAsync(
				new IpcRequest { Command = IpcCommand.GetShadowPolicyStatus },
				CancellationToken.None);

			Assert.True(response.Success);
			ShadowPolicyStatusDto? dto = JsonSerializer.Deserialize<ShadowPolicyStatusDto>(response.Payload!, JsonOptions.Default);
			Assert.NotNull(dto);
			Assert.Equal(IpcResultStatus.Unavailable, dto!.Status);
		}
		finally
		{
			await conn.DisposeAsync();
		}
	}

	[Fact]
	public async Task ApplyShadowPolicy_OnNonWindowsHost_ReturnsUnavailable()
	{
		(IDbContextFactory<AuditDbContext> factory, SqliteConnection conn) = await CreateDbAsync();
		try
		{
			IpcDispatcher dispatcher = CreateDispatcher(factory, new RdpAuditOptions());
			ShadowPolicyApplyRequest req = new() { EnableAllPermissions = true };
			IpcResponse response = await dispatcher.DispatchAsync(new IpcRequest
			{
				Command = IpcCommand.ApplyShadowPolicy,
				Payload = JsonSerializer.Serialize(req, JsonOptions.Default),
			}, CancellationToken.None);

			Assert.True(response.Success);
			ShadowPolicyStatusDto? dto = JsonSerializer.Deserialize<ShadowPolicyStatusDto>(response.Payload!, JsonOptions.Default);
			Assert.NotNull(dto);
			Assert.Equal(IpcResultStatus.Unavailable, dto!.Status);
		}
		finally
		{
			await conn.DisposeAsync();
		}
	}

	[Fact]
	public async Task BackupShadowPolicy_OnNonWindowsHost_ReturnsUnavailable()
	{
		(IDbContextFactory<AuditDbContext> factory, SqliteConnection conn) = await CreateDbAsync();
		try
		{
			IpcDispatcher dispatcher = CreateDispatcher(factory, new RdpAuditOptions());
			IpcResponse response = await dispatcher.DispatchAsync(
				new IpcRequest { Command = IpcCommand.BackupShadowPolicy },
				CancellationToken.None);

			Assert.True(response.Success);
			ShadowPolicyStatusDto? dto = JsonSerializer.Deserialize<ShadowPolicyStatusDto>(response.Payload!, JsonOptions.Default);
			Assert.NotNull(dto);
			Assert.Equal(IpcResultStatus.Unavailable, dto!.Status);
		}
		finally
		{
			await conn.DisposeAsync();
		}
	}

	[Fact]
	public async Task RestoreShadowPolicy_OnNonWindowsHost_ReturnsUnavailable()
	{
		(IDbContextFactory<AuditDbContext> factory, SqliteConnection conn) = await CreateDbAsync();
		try
		{
			IpcDispatcher dispatcher = CreateDispatcher(factory, new RdpAuditOptions());
			IpcResponse response = await dispatcher.DispatchAsync(
				new IpcRequest { Command = IpcCommand.RestoreShadowPolicy, Payload = null },
				CancellationToken.None);

			Assert.True(response.Success);
			ShadowPolicyStatusDto? dto = JsonSerializer.Deserialize<ShadowPolicyStatusDto>(response.Payload!, JsonOptions.Default);
			Assert.NotNull(dto);
			Assert.Equal(IpcResultStatus.Unavailable, dto!.Status);
		}
		finally
		{
			await conn.DisposeAsync();
		}
	}

	[Fact]
	public async Task DisconnectSession_DisabledByPolicy_ReturnsRefused()
	{
		(IDbContextFactory<AuditDbContext> factory, SqliteConnection conn) = await CreateDbAsync();
		try
		{
			RdpAuditOptions opts = new();
			opts.SessionControl.AllowDisconnect = false;
			IpcDispatcher dispatcher = CreateDispatcher(factory, opts);

			SessionActionRequest req = new() { SessionId = 1 };
			IpcResponse response = await dispatcher.DispatchAsync(new IpcRequest
			{
				Command = IpcCommand.DisconnectSession,
				Payload = JsonSerializer.Serialize(req, JsonOptions.Default),
			}, CancellationToken.None);

			Assert.True(response.Success);
			SessionActionResult? result = JsonSerializer.Deserialize<SessionActionResult>(response.Payload!, JsonOptions.Default);
			Assert.NotNull(result);
			// On non-Windows the unavailable check triggers first; but we still want a controlled response.
			Assert.True(result!.Status == IpcResultStatus.Unavailable
				|| result.Status == IpcResultStatus.Refused);
		}
		finally
		{
			await conn.DisposeAsync();
		}
	}

	[Fact]
	public async Task ShadowSession_InvalidPayload_ReturnsControlledError()
	{
		(IDbContextFactory<AuditDbContext> factory, SqliteConnection conn) = await CreateDbAsync();
		try
		{
			IpcDispatcher dispatcher = CreateDispatcher(factory, new RdpAuditOptions());
			IpcResponse response = await dispatcher.DispatchAsync(new IpcRequest
			{
				Command = IpcCommand.ShadowSession,
				Payload = "{not-json",
			}, CancellationToken.None);

			Assert.False(response.Success);
			Assert.NotNull(response.Error);
		}
		finally
		{
			await conn.DisposeAsync();
		}
	}
}
