// File:    tests/RdpAudit.Service.Tests/IpcDispatcherStage5Tests.cs
// Module:  RdpAudit.Service.Tests
// Purpose: End-to-end IPC dispatcher tests for the Stage 5 commands: LoginRules CRUD,
//          ListActiveBlocksDetailed, and UnblockActiveBlock (DB-side bookkeeping only;
//          the provider unblock is skipped on non-Windows test hosts).
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
using Xunit;

namespace RdpAudit.Service.Tests;

public class IpcDispatcherStage5Tests
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
		return new IpcDispatcher(factory, metrics, mon, settings, manager,
			Array.Empty<IFirewallProvider>(), NullLogger<IpcDispatcher>.Instance);
	}

	[Fact]
	public async Task AddLoginRule_NormalisesAndPersistsRow()
	{
		(IDbContextFactory<AuditDbContext> factory, SqliteConnection conn) = await CreateDbAsync();
		try
		{
			IpcDispatcher dispatcher = CreateDispatcher(factory, new RdpAuditOptions());
			LoginRuleMutationRequest req = new() { Login = "  Administrator  ", Note = "honey-pot" };

			IpcResponse response = await dispatcher.DispatchAsync(new IpcRequest
			{
				Command = IpcCommand.AddLoginRule,
				Payload = JsonSerializer.Serialize(req, JsonOptions.Default),
			}, CancellationToken.None);

			Assert.True(response.Success);
			await using AuditDbContext db = factory.CreateDbContext();
			LoginRule row = Assert.Single(await db.LoginRules.ToListAsync());
			Assert.Equal("administrator", row.Login);
			Assert.True(row.Enabled);
		}
		finally
		{
			await conn.DisposeAsync();
		}
	}

	[Fact]
	public async Task AddLoginRule_EmptyLogin_ReturnsControlledError()
	{
		(IDbContextFactory<AuditDbContext> factory, SqliteConnection conn) = await CreateDbAsync();
		try
		{
			IpcDispatcher dispatcher = CreateDispatcher(factory, new RdpAuditOptions());
			LoginRuleMutationRequest req = new() { Login = "   " };
			IpcResponse response = await dispatcher.DispatchAsync(new IpcRequest
			{
				Command = IpcCommand.AddLoginRule,
				Payload = JsonSerializer.Serialize(req, JsonOptions.Default),
			}, CancellationToken.None);

			Assert.False(response.Success);
			Assert.Contains("empty", response.Error, StringComparison.OrdinalIgnoreCase);
		}
		finally
		{
			await conn.DisposeAsync();
		}
	}

	[Fact]
	public async Task AddLoginRule_ReAdd_ReenablesRowAndUpdatesNote()
	{
		(IDbContextFactory<AuditDbContext> factory, SqliteConnection conn) = await CreateDbAsync();
		try
		{
			await using (AuditDbContext seed = factory.CreateDbContext())
			{
				seed.LoginRules.Add(new LoginRule
				{
					Login = "guest",
					Note = "old",
					Enabled = false,
					AddedUtc = DateTime.UtcNow,
				});
				await seed.SaveChangesAsync();
			}

			IpcDispatcher dispatcher = CreateDispatcher(factory, new RdpAuditOptions());
			LoginRuleMutationRequest req = new() { Login = "Guest", Note = "fresh" };

			IpcResponse response = await dispatcher.DispatchAsync(new IpcRequest
			{
				Command = IpcCommand.AddLoginRule,
				Payload = JsonSerializer.Serialize(req, JsonOptions.Default),
			}, CancellationToken.None);

			Assert.True(response.Success);
			await using AuditDbContext db = factory.CreateDbContext();
			LoginRule row = Assert.Single(await db.LoginRules.ToListAsync());
			Assert.True(row.Enabled);
			Assert.Equal("fresh", row.Note);
		}
		finally
		{
			await conn.DisposeAsync();
		}
	}

	[Fact]
	public async Task SetLoginRuleEnabled_TogglesFlag()
	{
		(IDbContextFactory<AuditDbContext> factory, SqliteConnection conn) = await CreateDbAsync();
		try
		{
			long id;
			await using (AuditDbContext seed = factory.CreateDbContext())
			{
				LoginRule rule = new()
				{
					Login = "root",
					Enabled = true,
					AddedUtc = DateTime.UtcNow,
				};
				seed.LoginRules.Add(rule);
				await seed.SaveChangesAsync();
				id = rule.Id;
			}

			IpcDispatcher dispatcher = CreateDispatcher(factory, new RdpAuditOptions());
			LoginRuleMutationRequest req = new() { Id = id, Enabled = false };

			IpcResponse response = await dispatcher.DispatchAsync(new IpcRequest
			{
				Command = IpcCommand.SetLoginRuleEnabled,
				Payload = JsonSerializer.Serialize(req, JsonOptions.Default),
			}, CancellationToken.None);

			Assert.True(response.Success);
			await using AuditDbContext db = factory.CreateDbContext();
			LoginRule row = Assert.Single(await db.LoginRules.ToListAsync());
			Assert.False(row.Enabled);
		}
		finally
		{
			await conn.DisposeAsync();
		}
	}

	[Fact]
	public async Task RemoveLoginRule_DeletesByLoginFallback()
	{
		(IDbContextFactory<AuditDbContext> factory, SqliteConnection conn) = await CreateDbAsync();
		try
		{
			await using (AuditDbContext seed = factory.CreateDbContext())
			{
				seed.LoginRules.Add(new LoginRule { Login = "honeypot", AddedUtc = DateTime.UtcNow });
				await seed.SaveChangesAsync();
			}

			IpcDispatcher dispatcher = CreateDispatcher(factory, new RdpAuditOptions());
			LoginRuleMutationRequest req = new() { Login = "  HONEYPOT  " };

			IpcResponse response = await dispatcher.DispatchAsync(new IpcRequest
			{
				Command = IpcCommand.RemoveLoginRule,
				Payload = JsonSerializer.Serialize(req, JsonOptions.Default),
			}, CancellationToken.None);

			Assert.True(response.Success);
			await using AuditDbContext db = factory.CreateDbContext();
			Assert.Empty(await db.LoginRules.ToListAsync());
		}
		finally
		{
			await conn.DisposeAsync();
		}
	}

	[Fact]
	public async Task ListActiveBlocksDetailed_ReturnsFullDtoShape()
	{
		(IDbContextFactory<AuditDbContext> factory, SqliteConnection conn) = await CreateDbAsync();
		try
		{
			await using (AuditDbContext seed = factory.CreateDbContext())
			{
				seed.ActiveBlocks.Add(new ActiveBlock
				{
					Ip = "203.0.113.10",
					Provider = FirewallProviderKind.Windows,
					RuleHandle = "RdpAudit-Block-203.0.113.10",
					CreatedUtc = DateTime.UtcNow,
					ExpiresUtc = DateTime.UtcNow.AddHours(1),
					Reason = "manual",
					Status = ActiveBlockStatus.Active,
				});
				await seed.SaveChangesAsync();
			}

			IpcDispatcher dispatcher = CreateDispatcher(factory, new RdpAuditOptions());
			IpcResponse response = await dispatcher.DispatchAsync(new IpcRequest
			{
				Command = IpcCommand.ListActiveBlocksDetailed,
			}, CancellationToken.None);

			Assert.True(response.Success);
			Assert.NotNull(response.Payload);
			List<ActiveBlockDto>? rows = JsonSerializer.Deserialize<List<ActiveBlockDto>>(response.Payload!, JsonOptions.Default);
			Assert.NotNull(rows);
			ActiveBlockDto row = Assert.Single(rows!);
			Assert.Equal("203.0.113.10", row.Ip);
			Assert.Equal(FirewallProviderKind.Windows, row.Provider);
			Assert.Equal("RdpAudit-Block-203.0.113.10", row.RuleHandle);
			Assert.Equal(ActiveBlockStatus.Active, row.Status);
		}
		finally
		{
			await conn.DisposeAsync();
		}
	}

	[Fact]
	public async Task UnblockActiveBlock_DisablesRelatedBlocklistRows()
	{
		(IDbContextFactory<AuditDbContext> factory, SqliteConnection conn) = await CreateDbAsync();
		try
		{
			long blockId;
			await using (AuditDbContext seed = factory.CreateDbContext())
			{
				ActiveBlock ab = new()
				{
					Ip = "203.0.113.55",
					Provider = FirewallProviderKind.None,
					CreatedUtc = DateTime.UtcNow,
					Reason = "test",
					Status = ActiveBlockStatus.Active,
				};
				seed.ActiveBlocks.Add(ab);
				seed.BlocklistEntries.Add(new BlocklistEntry
				{
					Ip = "203.0.113.55",
					Reason = "manual",
					AddedUtc = DateTime.UtcNow,
					Source = BlocklistSource.Manual,
					IsEnabled = true,
				});
				await seed.SaveChangesAsync();
				blockId = ab.Id;
			}

			IpcDispatcher dispatcher = CreateDispatcher(factory, new RdpAuditOptions());
			IpcResponse response = await dispatcher.DispatchAsync(new IpcRequest
			{
				Command = IpcCommand.UnblockActiveBlock,
				Payload = JsonSerializer.Serialize(blockId, JsonOptions.Default),
			}, CancellationToken.None);

			Assert.True(response.Success);
			await using AuditDbContext db = factory.CreateDbContext();
			ActiveBlock after = Assert.Single(await db.ActiveBlocks.ToListAsync());
			Assert.Equal(ActiveBlockStatus.Removed, after.Status);
			BlocklistEntry blk = Assert.Single(await db.BlocklistEntries.ToListAsync());
			Assert.False(blk.IsEnabled);
		}
		finally
		{
			await conn.DisposeAsync();
		}
	}

	[Fact]
	public async Task UnblockActiveBlock_MissingId_ReturnsControlledError()
	{
		(IDbContextFactory<AuditDbContext> factory, SqliteConnection conn) = await CreateDbAsync();
		try
		{
			IpcDispatcher dispatcher = CreateDispatcher(factory, new RdpAuditOptions());
			IpcResponse response = await dispatcher.DispatchAsync(new IpcRequest
			{
				Command = IpcCommand.UnblockActiveBlock,
				Payload = JsonSerializer.Serialize<long>(9999, JsonOptions.Default),
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
