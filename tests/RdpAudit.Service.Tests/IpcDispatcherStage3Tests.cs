// File:    tests/RdpAudit.Service.Tests/IpcDispatcherStage3Tests.cs
// Module:  RdpAudit.Service.Tests
// Purpose: End-to-end IPC dispatcher tests for the Stage 3 commands: GetFirewallStatus,
//          ListBlocklist / Whitelist / ActiveBlocks, AddToBlocklist / Whitelist (with input
//          validation and whitelist precedence), and Remove* mutations.
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

public class IpcDispatcherStage3Tests
{
	private sealed class TestDbContextFactory : IDbContextFactory<AuditDbContext>
	{
		private readonly DbContextOptions<AuditDbContext> _options;

		public TestDbContextFactory(DbContextOptions<AuditDbContext> options)
		{
			_options = options;
		}

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

	private static IpcDispatcher CreateDispatcher(
		IDbContextFactory<AuditDbContext> factory,
		RdpAuditOptions opts,
		IEnumerable<IFirewallProvider> providers)
	{
		ServiceMetrics metrics = new();
		StaticOptionsMonitorLocal<RdpAuditOptions> mon = new(opts);
		SettingsManager settings = new(NullLogger<SettingsManager>.Instance);
		FirewallManager manager = new(NullLogger<FirewallManager>.Instance);
		return new IpcDispatcher(factory, metrics, mon, settings, manager, providers, NullLogger<IpcDispatcher>.Instance);
	}

	[Fact]
	public async Task AddToWhitelist_NormalizesAndPersistsRow()
	{
		(IDbContextFactory<AuditDbContext> factory, SqliteConnection conn) = await CreateDbAsync();
		try
		{
			IpcDispatcher dispatcher = CreateDispatcher(factory, new RdpAuditOptions(), Array.Empty<IFirewallProvider>());

			AddressListMutationRequest req = new() { Address = "  203.0.113.10  ", Note = "office gateway" };
			IpcResponse response = await dispatcher.DispatchAsync(new IpcRequest
			{
				Command = IpcCommand.AddToWhitelist,
				Payload = JsonSerializer.Serialize(req, JsonOptions.Default),
			}, CancellationToken.None);

			Assert.True(response.Success);
			await using AuditDbContext db = factory.CreateDbContext();
			WhitelistEntry row = Assert.Single(await db.WhitelistEntries.ToListAsync());
			Assert.Equal("203.0.113.10", row.Ip);
		}
		finally
		{
			await conn.DisposeAsync();
		}
	}

	[Fact]
	public async Task AddToWhitelist_InvalidAddress_FailsWithControlledMessage()
	{
		(IDbContextFactory<AuditDbContext> factory, SqliteConnection conn) = await CreateDbAsync();
		try
		{
			IpcDispatcher dispatcher = CreateDispatcher(factory, new RdpAuditOptions(), Array.Empty<IFirewallProvider>());

			AddressListMutationRequest req = new() { Address = "not-an-ip" };
			IpcResponse response = await dispatcher.DispatchAsync(new IpcRequest
			{
				Command = IpcCommand.AddToWhitelist,
				Payload = JsonSerializer.Serialize(req, JsonOptions.Default),
			}, CancellationToken.None);

			Assert.False(response.Success);
			Assert.Contains("not a valid", response.Error, StringComparison.OrdinalIgnoreCase);
		}
		finally
		{
			await conn.DisposeAsync();
		}
	}

	[Fact]
	public async Task AddToBlocklist_RefusesWhitelistedAddress()
	{
		(IDbContextFactory<AuditDbContext> factory, SqliteConnection conn) = await CreateDbAsync();
		try
		{
			await using (AuditDbContext seed = factory.CreateDbContext())
			{
				seed.WhitelistEntries.Add(new WhitelistEntry { Ip = "203.0.113.10", AddedUtc = DateTime.UtcNow });
				await seed.SaveChangesAsync();
			}

			IpcDispatcher dispatcher = CreateDispatcher(factory, new RdpAuditOptions(), Array.Empty<IFirewallProvider>());
			AddressListMutationRequest req = new() { Address = "203.0.113.10" };
			IpcResponse response = await dispatcher.DispatchAsync(new IpcRequest
			{
				Command = IpcCommand.AddToBlocklist,
				Payload = JsonSerializer.Serialize(req, JsonOptions.Default),
			}, CancellationToken.None);

			Assert.False(response.Success);
			Assert.Contains("whitelisted", response.Error, StringComparison.OrdinalIgnoreCase);
		}
		finally
		{
			await conn.DisposeAsync();
		}
	}

	[Fact]
	public async Task AddToWhitelist_DisablesConflictingBlocklistRows()
	{
		(IDbContextFactory<AuditDbContext> factory, SqliteConnection conn) = await CreateDbAsync();
		try
		{
			await using (AuditDbContext seed = factory.CreateDbContext())
			{
				seed.BlocklistEntries.Add(new BlocklistEntry
				{
					Ip = "203.0.113.10",
					Reason = "manual",
					AddedUtc = DateTime.UtcNow,
					Source = BlocklistSource.Manual,
					IsEnabled = true,
				});
				await seed.SaveChangesAsync();
			}

			IpcDispatcher dispatcher = CreateDispatcher(factory, new RdpAuditOptions(), Array.Empty<IFirewallProvider>());
			AddressListMutationRequest req = new() { Address = "203.0.113.10", Note = "trusted" };
			IpcResponse response = await dispatcher.DispatchAsync(new IpcRequest
			{
				Command = IpcCommand.AddToWhitelist,
				Payload = JsonSerializer.Serialize(req, JsonOptions.Default),
			}, CancellationToken.None);

			Assert.True(response.Success);

			await using AuditDbContext db = factory.CreateDbContext();
			BlocklistEntry block = Assert.Single(await db.BlocklistEntries.ToListAsync());
			Assert.False(block.IsEnabled);
		}
		finally
		{
			await conn.DisposeAsync();
		}
	}

	[Fact]
	public async Task RemoveFromBlocklist_SoftDisablesRows()
	{
		(IDbContextFactory<AuditDbContext> factory, SqliteConnection conn) = await CreateDbAsync();
		try
		{
			await using (AuditDbContext seed = factory.CreateDbContext())
			{
				seed.BlocklistEntries.Add(new BlocklistEntry
				{
					Ip = "203.0.113.11",
					Reason = "manual",
					AddedUtc = DateTime.UtcNow,
					Source = BlocklistSource.Manual,
					IsEnabled = true,
				});
				await seed.SaveChangesAsync();
			}

			IpcDispatcher dispatcher = CreateDispatcher(factory, new RdpAuditOptions(), Array.Empty<IFirewallProvider>());
			AddressListMutationRequest req = new() { Address = "203.0.113.11" };
			IpcResponse response = await dispatcher.DispatchAsync(new IpcRequest
			{
				Command = IpcCommand.RemoveFromBlocklist,
				Payload = JsonSerializer.Serialize(req, JsonOptions.Default),
			}, CancellationToken.None);

			Assert.True(response.Success);
			await using AuditDbContext db = factory.CreateDbContext();
			BlocklistEntry row = Assert.Single(await db.BlocklistEntries.ToListAsync());
			Assert.False(row.IsEnabled);
		}
		finally
		{
			await conn.DisposeAsync();
		}
	}

	[Fact]
	public async Task RemoveFromBlocklist_ById_DisablesOnlyTheTargetedRow()
	{
		(IDbContextFactory<AuditDbContext> factory, SqliteConnection conn) = await CreateDbAsync();
		try
		{
			long targetId;
			await using (AuditDbContext seed = factory.CreateDbContext())
			{
				// Two enabled rows share the same address (e.g. Manual + AutoBlock). Removing by Id
				// must disable exactly one of them, not both.
				BlocklistEntry manual = new()
				{
					Ip = "203.0.113.11",
					Reason = "manual",
					AddedUtc = DateTime.UtcNow,
					Source = BlocklistSource.Manual,
					IsEnabled = true,
				};
				BlocklistEntry auto = new()
				{
					Ip = "203.0.113.11",
					Reason = "auto",
					AddedUtc = DateTime.UtcNow,
					Source = BlocklistSource.Auto,
					IsEnabled = true,
				};
				seed.BlocklistEntries.Add(manual);
				seed.BlocklistEntries.Add(auto);
				await seed.SaveChangesAsync();
				targetId = manual.Id;
			}

			IpcDispatcher dispatcher = CreateDispatcher(factory, new RdpAuditOptions(), Array.Empty<IFirewallProvider>());
			AddressListMutationRequest req = new() { Id = targetId, Address = "203.0.113.11" };
			IpcResponse response = await dispatcher.DispatchAsync(new IpcRequest
			{
				Command = IpcCommand.RemoveFromBlocklist,
				Payload = JsonSerializer.Serialize(req, JsonOptions.Default),
			}, CancellationToken.None);

			Assert.True(response.Success);
			Assert.NotNull(response.Payload);
			using JsonDocument doc = JsonDocument.Parse(response.Payload!);
			Assert.Equal(1, doc.RootElement.GetProperty("removed").GetInt32());

			await using AuditDbContext db = factory.CreateDbContext();
			BlocklistEntry disabled = await db.BlocklistEntries.SingleAsync(b => b.Id == targetId);
			Assert.False(disabled.IsEnabled);
			Assert.Equal(1, await db.BlocklistEntries.CountAsync(b => b.IsEnabled));
		}
		finally
		{
			await conn.DisposeAsync();
		}
	}

	[Fact]
	public async Task RemoveFromBlocklist_NoMatchingRow_ReturnsControlledError()
	{
		(IDbContextFactory<AuditDbContext> factory, SqliteConnection conn) = await CreateDbAsync();
		try
		{
			IpcDispatcher dispatcher = CreateDispatcher(factory, new RdpAuditOptions(), Array.Empty<IFirewallProvider>());
			AddressListMutationRequest req = new() { Id = 999, Address = "203.0.113.11" };
			IpcResponse response = await dispatcher.DispatchAsync(new IpcRequest
			{
				Command = IpcCommand.RemoveFromBlocklist,
				Payload = JsonSerializer.Serialize(req, JsonOptions.Default),
			}, CancellationToken.None);

			Assert.False(response.Success);
			Assert.NotNull(response.Error);
			Assert.Contains("nothing was removed", response.Error!, StringComparison.Ordinal);
		}
		finally
		{
			await conn.DisposeAsync();
		}
	}

	[Fact]
	public async Task ListBlocklist_ProjectsStableRowId()
	{
		(IDbContextFactory<AuditDbContext> factory, SqliteConnection conn) = await CreateDbAsync();
		try
		{
			long expectedId;
			await using (AuditDbContext seed = factory.CreateDbContext())
			{
				BlocklistEntry row = new()
				{
					Ip = "203.0.113.12",
					Reason = "manual",
					AddedUtc = DateTime.UtcNow,
					Source = BlocklistSource.Manual,
					IsEnabled = true,
				};
				seed.BlocklistEntries.Add(row);
				await seed.SaveChangesAsync();
				expectedId = row.Id;
			}

			IpcDispatcher dispatcher = CreateDispatcher(factory, new RdpAuditOptions(), Array.Empty<IFirewallProvider>());
			IpcResponse response = await dispatcher.DispatchAsync(new IpcRequest
			{
				Command = IpcCommand.ListBlocklist,
			}, CancellationToken.None);

			Assert.True(response.Success);
			Assert.NotNull(response.Payload);
			List<AddressListEntryDto>? rows =
				JsonSerializer.Deserialize<List<AddressListEntryDto>>(response.Payload!, JsonOptions.Default);
			Assert.NotNull(rows);
			AddressListEntryDto dto = Assert.Single(rows!);
			Assert.Equal(expectedId, dto.Id);
			Assert.Equal("203.0.113.12", dto.Address);
		}
		finally
		{
			await conn.DisposeAsync();
		}
	}

	[Fact]
	public async Task GetFirewallStatus_ReturnsDtoWithCounters()
	{
		(IDbContextFactory<AuditDbContext> factory, SqliteConnection conn) = await CreateDbAsync();
		try
		{
			await using (AuditDbContext seed = factory.CreateDbContext())
			{
				seed.WhitelistEntries.Add(new WhitelistEntry { Ip = "203.0.113.5", AddedUtc = DateTime.UtcNow });
				seed.BlocklistEntries.Add(new BlocklistEntry
				{
					Ip = "203.0.113.10",
					Reason = "manual",
					AddedUtc = DateTime.UtcNow,
					Source = BlocklistSource.Manual,
					IsEnabled = true,
				});
				seed.ActiveBlocks.Add(new ActiveBlock
				{
					Ip = "203.0.113.10",
					Provider = FirewallProviderKind.Windows,
					CreatedUtc = DateTime.UtcNow,
					Reason = "manual",
					Status = ActiveBlockStatus.Active,
				});
				await seed.SaveChangesAsync();
			}

			IpcDispatcher dispatcher = CreateDispatcher(factory, new RdpAuditOptions(), Array.Empty<IFirewallProvider>());
			IpcResponse response = await dispatcher.DispatchAsync(new IpcRequest
			{
				Command = IpcCommand.GetFirewallStatus,
			}, CancellationToken.None);

			Assert.True(response.Success);
			Assert.NotNull(response.Payload);
			FirewallStatusDto? dto = JsonSerializer.Deserialize<FirewallStatusDto>(response.Payload!, JsonOptions.Default);
			Assert.NotNull(dto);
			Assert.Equal(IpcResultStatus.Success, dto!.Status);
			Assert.Equal(1, dto.ActiveBlockCount);
			Assert.Equal(1, dto.WhitelistCount);
			Assert.Equal(1, dto.BlacklistCount);
		}
		finally
		{
			await conn.DisposeAsync();
		}
	}

	[Fact]
	public async Task AddToBlocklist_MissingPayload_ReturnsControlledError()
	{
		(IDbContextFactory<AuditDbContext> factory, SqliteConnection conn) = await CreateDbAsync();
		try
		{
			IpcDispatcher dispatcher = CreateDispatcher(factory, new RdpAuditOptions(), Array.Empty<IFirewallProvider>());
			IpcResponse response = await dispatcher.DispatchAsync(new IpcRequest
			{
				Command = IpcCommand.AddToBlocklist,
				Payload = null,
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
