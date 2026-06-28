// File:    tests/RdpAudit.Service.Tests/IpcDispatcherDedupeTests.cs
// Module:  RdpAudit.Service.Tests
// Purpose: Tests for the v1.3.1 DedupeBlocklistEntries IPC command. Confirms that duplicate
//          BlocklistEntry rows sharing one IP collapse to a single canonical row (enabled preferred,
//          then oldest by AddedUtc, then lowest Id), that duplicates are soft-disabled with an audit
//          annotation rather than hard-deleted, and that distinct IPs are left untouched.
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

public class IpcDispatcherDedupeTests
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
			abuseClient: null, protector: null,
			mikroTikClient: null);
	}

	private static async Task<BlocklistDedupeResultDto> RunDedupeAsync(IpcDispatcher dispatcher)
	{
		IpcResponse response = await dispatcher.DispatchAsync(
			new IpcRequest { Command = IpcCommand.DedupeBlocklistEntries }, CancellationToken.None);
		Assert.True(response.Success);
		BlocklistDedupeResultDto? dto = JsonSerializer.Deserialize<BlocklistDedupeResultDto>(response.Payload!, JsonOptions.Default);
		Assert.NotNull(dto);
		return dto!;
	}

	[Fact]
	public async Task Dedupe_CollapsesDuplicates_KeepsEnabledCanonical_SoftDisablesOthers()
	{
		(IDbContextFactory<AuditDbContext> factory, SqliteConnection conn) = await CreateDbAsync();
		try
		{
			const string ip = "203.0.113.10";
			long enabledId;
			await using (AuditDbContext db = factory.CreateDbContext())
			{
				// Oldest row is disabled; a newer enabled row must win as canonical (enabled preferred).
				db.BlocklistEntries.Add(new BlocklistEntry { Ip = ip, Reason = "old-disabled", AddedUtc = DateTime.UtcNow.AddDays(-2), Source = BlocklistSource.Manual, IsEnabled = false });
				BlocklistEntry enabled = new() { Ip = ip, Reason = "enabled", AddedUtc = DateTime.UtcNow.AddDays(-1), Source = BlocklistSource.Manual, IsEnabled = true };
				db.BlocklistEntries.Add(enabled);
				db.BlocklistEntries.Add(new BlocklistEntry { Ip = ip, Reason = "newer-enabled", AddedUtc = DateTime.UtcNow, Source = BlocklistSource.Manual, IsEnabled = true });
				await db.SaveChangesAsync();
				enabledId = enabled.Id;
			}

			IpcDispatcher dispatcher = CreateDispatcher(factory, new RdpAuditOptions());
			BlocklistDedupeResultDto result = await RunDedupeAsync(dispatcher);

			Assert.Equal(IpcResultStatus.Success, result.Status);
			Assert.Equal(1, result.IpsCollapsed);
			// One enabled duplicate disabled; the already-disabled row is left as-is (not re-counted).
			Assert.Equal(1, result.RowsDisabled);
			Assert.Single(result.Audit);

			await using AuditDbContext verify = factory.CreateDbContext();
			// Exactly one enabled row remains and it is the oldest enabled (canonical) row.
			List<BlocklistEntry> remaining = await verify.BlocklistEntries.Where(b => b.Ip == ip && b.IsEnabled).ToListAsync();
			BlocklistEntry canonical = Assert.Single(remaining);
			Assert.Equal(enabledId, canonical.Id);
			// Nothing was hard-deleted: all three rows still exist.
			Assert.Equal(3, await verify.BlocklistEntries.CountAsync(b => b.Ip == ip));
			// The disabled duplicate carries the audit annotation.
			Assert.Contains(await verify.BlocklistEntries.Where(b => b.Ip == ip && !b.IsEnabled).Select(b => b.Reason).ToListAsync(),
				r => r != null && r.Contains("deduped", StringComparison.OrdinalIgnoreCase));
		}
		finally
		{
			await conn.DisposeAsync();
		}
	}

	[Fact]
	public async Task Dedupe_NoDuplicates_LeavesDistinctIpsUntouched()
	{
		(IDbContextFactory<AuditDbContext> factory, SqliteConnection conn) = await CreateDbAsync();
		try
		{
			await using (AuditDbContext db = factory.CreateDbContext())
			{
				db.BlocklistEntries.Add(new BlocklistEntry { Ip = "203.0.113.10", Reason = "a", AddedUtc = DateTime.UtcNow, Source = BlocklistSource.Manual, IsEnabled = true });
				db.BlocklistEntries.Add(new BlocklistEntry { Ip = "203.0.113.20", Reason = "b", AddedUtc = DateTime.UtcNow, Source = BlocklistSource.Manual, IsEnabled = true });
				await db.SaveChangesAsync();
			}

			IpcDispatcher dispatcher = CreateDispatcher(factory, new RdpAuditOptions());
			BlocklistDedupeResultDto result = await RunDedupeAsync(dispatcher);

			Assert.Equal(0, result.IpsCollapsed);
			Assert.Equal(0, result.RowsDisabled);

			await using AuditDbContext verify = factory.CreateDbContext();
			Assert.Equal(2, await verify.BlocklistEntries.CountAsync(b => b.IsEnabled));
		}
		finally
		{
			await conn.DisposeAsync();
		}
	}
}
