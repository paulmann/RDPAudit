// File:    tests/RdpAudit.Service.Tests/ApplicationDataPurgeServiceTests.cs
// Module:  RdpAudit.Service.Tests
// Purpose: Tests for the DEBUG-gated full application-data cleanup (Req C). Drives PurgeAllAsync against
//          an in-memory SQLite database seeded with rows across the accumulated operational tables, and
//          verifies that those tables are cleared with accurate per-table counts while the preserved
//          surfaces (DbProps configuration, event-log Bookmarks, schema / migrations) survive — so the
//          service stays healthy and reachable after a purge. Also covers the already-empty no-op.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using RdpAudit.Core.Config;
using RdpAudit.Core.Data;
using RdpAudit.Core.Ipc.Contracts;
using RdpAudit.Core.Models;
using RdpAudit.Service.Services;
using Xunit;

namespace RdpAudit.Service.Tests;

public class ApplicationDataPurgeServiceTests
{
	private sealed class TestDbContextFactory : IDbContextFactory<AuditDbContext>
	{
		private readonly DbContextOptions<AuditDbContext> _options;

		public TestDbContextFactory(DbContextOptions<AuditDbContext> options) => _options = options;

		public AuditDbContext CreateDbContext() => new(_options);
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

	private static ApplicationDataPurgeService MakeService(IDbContextFactory<AuditDbContext> factory) =>
		new(factory, NullLogger<ApplicationDataPurgeService>.Instance, TimeProvider.System);

	[Fact]
	public async Task PurgeAllAsync_ClearsOperationalData_PreservesConfigAndBookmarks()
	{
		(IDbContextFactory<AuditDbContext> factory, SqliteConnection conn) = await CreateDbAsync();
		try
		{
			await using (AuditDbContext db = factory.CreateDbContext())
			{
				db.RawEvents.Add(new RawEvent
				{
					Channel = "Security",
					EventId = 4625,
					TimeUtc = DateTime.UtcNow,
				});
				db.ActiveBlocks.Add(new ActiveBlock
				{
					Ip = "203.0.113.10",
					Provider = FirewallProviderKind.Windows,
					CreatedUtc = DateTime.UtcNow,
					Reason = "test",
					Status = ActiveBlockStatus.Active,
				});
				db.BlocklistEntries.Add(new BlocklistEntry
				{
					Ip = "203.0.113.10",
					Reason = "test",
					AddedUtc = DateTime.UtcNow,
					Source = BlocklistSource.Manual,
					IsEnabled = true,
				});
				db.Alerts.Add(new Alert
				{
					RuleId = "test-rule",
					Severity = AlertSeverity.Medium,
					TimeUtc = DateTime.UtcNow,
					Message = "test",
				});

				// Preserved surfaces: configuration prop and an event-log read bookmark.
				db.DbProps.Add(new DbProp { Key = "SchemaVersion", Value = "42" });
				db.Bookmarks.Add(new Bookmark { Channel = "Security", BookmarkXml = "<BookmarkList/>" });
				await db.SaveChangesAsync();
			}

			ApplicationDataPurgeService svc = MakeService(factory);

			AppDataPurgeResultDto result = await svc.PurgeAllAsync(CancellationToken.None);

			Assert.Equal(IpcResultStatus.Success, result.Status);
			Assert.Equal(0, result.Errors);
			Assert.True(result.WalCheckpointed);
			Assert.True(result.DatabaseVacuumed);

			int rawCleared = Assert.Single(result.TablesCleared, t => t.Table == "RawEvents").RowsCleared;
			Assert.Equal(1, rawCleared);
			Assert.Equal(1, Assert.Single(result.TablesCleared, t => t.Table == "ActiveBlocks").RowsCleared);
			Assert.Equal(1, Assert.Single(result.TablesCleared, t => t.Table == "BlocklistEntries").RowsCleared);
			Assert.Equal(1, Assert.Single(result.TablesCleared, t => t.Table == "Alerts").RowsCleared);

			await using AuditDbContext verify = factory.CreateDbContext();
			Assert.Equal(0, await verify.RawEvents.CountAsync());
			Assert.Equal(0, await verify.ActiveBlocks.CountAsync());
			Assert.Equal(0, await verify.BlocklistEntries.CountAsync());
			Assert.Equal(0, await verify.Alerts.CountAsync());

			// Preserved surfaces survive so the service stays healthy and never re-reads the whole log.
			Assert.Equal(1, await verify.DbProps.CountAsync());
			Assert.Equal(1, await verify.Bookmarks.CountAsync());
		}
		finally
		{
			await conn.DisposeAsync();
		}
	}

	[Fact]
	public async Task PurgeAllAsync_AlreadyEmpty_IsSuccessfulNoOp()
	{
		(IDbContextFactory<AuditDbContext> factory, SqliteConnection conn) = await CreateDbAsync();
		try
		{
			ApplicationDataPurgeService svc = MakeService(factory);

			AppDataPurgeResultDto result = await svc.PurgeAllAsync(CancellationToken.None);

			Assert.Equal(IpcResultStatus.Success, result.Status);
			Assert.Equal(0, result.Errors);
			Assert.All(result.TablesCleared, t => Assert.Equal(0, t.RowsCleared));
			Assert.True(result.WalCheckpointed);
			Assert.True(result.DatabaseVacuumed);
		}
		finally
		{
			await conn.DisposeAsync();
		}
	}
}
