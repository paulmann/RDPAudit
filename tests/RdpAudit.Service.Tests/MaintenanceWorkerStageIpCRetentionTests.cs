// File:    tests/RdpAudit.Service.Tests/MaintenanceWorkerStageIpCRetentionTests.cs
// Module:  RdpAudit.Service.Tests
// Purpose: Stage IP-C retention test — verifies MaintenanceWorker prunes stale RdpConnectionFacts
//          beyond the configured retention window while keeping recent rows.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using RdpAudit.Core.Config;
using RdpAudit.Core.Data;
using RdpAudit.Core.Models;
using RdpAudit.Service.Workers;
using Xunit;

namespace RdpAudit.Service.Tests;

public class MaintenanceWorkerStageIpCRetentionTests
{
	private sealed class TestDbContextFactory : IDbContextFactory<AuditDbContext>
	{
		private readonly DbContextOptions<AuditDbContext> _options;
		public TestDbContextFactory(DbContextOptions<AuditDbContext> options) => _options = options;
		public AuditDbContext CreateDbContext() => new(_options);
	}

	private sealed class StaticOptionsMonitor<T> : IOptionsMonitor<T>
	{
		public StaticOptionsMonitor(T value) => CurrentValue = value;
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

	[Fact]
	public async Task RunOnceAsync_PrunesStaleConnectionFacts_AndKeepsRecent()
	{
		(IDbContextFactory<AuditDbContext> factory, SqliteConnection conn) = await CreateDbAsync();
		try
		{
			DateTime now = DateTime.UtcNow;
			await using (AuditDbContext seed = factory.CreateDbContext())
			{
				// Stale (older than 90 days).
				seed.RdpConnectionFacts.Add(new RdpConnectionFact
				{
					LogonId = "0xOLD",
					Ip = "10.0.0.1",
					UserName = "stale",
					FirstSeenUtc = now.AddDays(-180),
					LastSeenUtc = now.AddDays(-120),
				});

				// Recent (within retention window).
				seed.RdpConnectionFacts.Add(new RdpConnectionFact
				{
					LogonId = "0xNEW",
					Ip = "203.0.113.4",
					UserName = "fresh",
					FirstSeenUtc = now.AddDays(-2),
					LastSeenUtc = now.AddDays(-1),
				});

				await seed.SaveChangesAsync();
			}

			RdpAuditOptions opts = new();
			opts.Storage.RdpConnectionFactRetentionDays = 90;
			opts.Storage.MaintenanceBatchSize = 50000;

			MaintenanceWorker worker = new(factory, new StaticOptionsMonitor<RdpAuditOptions>(opts),
				NullLogger<MaintenanceWorker>.Instance);

			await worker.RunOnceAsync(CancellationToken.None);

			await using AuditDbContext db = factory.CreateDbContext();
			List<RdpConnectionFact> remaining = await db.RdpConnectionFacts.ToListAsync();
			Assert.Single(remaining);
			Assert.Equal("0xNEW", remaining[0].LogonId);
		}
		finally
		{
			await conn.DisposeAsync();
		}
	}

	[Fact]
	public async Task RunOnceAsync_HonoursMinimumRetentionFloor_30Days()
	{
		(IDbContextFactory<AuditDbContext> factory, SqliteConnection conn) = await CreateDbAsync();
		try
		{
			DateTime now = DateTime.UtcNow;
			await using (AuditDbContext seed = factory.CreateDbContext())
			{
				// 20 days old — would be pruned at retention=10 if the floor were honoured directly,
				// but the maintenance worker floors retention at 30 days, so this must survive.
				seed.RdpConnectionFacts.Add(new RdpConnectionFact
				{
					LogonId = "0xMID",
					Ip = "10.0.0.2",
					UserName = "midaged",
					FirstSeenUtc = now.AddDays(-25),
					LastSeenUtc = now.AddDays(-20),
				});

				await seed.SaveChangesAsync();
			}

			RdpAuditOptions opts = new();
			// Operator misconfiguration — floor must still apply.
			opts.Storage.RdpConnectionFactRetentionDays = 1;
			opts.Storage.MaintenanceBatchSize = 50000;

			MaintenanceWorker worker = new(factory, new StaticOptionsMonitor<RdpAuditOptions>(opts),
				NullLogger<MaintenanceWorker>.Instance);

			await worker.RunOnceAsync(CancellationToken.None);

			await using AuditDbContext db = factory.CreateDbContext();
			Assert.Single(await db.RdpConnectionFacts.ToListAsync());
		}
		finally
		{
			await conn.DisposeAsync();
		}
	}
}
