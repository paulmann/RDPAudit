// File:    tests/RdpAudit.Service.Tests/MaintenanceWorkerStageIpBRetentionTests.cs
// Module:  RdpAudit.Service.Tests
// Purpose: Stage IP-B retention test — verifies MaintenanceWorker prunes stale SessionIpCorrelations
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

public class MaintenanceWorkerStageIpBRetentionTests
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
	public async Task RunOnceAsync_PrunesStaleCorrelations_AndKeepsRecent()
	{
		(IDbContextFactory<AuditDbContext> factory, SqliteConnection conn) = await CreateDbAsync();
		try
		{
			DateTime now = DateTime.UtcNow;
			await using (AuditDbContext seed = factory.CreateDbContext())
			{
				// Stale (>30d).
				seed.SessionIpCorrelations.Add(new SessionIpCorrelation
				{
					LogonId = "0xOLD",
					Ip = "10.0.0.1",
					FirstSeenUtc = now.AddDays(-60),
					LastSeenUtc = now.AddDays(-60),
				});
				// Recent.
				seed.SessionIpCorrelations.Add(new SessionIpCorrelation
				{
					LogonId = "0xNEW",
					Ip = "203.0.113.4",
					FirstSeenUtc = now.AddDays(-1),
					LastSeenUtc = now.AddDays(-1),
				});
				await seed.SaveChangesAsync();
			}

			RdpAuditOptions opts = new();
			opts.Storage.SessionIpCorrelationRetentionDays = 30;
			opts.Storage.MaintenanceBatchSize = 50000;

			MaintenanceWorker worker = new(factory, new StaticOptionsMonitor<RdpAuditOptions>(opts),
				NullLogger<MaintenanceWorker>.Instance);

			await worker.RunOnceAsync(CancellationToken.None);

			await using AuditDbContext db = factory.CreateDbContext();
			List<SessionIpCorrelation> remaining = await db.SessionIpCorrelations.ToListAsync();
			Assert.Single(remaining);
			Assert.Equal("0xNEW", remaining[0].LogonId);
		}
		finally
		{
			await conn.DisposeAsync();
		}
	}
}
