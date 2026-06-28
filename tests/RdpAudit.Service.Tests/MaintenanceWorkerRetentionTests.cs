// File:    tests/RdpAudit.Service.Tests/MaintenanceWorkerRetentionTests.cs
// Module:  RdpAudit.Service.Tests
// Purpose: Stage 10 retention pruning tests for MaintenanceWorker — verifies that RawEvents,
//          Alerts, AbuseReports, inactive ActiveBlocks and stale AttackStats are pruned past
//          their respective retention cutoffs while live rows are preserved.
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

public class MaintenanceWorkerRetentionTests
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
	public async Task RunOnceAsync_PrunesOldRowsAcrossAllRetentionTables()
	{
		(IDbContextFactory<AuditDbContext> factory, SqliteConnection conn) = await CreateDbAsync();
		try
		{
			DateTime now = DateTime.UtcNow;

			await using (AuditDbContext seed = factory.CreateDbContext())
			{
				// RawEvents: one stale (2 years), one fresh.
				seed.RawEvents.Add(new RawEvent
				{
					EventId = 4625,
					Channel = "Security",
					TimeUtc = now.AddDays(-800),
				});
				seed.RawEvents.Add(new RawEvent
				{
					EventId = 4625,
					Channel = "Security",
					TimeUtc = now.AddDays(-1),
				});

				// Alerts: one stale (3 years), one fresh.
				seed.Alerts.Add(new Alert
				{
					RuleId = "test",
					TimeUtc = now.AddDays(-1100),
					SourceIp = "203.0.113.5",
					UserName = "u",
					Severity = AlertSeverity.Low,
					Message = "old",
				});
				seed.Alerts.Add(new Alert
				{
					RuleId = "test",
					TimeUtc = now.AddDays(-2),
					SourceIp = "203.0.113.5",
					UserName = "u",
					Severity = AlertSeverity.Low,
					Message = "new",
				});

				// AbuseReports: one stale (2 years), one fresh.
				seed.AbuseReports.Add(new AbuseReport
				{
					Ip = "203.0.113.10",
					ReportedUtc = now.AddDays(-800),
					Categories = "22",
					ResponseCode = 200,
				});
				seed.AbuseReports.Add(new AbuseReport
				{
					Ip = "203.0.113.10",
					ReportedUtc = now.AddDays(-30),
					Categories = "22",
					ResponseCode = 200,
				});

				// ActiveBlocks: one Active (never deleted regardless of date), one Removed (eligible),
				// one expired long ago (eligible), one expired recently (NOT eligible).
				seed.ActiveBlocks.Add(new ActiveBlock
				{
					Ip = "203.0.113.20",
					Provider = FirewallProviderKind.Windows,
					CreatedUtc = now.AddDays(-3000),
					Reason = "active-old",
					Status = ActiveBlockStatus.Active,
				});
				seed.ActiveBlocks.Add(new ActiveBlock
				{
					Ip = "203.0.113.21",
					Provider = FirewallProviderKind.Windows,
					CreatedUtc = now.AddDays(-200),
					Reason = "removed",
					Status = ActiveBlockStatus.Removed,
				});
				seed.ActiveBlocks.Add(new ActiveBlock
				{
					Ip = "203.0.113.22",
					Provider = FirewallProviderKind.Windows,
					CreatedUtc = now.AddDays(-200),
					ExpiresUtc = now.AddDays(-150),
					Reason = "expired-old",
					Status = ActiveBlockStatus.Active,
				});
				seed.ActiveBlocks.Add(new ActiveBlock
				{
					Ip = "203.0.113.23",
					Provider = FirewallProviderKind.Windows,
					CreatedUtc = now.AddDays(-10),
					ExpiresUtc = now.AddDays(-1),
					Reason = "expired-recent",
					Status = ActiveBlockStatus.Active,
				});

				// AttackStats: one stale, one fresh.
				seed.AttackStats.Add(new AttackStat
				{
					Ip = "203.0.113.30",
					LastSeenUtc = now.AddDays(-400),
					FirstSeenUtc = now.AddDays(-400),
					LastUpdatedUtc = now.AddDays(-400),
				});
				seed.AttackStats.Add(new AttackStat
				{
					Ip = "203.0.113.31",
					LastSeenUtc = now.AddDays(-1),
					FirstSeenUtc = now.AddDays(-1),
					LastUpdatedUtc = now.AddDays(-1),
				});

				// Address rows to exercise the threat-score decay path.
				seed.Addresses.Add(new Address { Ip = "203.0.113.30", ThreatScore = 80.0 });

				await seed.SaveChangesAsync();
			}

			RdpAuditOptions opts = new();
			opts.Storage.EventRetentionDays = 365;
			opts.Storage.AlertRetentionDays = 730;
			opts.Storage.AbuseReportRetentionDays = 365;
			opts.Storage.ActiveBlockRetentionDays = 90;
			opts.Storage.AttackStatRetentionDays = 180;
			opts.Storage.MaintenanceBatchSize = 50000;

			MaintenanceWorker worker = new(factory, new StaticOptionsMonitor<RdpAuditOptions>(opts),
				NullLogger<MaintenanceWorker>.Instance);

			await worker.RunOnceAsync(CancellationToken.None);

			await using AuditDbContext db = factory.CreateDbContext();
			Assert.Equal(1, await db.RawEvents.CountAsync());
			Assert.Equal(1, await db.Alerts.CountAsync());
			Assert.Equal(1, await db.AbuseReports.CountAsync());
			// Active row retained; removed + long-expired rows pruned; recently-expired retained.
			List<ActiveBlock> blocks = await db.ActiveBlocks.OrderBy(b => b.Ip).ToListAsync();
			Assert.Equal(2, blocks.Count);
			Assert.Contains(blocks, b => b.Ip == "203.0.113.20" && b.Status == ActiveBlockStatus.Active);
			Assert.Contains(blocks, b => b.Ip == "203.0.113.23");
			Assert.Equal(1, await db.AttackStats.CountAsync());
			// Decay applied.
			Address? addr = await db.Addresses.SingleOrDefaultAsync();
			Assert.NotNull(addr);
			Assert.True(addr!.ThreatScore < 80.0);
		}
		finally
		{
			await conn.DisposeAsync();
		}
	}

	[Fact]
	public async Task RunOnceAsync_RespectsBatchSize_RemovingAllEligibleRows()
	{
		(IDbContextFactory<AuditDbContext> factory, SqliteConnection conn) = await CreateDbAsync();
		try
		{
			DateTime now = DateTime.UtcNow;
			await using (AuditDbContext seed = factory.CreateDbContext())
			{
				for (int i = 0; i < 25; i++)
				{
					seed.RawEvents.Add(new RawEvent
					{
						EventId = 4625,
						Channel = "Security",
						TimeUtc = now.AddDays(-1000 - i),
					});
				}

				await seed.SaveChangesAsync();
			}

			RdpAuditOptions opts = new();
			opts.Storage.EventRetentionDays = 365;
			opts.Storage.MaintenanceBatchSize = 1000; // batched path takes the >=1000 floor

			MaintenanceWorker worker = new(factory, new StaticOptionsMonitor<RdpAuditOptions>(opts),
				NullLogger<MaintenanceWorker>.Instance);

			await worker.RunOnceAsync(CancellationToken.None);

			await using AuditDbContext db = factory.CreateDbContext();
			Assert.Equal(0, await db.RawEvents.CountAsync());
		}
		finally
		{
			await conn.DisposeAsync();
		}
	}
}
