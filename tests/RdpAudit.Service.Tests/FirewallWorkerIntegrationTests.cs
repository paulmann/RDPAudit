// File:    tests/RdpAudit.Service.Tests/FirewallWorkerIntegrationTests.cs
// Module:  RdpAudit.Service.Tests
// Purpose: Integration-style tests for FirewallAutoBlockWorker and FirewallExpirationWorker
//          driven against an in-memory SQLite database with a mocked IFirewallProvider. Covers
//          the policy decisions (whitelist skip, threshold block, instant trip-wire) and the
//          expiration round-trip (provider success -> Removed, provider failure -> Failed).
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using RdpAudit.Core.Config;
using RdpAudit.Core.Data;
using RdpAudit.Core.Firewall;
using RdpAudit.Core.Models;
using RdpAudit.Service.Workers;
using Xunit;

namespace RdpAudit.Service.Tests;

public class FirewallWorkerIntegrationTests
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

	private sealed class MockFirewallProvider : IFirewallProvider
	{
		public string ProviderId { get; init; } = "Windows";

		public Queue<FirewallActionResult> BlockResponses { get; } = new();

		public Queue<FirewallActionResult> UnblockResponses { get; } = new();

		public List<FirewallBlockRequest> BlockCalls { get; } = new();

		public List<string> UnblockCalls { get; } = new();

		public Task<FirewallStatusReport> GetStatusAsync(CancellationToken ct) =>
			Task.FromResult(new FirewallStatusReport
			{
				Status = FirewallProviderStatus.Available,
				ProviderId = ProviderId,
			});

		public Task<FirewallActionResult> BlockAsync(FirewallBlockRequest request, CancellationToken ct)
		{
			BlockCalls.Add(request);
			FirewallActionResult result = BlockResponses.Count > 0
				? BlockResponses.Dequeue()
				: new FirewallActionResult
				{
					Status = FirewallActionStatus.Success,
					ProviderId = ProviderId,
					RuleId = "RdpAudit-Block-" + request.Ip,
				};
			return Task.FromResult(result);
		}

		public Task<FirewallActionResult> UnblockAsync(string ip, string ruleName, CancellationToken ct)
		{
			UnblockCalls.Add(ip);
			FirewallActionResult result = UnblockResponses.Count > 0
				? UnblockResponses.Dequeue()
				: new FirewallActionResult
				{
					Status = FirewallActionStatus.Success,
					ProviderId = ProviderId,
					RuleId = "RdpAudit-Block-" + ip,
				};
			return Task.FromResult(result);
		}

		public Task<IReadOnlyList<FirewallBlockEntry>> ListBlocksAsync(string ruleName, CancellationToken ct) =>
			Task.FromResult<IReadOnlyList<FirewallBlockEntry>>(Array.Empty<FirewallBlockEntry>());
	}

	private static IOptionsMonitor<RdpAuditOptions> Options(RdpAuditOptions opts) =>
		new StaticOptionsMonitor<RdpAuditOptions>(opts);

	private static Alert NewAlert(long id, string ruleId, string? ip, string? user) => new()
	{
		Id = id,
		RuleId = ruleId,
		Severity = AlertSeverity.High,
		TimeUtc = DateTime.UtcNow,
		SourceIp = ip,
		UserName = user,
		Message = "test",
		TriggerEventId = id,
	};

	[Fact]
	public async Task AutoBlockWorker_WhitelistedIp_DoesNotWriteActiveBlock()
	{
		(IDbContextFactory<AuditDbContext> factory, SqliteConnection conn) = await CreateDbAsync();
		try
		{
			await using (AuditDbContext seed = factory.CreateDbContext())
			{
				seed.WhitelistEntries.Add(new WhitelistEntry { Ip = "203.0.113.10", AddedUtc = DateTime.UtcNow });
				seed.Alerts.Add(NewAlert(1, "BRUTE_FORCE_01", "203.0.113.10", "alice"));
				await seed.SaveChangesAsync();
			}

			MockFirewallProvider provider = new();
			FirewallAutoBlockWorker worker = new(
				factory,
				Options(new RdpAuditOptions { Firewall = new FirewallOptions { AutoBlockBruteForce = true } }),
				new IFirewallProvider[] { provider },
				NullLogger<FirewallAutoBlockWorker>.Instance);

			await InvokeProcessBatchAsync(worker);

			Assert.Empty(provider.BlockCalls);
			await using AuditDbContext db = factory.CreateDbContext();
			Assert.Empty(await db.ActiveBlocks.ToListAsync());
		}
		finally
		{
			await conn.DisposeAsync();
		}
	}

	[Fact]
	public async Task AutoBlockWorker_BruteForce_WritesActiveBlockAndBlocklistEntry()
	{
		(IDbContextFactory<AuditDbContext> factory, SqliteConnection conn) = await CreateDbAsync();
		try
		{
			await using (AuditDbContext seed = factory.CreateDbContext())
			{
				seed.Alerts.Add(NewAlert(1, "BRUTE_FORCE_01", "203.0.113.10", "alice"));
				await seed.SaveChangesAsync();
			}

			MockFirewallProvider provider = new();
			FirewallAutoBlockWorker worker = new(
				factory,
				Options(new RdpAuditOptions { Firewall = new FirewallOptions { AutoBlockBruteForce = true } }),
				new IFirewallProvider[] { provider },
				NullLogger<FirewallAutoBlockWorker>.Instance);

			await InvokeProcessBatchAsync(worker);

			Assert.Single(provider.BlockCalls);
			Assert.Equal("203.0.113.10", provider.BlockCalls[0].Ip);

			await using AuditDbContext db = factory.CreateDbContext();
			ActiveBlock active = Assert.Single(await db.ActiveBlocks.ToListAsync());
			Assert.Equal(ActiveBlockStatus.Active, active.Status);
			Assert.Equal("203.0.113.10", active.Ip);
			BlocklistEntry blocklist = Assert.Single(await db.BlocklistEntries.ToListAsync());
			Assert.Equal(BlocklistSource.Auto, blocklist.Source);
			Assert.True(blocklist.IsEnabled);
		}
		finally
		{
			await conn.DisposeAsync();
		}
	}

	[Fact]
	public async Task AutoBlockWorker_InstantLogin_TripsBlockEvenWithoutBruteForce()
	{
		(IDbContextFactory<AuditDbContext> factory, SqliteConnection conn) = await CreateDbAsync();
		try
		{
			await using (AuditDbContext seed = factory.CreateDbContext())
			{
				seed.LoginRules.Add(new LoginRule { Login = "guest", Enabled = true, AddedUtc = DateTime.UtcNow });
				seed.Alerts.Add(NewAlert(1, "EXTERNAL_RDP_LOGIN", "203.0.113.11", "guest"));
				await seed.SaveChangesAsync();
			}

			MockFirewallProvider provider = new();
			FirewallAutoBlockWorker worker = new(
				factory,
				Options(new RdpAuditOptions { Firewall = new FirewallOptions { AutoBlockBruteForce = false } }),
				new IFirewallProvider[] { provider },
				NullLogger<FirewallAutoBlockWorker>.Instance);

			await InvokeProcessBatchAsync(worker);

			Assert.Single(provider.BlockCalls);
			await using AuditDbContext db = factory.CreateDbContext();
			Assert.Single(await db.ActiveBlocks.ToListAsync());
		}
		finally
		{
			await conn.DisposeAsync();
		}
	}

	[Fact]
	public async Task AutoBlockWorker_DoesNotDuplicateActiveBlock()
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
					CreatedUtc = DateTime.UtcNow,
					Reason = "existing",
					Status = ActiveBlockStatus.Active,
				});
				seed.Alerts.Add(NewAlert(1, "BRUTE_FORCE_01", "203.0.113.10", "alice"));
				await seed.SaveChangesAsync();
			}

			MockFirewallProvider provider = new();
			FirewallAutoBlockWorker worker = new(
				factory,
				Options(new RdpAuditOptions { Firewall = new FirewallOptions { AutoBlockBruteForce = true } }),
				new IFirewallProvider[] { provider },
				NullLogger<FirewallAutoBlockWorker>.Instance);

			await InvokeProcessBatchAsync(worker);

			Assert.Empty(provider.BlockCalls);
			await using AuditDbContext db = factory.CreateDbContext();
			Assert.Single(await db.ActiveBlocks.ToListAsync());
		}
		finally
		{
			await conn.DisposeAsync();
		}
	}

	[Fact]
	public async Task AutoBlockWorker_ProviderError_FlagsActiveBlockFailed()
	{
		(IDbContextFactory<AuditDbContext> factory, SqliteConnection conn) = await CreateDbAsync();
		try
		{
			await using (AuditDbContext seed = factory.CreateDbContext())
			{
				seed.Alerts.Add(NewAlert(1, "BRUTE_FORCE_01", "203.0.113.10", "alice"));
				await seed.SaveChangesAsync();
			}

			MockFirewallProvider provider = new();
			provider.BlockResponses.Enqueue(new FirewallActionResult
			{
				Status = FirewallActionStatus.Unavailable,
				ProviderId = "Windows",
				Message = "netsh add rule returned exit=1.",
			});

			FirewallAutoBlockWorker worker = new(
				factory,
				Options(new RdpAuditOptions { Firewall = new FirewallOptions { AutoBlockBruteForce = true } }),
				new IFirewallProvider[] { provider },
				NullLogger<FirewallAutoBlockWorker>.Instance);

			await InvokeProcessBatchAsync(worker);

			await using AuditDbContext db = factory.CreateDbContext();
			ActiveBlock active = Assert.Single(await db.ActiveBlocks.ToListAsync());
			Assert.Equal(ActiveBlockStatus.Failed, active.Status);
			Assert.NotNull(active.LastError);
		}
		finally
		{
			await conn.DisposeAsync();
		}
	}

	[Fact]
	public async Task ExpirationWorker_UnblocksAndMarksRemoved()
	{
		(IDbContextFactory<AuditDbContext> factory, SqliteConnection conn) = await CreateDbAsync();
		try
		{
			DateTime past = DateTime.UtcNow.AddMinutes(-5);
			await using (AuditDbContext seed = factory.CreateDbContext())
			{
				seed.ActiveBlocks.Add(new ActiveBlock
				{
					Ip = "203.0.113.10",
					Provider = FirewallProviderKind.Windows,
					CreatedUtc = past.AddMinutes(-10),
					ExpiresUtc = past,
					Reason = "expired",
					Status = ActiveBlockStatus.Active,
				});
				await seed.SaveChangesAsync();
			}

			MockFirewallProvider provider = new();
			FirewallExpirationWorker worker = new(
				factory,
				Options(new RdpAuditOptions()),
				new IFirewallProvider[] { provider },
				NullLogger<FirewallExpirationWorker>.Instance);

			await worker.TickAsync(CancellationToken.None);

			Assert.Single(provider.UnblockCalls);
			await using AuditDbContext db = factory.CreateDbContext();
			ActiveBlock row = Assert.Single(await db.ActiveBlocks.ToListAsync());
			Assert.Equal(ActiveBlockStatus.Removed, row.Status);
		}
		finally
		{
			await conn.DisposeAsync();
		}
	}

	[Fact]
	public async Task ExpirationWorker_ProviderError_MarksFailed()
	{
		(IDbContextFactory<AuditDbContext> factory, SqliteConnection conn) = await CreateDbAsync();
		try
		{
			DateTime past = DateTime.UtcNow.AddMinutes(-5);
			await using (AuditDbContext seed = factory.CreateDbContext())
			{
				seed.ActiveBlocks.Add(new ActiveBlock
				{
					Ip = "203.0.113.10",
					Provider = FirewallProviderKind.Windows,
					CreatedUtc = past.AddMinutes(-10),
					ExpiresUtc = past,
					Reason = "expired",
					Status = ActiveBlockStatus.Active,
				});
				await seed.SaveChangesAsync();
			}

			MockFirewallProvider provider = new();
			provider.UnblockResponses.Enqueue(new FirewallActionResult
			{
				Status = FirewallActionStatus.Unavailable,
				ProviderId = "Windows",
				Message = "provider unavailable",
			});

			FirewallExpirationWorker worker = new(
				factory,
				Options(new RdpAuditOptions()),
				new IFirewallProvider[] { provider },
				NullLogger<FirewallExpirationWorker>.Instance);

			await worker.TickAsync(CancellationToken.None);

			await using AuditDbContext db = factory.CreateDbContext();
			ActiveBlock row = Assert.Single(await db.ActiveBlocks.ToListAsync());
			Assert.Equal(ActiveBlockStatus.Failed, row.Status);
			Assert.Contains("provider unavailable", row.LastError, StringComparison.Ordinal);
		}
		finally
		{
			await conn.DisposeAsync();
		}
	}

	[Fact]
	public async Task ExpirationWorker_NoExpiredRows_ReturnsFallbackDelay()
	{
		(IDbContextFactory<AuditDbContext> factory, SqliteConnection conn) = await CreateDbAsync();
		try
		{
			MockFirewallProvider provider = new();
			FirewallExpirationWorker worker = new(
				factory,
				Options(new RdpAuditOptions()),
				new IFirewallProvider[] { provider },
				NullLogger<FirewallExpirationWorker>.Instance);

			TimeSpan delay = await worker.TickAsync(CancellationToken.None);
			Assert.True(delay >= TimeSpan.FromSeconds(1));
			Assert.Empty(provider.UnblockCalls);
		}
		finally
		{
			await conn.DisposeAsync();
		}
	}

	private static async Task InvokeProcessBatchAsync(FirewallAutoBlockWorker worker)
	{
		// Use reflection-free path: cancel before ExecuteAsync would loop forever by invoking
		// the internal ProcessBatchAsync method via the InternalsVisibleTo channel.
		var method = typeof(FirewallAutoBlockWorker)
			.GetMethod("ProcessBatchAsync", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance);
		Assert.NotNull(method);
		Task task = (Task)method!.Invoke(worker, new object[] { CancellationToken.None })!;
		await task;
	}
}
