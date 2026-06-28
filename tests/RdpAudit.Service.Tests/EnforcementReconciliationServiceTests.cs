// File:    tests/RdpAudit.Service.Tests/EnforcementReconciliationServiceTests.cs
// Module:  RdpAudit.Service.Tests
// Purpose: Integration-style tests for EnforcementReconciliationService and the reconciliation
//          worker's row-health mapping, driven against an in-memory SQLite database with a mocked
//          firewall rule scanner and firewall provider. Covers: a verified block (scanner finds the
//          rule), an unenforced block (scanner finds nothing -> MissingRule), repair re-installing a
//          missing rule via the provider, emergency cleanup removing only RdpAudit rules and marking
//          rows Removed, and the worker demoting an Active row whose enforcement could not be verified.
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
using RdpAudit.Core.Ipc.Contracts;
using RdpAudit.Core.Models;
using RdpAudit.Service.Firewall;
using RdpAudit.Service.Services;
using RdpAudit.Service.Workers;
using Xunit;

namespace RdpAudit.Service.Tests;

public class EnforcementReconciliationServiceTests
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

	private sealed class StubScanner : IFirewallRuleScanner
	{
		private readonly FirewallScanResult _result;

		public StubScanner(FirewallScanResult result) => _result = result;

		public List<string> ScanCalls { get; } = new();

		public Task<FirewallScanResult> ScanRdpAuditBlockRulesAsync(string ruleNamePrefix, CancellationToken ct)
		{
			ScanCalls.Add(ruleNamePrefix);
			return Task.FromResult(_result);
		}
	}

	/// <summary>Scanner that returns a different result per call so a Repair can be exercised: the first
	/// (pre-check) scan finds no rule, so Repair proceeds to the provider; the second (post-repair) scan
	/// finds the freshly installed rule, so reconciliation verifies it. The last result is reused for any
	/// further calls.</summary>
	private sealed class SequencedScanner : IFirewallRuleScanner
	{
		private readonly Queue<FirewallScanResult> _results;
		private FirewallScanResult _last;

		public SequencedScanner(params FirewallScanResult[] results)
		{
			_results = new Queue<FirewallScanResult>(results);
			_last = results[^1];
		}

		public Task<FirewallScanResult> ScanRdpAuditBlockRulesAsync(string ruleNamePrefix, CancellationToken ct)
		{
			if (_results.Count > 0)
			{
				_last = _results.Dequeue();
			}

			return Task.FromResult(_last);
		}
	}

	private sealed class MockFirewallProvider : IFirewallProvider
	{
		public string ProviderId { get; init; } = FirewallProviderRouting.WindowsProviderId;

		public Queue<FirewallActionResult> BlockResponses { get; } = new();

		public List<FirewallBlockRequest> BlockCalls { get; } = new();

		public List<string> UnblockCalls { get; } = new();

		public FirewallProviderStatus StatusToReport { get; init; } = FirewallProviderStatus.Available;

		public Task<FirewallStatusReport> GetStatusAsync(CancellationToken ct) =>
			Task.FromResult(new FirewallStatusReport { Status = StatusToReport, ProviderId = ProviderId });

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
			return Task.FromResult(new FirewallActionResult
			{
				Status = FirewallActionStatus.Success,
				ProviderId = ProviderId,
				RuleId = "RdpAudit-Block-" + ip,
			});
		}

		public Task<IReadOnlyList<FirewallBlockEntry>> ListBlocksAsync(string ruleName, CancellationToken ct) =>
			Task.FromResult<IReadOnlyList<FirewallBlockEntry>>(Array.Empty<FirewallBlockEntry>());
	}

	private sealed class TestOptionsMonitor : IOptionsMonitor<RdpAuditOptions>
	{
		public TestOptionsMonitor(RdpAuditOptions value) => CurrentValue = value;

		public RdpAuditOptions CurrentValue { get; }

		public RdpAuditOptions Get(string? name) => CurrentValue;

		public IDisposable? OnChange(Action<RdpAuditOptions, string?> listener) => null;
	}

	private static RdpAuditOptions WindowsOptions() => new()
	{
		Firewall = new FirewallOptions
		{
			Provider = FirewallProviderKind.Windows,
			EnforcementBackend = FirewallEnforcementBackend.WindowsFirewall,
			BlockRuleName = "RdpAudit-Block",
			ReconciliationIntervalSeconds = 300,
		},
	};

	private static DiscoveredBlockRule BlockRule(string ip) => new(
		RuleName: "RdpAudit-Block-" + ip,
		Enabled: true,
		DirectionInbound: true,
		ActionBlock: true,
		Protocol: "TCP",
		LocalPorts: new[] { 3389 },
		RemoteIps: new[] { ip });

	private static async Task SeedBlockAsync(
		IDbContextFactory<AuditDbContext> factory, string ip, ActiveBlockStatus status)
	{
		await using AuditDbContext db = factory.CreateDbContext();
		db.ActiveBlocks.Add(new ActiveBlock
		{
			Ip = ip,
			Provider = FirewallProviderKind.Windows,
			RuleHandle = "RdpAudit-Block-" + ip,
			CreatedUtc = DateTime.UtcNow.AddMinutes(-5),
			ExpiresUtc = null,
			Reason = "test",
			Status = status,
		});
		await db.SaveChangesAsync();
	}

	private static EnforcementReconciliationService MakeService(
		IDbContextFactory<AuditDbContext> factory,
		IFirewallRuleScanner scanner,
		params IFirewallProvider[] providers) =>
		new(
			factory,
			new TestOptionsMonitor(WindowsOptions()),
			providers,
			scanner,
			NullLogger<EnforcementReconciliationService>.Instance,
			TimeProvider.System);

	[Fact]
	public async Task ReconcileAsync_RuleFound_ReportsVerified()
	{
		(IDbContextFactory<AuditDbContext> factory, SqliteConnection conn) = await CreateDbAsync();
		try
		{
			await SeedBlockAsync(factory, "203.0.113.10", ActiveBlockStatus.Active);
			StubScanner scanner = new(new FirewallScanResult(true, new[] { BlockRule("203.0.113.10") }, null));
			EnforcementReconciliationService svc = MakeService(factory, scanner, new MockFirewallProvider());

			ReconciliationReportDto report = await svc.ReconcileAsync(CancellationToken.None);

			ReconciledBlockDto block = Assert.Single(report.Blocks);
			Assert.Equal(EnforcementStatus.Active, block.Status);
			Assert.Equal(EnforcementConfidence.Verified, block.Confidence);
			Assert.Equal(1, report.VerifiedCount);
		}
		finally
		{
			await conn.DisposeAsync();
		}
	}

	[Fact]
	public async Task ReconcileAsync_NoRule_ReportsMissingRuleUnenforced()
	{
		(IDbContextFactory<AuditDbContext> factory, SqliteConnection conn) = await CreateDbAsync();
		try
		{
			await SeedBlockAsync(factory, "203.0.113.10", ActiveBlockStatus.Active);
			StubScanner scanner = new(new FirewallScanResult(true, Array.Empty<DiscoveredBlockRule>(), null));
			EnforcementReconciliationService svc = MakeService(factory, scanner, new MockFirewallProvider());

			ReconciliationReportDto report = await svc.ReconcileAsync(CancellationToken.None);

			ReconciledBlockDto block = Assert.Single(report.Blocks);
			Assert.Equal(EnforcementStatus.MissingRule, block.Status);
			Assert.Equal(1, report.UnenforcedCount);
		}
		finally
		{
			await conn.DisposeAsync();
		}
	}

	[Fact]
	public async Task RepairAsync_ReinstallsRuleViaProvider_AndVerifies()
	{
		(IDbContextFactory<AuditDbContext> factory, SqliteConnection conn) = await CreateDbAsync();
		try
		{
			await SeedBlockAsync(factory, "203.0.113.10", ActiveBlockStatus.Failed);
			// Pre-check scan finds no rule (so Repair proceeds to the provider); the post-repair scan
			// finds the freshly installed rule, so re-reconciliation verifies it.
			SequencedScanner scanner = new(
				new FirewallScanResult(true, Array.Empty<DiscoveredBlockRule>(), null),
				new FirewallScanResult(true, new[] { BlockRule("203.0.113.10") }, null));
			MockFirewallProvider provider = new();
			EnforcementReconciliationService svc = MakeService(factory, scanner, provider);

			long id;
			await using (AuditDbContext db = factory.CreateDbContext())
			{
				id = await db.ActiveBlocks.Select(b => b.Id).FirstAsync();
			}

			ReconciledBlockDto result = await svc.RepairAsync(id, CancellationToken.None);

			Assert.Single(provider.BlockCalls);
			Assert.Equal(EnforcementStatus.Active, result.Status);

			await using AuditDbContext verify = factory.CreateDbContext();
			ActiveBlock row = await verify.ActiveBlocks.FirstAsync(b => b.Id == id);
			Assert.Equal(ActiveBlockStatus.Active, row.Status);
		}
		finally
		{
			await conn.DisposeAsync();
		}
	}

	[Fact]
	public async Task RepairBlocklistAsync_CreatesActiveBlock_InstallsRule_AndVerifies()
	{
		(IDbContextFactory<AuditDbContext> factory, SqliteConnection conn) = await CreateDbAsync();
		try
		{
			// A BlockList row exists (intent) but no ActiveBlock yet — the Active Blocks tab is empty.
			long blocklistId;
			await using (AuditDbContext db = factory.CreateDbContext())
			{
				BlocklistEntry entry = new()
				{
					Ip = "203.0.113.10",
					Reason = "manual",
					AddedUtc = DateTime.UtcNow,
					Source = BlocklistSource.Manual,
					IsEnabled = true,
				};
				db.BlocklistEntries.Add(entry);
				await db.SaveChangesAsync();
				blocklistId = entry.Id;
			}

			// Pre-check scan finds no rule (Repair proceeds to install); post-repair scan finds it, so
			// reconciliation verifies it.
			SequencedScanner scanner = new(
				new FirewallScanResult(true, Array.Empty<DiscoveredBlockRule>(), null),
				new FirewallScanResult(true, new[] { BlockRule("203.0.113.10") }, null));
			MockFirewallProvider provider = new();
			EnforcementReconciliationService svc = MakeService(factory, scanner, provider);

			ReconciledBlockDto result = await svc.RepairBlocklistAsync(blocklistId, CancellationToken.None);

			Assert.Single(provider.BlockCalls);
			Assert.Equal(EnforcementStatus.Active, result.Status);
			Assert.Equal(EnforcementConfidence.Verified, result.Confidence);

			await using AuditDbContext verify = factory.CreateDbContext();
			ActiveBlock row = await verify.ActiveBlocks.SingleAsync(b => b.Ip == "203.0.113.10");
			Assert.Equal(ActiveBlockStatus.Active, row.Status);
		}
		finally
		{
			await conn.DisposeAsync();
		}
	}

	[Fact]
	public async Task RepairBlocklistAsync_MissingRow_ReturnsFailedWithDetail()
	{
		(IDbContextFactory<AuditDbContext> factory, SqliteConnection conn) = await CreateDbAsync();
		try
		{
			StubScanner scanner = new(new FirewallScanResult(true, Array.Empty<DiscoveredBlockRule>(), null));
			EnforcementReconciliationService svc = MakeService(factory, scanner, new MockFirewallProvider());

			ReconciledBlockDto result = await svc.RepairBlocklistAsync(999, CancellationToken.None);

			Assert.Equal(EnforcementStatus.Failed, result.Status);
			Assert.Contains("not found", result.Detail ?? string.Empty, StringComparison.OrdinalIgnoreCase);
		}
		finally
		{
			await conn.DisposeAsync();
		}
	}

	[Fact]
	public async Task RepairAllEnabledBlocklistAsync_VerifiesEnabledRows_AndReportsCounts()
	{
		(IDbContextFactory<AuditDbContext> factory, SqliteConnection conn) = await CreateDbAsync();
		try
		{
			await using (AuditDbContext db = factory.CreateDbContext())
			{
				db.BlocklistEntries.Add(new BlocklistEntry
				{
					Ip = "203.0.113.10",
					Reason = "manual",
					AddedUtc = DateTime.UtcNow,
					Source = BlocklistSource.Manual,
					IsEnabled = true,
				});
				// Disabled rows must be skipped.
				db.BlocklistEntries.Add(new BlocklistEntry
				{
					Ip = "203.0.113.20",
					Reason = "manual-disabled",
					AddedUtc = DateTime.UtcNow,
					Source = BlocklistSource.Manual,
					IsEnabled = false,
				});
				await db.SaveChangesAsync();
			}

			// Pre-check scan finds no rule (Repair installs it); post-repair scan finds it and verifies.
			SequencedScanner scanner = new(
				new FirewallScanResult(true, Array.Empty<DiscoveredBlockRule>(), null),
				new FirewallScanResult(true, new[] { BlockRule("203.0.113.10") }, null));
			EnforcementReconciliationService svc = MakeService(factory, scanner, new MockFirewallProvider());

			ReconciliationReportDto report = await svc.RepairAllEnabledBlocklistAsync(CancellationToken.None);

			Assert.Single(report.Blocks);
			Assert.Equal(1, report.VerifiedCount);
			Assert.Equal(0, report.UnenforcedCount);
		}
		finally
		{
			await conn.DisposeAsync();
		}
	}

	[Fact]
	public async Task RemoveAllEnforcementAsync_RemovesRules_AndMarksRowsRemoved()
	{
		(IDbContextFactory<AuditDbContext> factory, SqliteConnection conn) = await CreateDbAsync();
		try
		{
			await SeedBlockAsync(factory, "203.0.113.10", ActiveBlockStatus.Active);
			await SeedBlockAsync(factory, "203.0.113.11", ActiveBlockStatus.Active);
			StubScanner scanner = new(new FirewallScanResult(
				true,
				new[] { BlockRule("203.0.113.10"), BlockRule("203.0.113.11") },
				null));
			MockFirewallProvider provider = new();
			EnforcementReconciliationService svc = MakeService(factory, scanner, provider);

			EnforcementCleanupResultDto result = await svc.RemoveAllEnforcementAsync(CancellationToken.None);

			Assert.Equal(2, result.FirewallRulesRemoved);
			Assert.Equal(2, result.ActiveBlockRowsMarkedRemoved);
			Assert.Equal(0, result.Failures);
			Assert.Equal(IpcResultStatus.Success, result.Status);
			Assert.Equal(2, provider.UnblockCalls.Count);

			await using AuditDbContext verify = factory.CreateDbContext();
			Assert.Equal(0, await verify.ActiveBlocks.CountAsync(b => b.Status == ActiveBlockStatus.Active));
		}
		finally
		{
			await conn.DisposeAsync();
		}
	}

	[Fact]
	public async Task RemoveAllEnforcementAsync_Unscannable_RemovesNothing()
	{
		(IDbContextFactory<AuditDbContext> factory, SqliteConnection conn) = await CreateDbAsync();
		try
		{
			await SeedBlockAsync(factory, "203.0.113.10", ActiveBlockStatus.Active);
			StubScanner scanner = new(new FirewallScanResult(false, Array.Empty<DiscoveredBlockRule>(), "not scannable"));
			MockFirewallProvider provider = new();
			EnforcementReconciliationService svc = MakeService(factory, scanner, provider);

			EnforcementCleanupResultDto result = await svc.RemoveAllEnforcementAsync(CancellationToken.None);

			Assert.Equal(0, result.FirewallRulesRemoved);
			Assert.Equal(0, result.ActiveBlockRowsMarkedRemoved);
			Assert.Empty(provider.UnblockCalls);

			await using AuditDbContext verify = factory.CreateDbContext();
			Assert.Equal(1, await verify.ActiveBlocks.CountAsync(b => b.Status == ActiveBlockStatus.Active));
		}
		finally
		{
			await conn.DisposeAsync();
		}
	}

	[Fact]
	public async Task RepairAsync_AlreadyVerified_IsNoOp_AndDoesNotCallProvider()
	{
		(IDbContextFactory<AuditDbContext> factory, SqliteConnection conn) = await CreateDbAsync();
		try
		{
			await SeedBlockAsync(factory, "203.0.113.10", ActiveBlockStatus.Active);
			// Scanner already finds the rule -> the row is Verified, so Repair must be a no-op.
			StubScanner scanner = new(new FirewallScanResult(true, new[] { BlockRule("203.0.113.10") }, null));
			MockFirewallProvider provider = new();
			EnforcementReconciliationService svc = MakeService(factory, scanner, provider);

			long id;
			await using (AuditDbContext db = factory.CreateDbContext())
			{
				id = await db.ActiveBlocks.Select(b => b.Id).FirstAsync();
			}

			ReconciledBlockDto result = await svc.RepairAsync(id, CancellationToken.None);

			Assert.Empty(provider.BlockCalls);
			Assert.Equal(EnforcementStatus.Active, result.Status);
			Assert.Equal("Already verified; no repair required.", result.Detail);
		}
		finally
		{
			await conn.DisposeAsync();
		}
	}

	[Fact]
	public async Task RemoveBlocklistEntryAsync_LastEnabledRow_SyncsActiveBlock_AndRemovesFirewall()
	{
		(IDbContextFactory<AuditDbContext> factory, SqliteConnection conn) = await CreateDbAsync();
		try
		{
			const string ip = "203.0.113.10";
			long blocklistId;
			await using (AuditDbContext db = factory.CreateDbContext())
			{
				BlocklistEntry entry = new()
				{
					Ip = ip,
					Reason = "manual",
					AddedUtc = DateTime.UtcNow,
					Source = BlocklistSource.Manual,
					IsEnabled = true,
				};
				db.BlocklistEntries.Add(entry);
				db.ActiveBlocks.Add(new ActiveBlock
				{
					Ip = ip,
					Provider = FirewallProviderKind.Windows,
					RuleHandle = "RdpAudit-Block-" + ip,
					CreatedUtc = DateTime.UtcNow.AddMinutes(-5),
					Reason = "manual",
					Status = ActiveBlockStatus.Active,
				});
				await db.SaveChangesAsync();
				blocklistId = entry.Id;
			}

			StubScanner scanner = new(new FirewallScanResult(true, new[] { BlockRule(ip) }, null));
			MockFirewallProvider provider = new();
			EnforcementReconciliationService svc = MakeService(factory, scanner, provider);

			BlocklistRemovalResultDto result = await svc.RemoveBlocklistEntryAsync(blocklistId, ip, CancellationToken.None);

			Assert.Equal(IpcResultStatus.Success, result.Status);
			Assert.Equal(1, result.RowsAffected);
			Assert.True(result.WasEnabled);
			Assert.True(result.ActiveBlockRemoved);
			Assert.True(result.FirewallRuleRemoved);
			Assert.Single(provider.UnblockCalls);

			await using AuditDbContext verify = factory.CreateDbContext();
			Assert.False(await verify.BlocklistEntries.Where(b => b.Id == blocklistId).Select(b => b.IsEnabled).SingleAsync());
			Assert.Equal(0, await verify.ActiveBlocks.CountAsync(b => b.Status == ActiveBlockStatus.Active));
		}
		finally
		{
			await conn.DisposeAsync();
		}
	}

	[Fact]
	public async Task RemoveBlocklistEntryAsync_OtherEnabledRowRemains_KeepsActiveBlockAndFirewall()
	{
		(IDbContextFactory<AuditDbContext> factory, SqliteConnection conn) = await CreateDbAsync();
		try
		{
			const string ip = "203.0.113.10";
			long targetId;
			await using (AuditDbContext db = factory.CreateDbContext())
			{
				BlocklistEntry first = new() { Ip = ip, Reason = "a", AddedUtc = DateTime.UtcNow, Source = BlocklistSource.Manual, IsEnabled = true };
				BlocklistEntry second = new() { Ip = ip, Reason = "b", AddedUtc = DateTime.UtcNow, Source = BlocklistSource.Manual, IsEnabled = true };
				db.BlocklistEntries.AddRange(first, second);
				db.ActiveBlocks.Add(new ActiveBlock
				{
					Ip = ip,
					Provider = FirewallProviderKind.Windows,
					RuleHandle = "RdpAudit-Block-" + ip,
					CreatedUtc = DateTime.UtcNow,
					Reason = "manual",
					Status = ActiveBlockStatus.Active,
				});
				await db.SaveChangesAsync();
				targetId = first.Id;
			}

			StubScanner scanner = new(new FirewallScanResult(true, new[] { BlockRule(ip) }, null));
			MockFirewallProvider provider = new();
			EnforcementReconciliationService svc = MakeService(factory, scanner, provider);

			BlocklistRemovalResultDto result = await svc.RemoveBlocklistEntryAsync(targetId, ip, CancellationToken.None);

			Assert.Equal(IpcResultStatus.Success, result.Status);
			Assert.Equal(1, result.RowsAffected);
			Assert.False(result.ActiveBlockRemoved);
			Assert.False(result.FirewallRuleRemoved);
			Assert.Empty(provider.UnblockCalls);

			await using AuditDbContext verify = factory.CreateDbContext();
			Assert.Equal(1, await verify.ActiveBlocks.CountAsync(b => b.Status == ActiveBlockStatus.Active));
		}
		finally
		{
			await conn.DisposeAsync();
		}
	}

	[Fact]
	public async Task RemoveBlocklistEntryAsync_AlreadyDisabledRow_DoesNotTouchFirewall()
	{
		(IDbContextFactory<AuditDbContext> factory, SqliteConnection conn) = await CreateDbAsync();
		try
		{
			const string ip = "203.0.113.10";
			long disabledId;
			await using (AuditDbContext db = factory.CreateDbContext())
			{
				BlocklistEntry entry = new() { Ip = ip, Reason = "x", AddedUtc = DateTime.UtcNow, Source = BlocklistSource.Manual, IsEnabled = false };
				db.BlocklistEntries.Add(entry);
				await db.SaveChangesAsync();
				disabledId = entry.Id;
			}

			StubScanner scanner = new(new FirewallScanResult(true, new[] { BlockRule(ip) }, null));
			MockFirewallProvider provider = new();
			EnforcementReconciliationService svc = MakeService(factory, scanner, provider);

			BlocklistRemovalResultDto result = await svc.RemoveBlocklistEntryAsync(disabledId, ip, CancellationToken.None);

			Assert.Equal(IpcResultStatus.Success, result.Status);
			Assert.Equal(0, result.RowsAffected);
			Assert.False(result.WasEnabled);
			Assert.False(result.FirewallRuleRemoved);
			Assert.Empty(provider.UnblockCalls);
			Assert.Contains("already disabled", result.Message, StringComparison.OrdinalIgnoreCase);
		}
		finally
		{
			await conn.DisposeAsync();
		}
	}

	[Fact]
	public async Task RemoveBlocklistEntryAsync_MissingId_ReturnsErrorWithoutFirewallChange()
	{
		(IDbContextFactory<AuditDbContext> factory, SqliteConnection conn) = await CreateDbAsync();
		try
		{
			StubScanner scanner = new(new FirewallScanResult(true, Array.Empty<DiscoveredBlockRule>(), null));
			MockFirewallProvider provider = new();
			EnforcementReconciliationService svc = MakeService(factory, scanner, provider);

			BlocklistRemovalResultDto result = await svc.RemoveBlocklistEntryAsync(999, null, CancellationToken.None);

			Assert.Equal(IpcResultStatus.Unavailable, result.Status);
			Assert.NotNull(result.Error);
			Assert.Empty(provider.UnblockCalls);
		}
		finally
		{
			await conn.DisposeAsync();
		}
	}

	[Fact]
	public async Task WorkerTick_DemotesActiveRowWithMissingEnforcement_ToFailed()
	{
		(IDbContextFactory<AuditDbContext> factory, SqliteConnection conn) = await CreateDbAsync();
		try
		{
			await SeedBlockAsync(factory, "203.0.113.10", ActiveBlockStatus.Active);
			// Scanner finds nothing -> reconciler reports MissingRule -> worker demotes the row.
			StubScanner scanner = new(new FirewallScanResult(true, Array.Empty<DiscoveredBlockRule>(), null));
			EnforcementReconciliationService svc = MakeService(factory, scanner, new MockFirewallProvider());

			EnforcementReconciliationWorker worker = new(
				svc,
				factory,
				new TestOptionsMonitor(WindowsOptions()),
				NullLogger<EnforcementReconciliationWorker>.Instance);

			await worker.TickAsync(CancellationToken.None);

			await using AuditDbContext verify = factory.CreateDbContext();
			ActiveBlock row = await verify.ActiveBlocks.FirstAsync();
			Assert.Equal(ActiveBlockStatus.Failed, row.Status);
			Assert.NotNull(row.LastError);
		}
		finally
		{
			await conn.DisposeAsync();
		}
	}

	[Fact]
	public async Task WorkerTick_PromotesFailedRowWithVerifiedEnforcement_ToActive()
	{
		(IDbContextFactory<AuditDbContext> factory, SqliteConnection conn) = await CreateDbAsync();
		try
		{
			await SeedBlockAsync(factory, "203.0.113.10", ActiveBlockStatus.Failed);
			StubScanner scanner = new(new FirewallScanResult(true, new[] { BlockRule("203.0.113.10") }, null));
			EnforcementReconciliationService svc = MakeService(factory, scanner, new MockFirewallProvider());

			EnforcementReconciliationWorker worker = new(
				svc,
				factory,
				new TestOptionsMonitor(WindowsOptions()),
				NullLogger<EnforcementReconciliationWorker>.Instance);

			await worker.TickAsync(CancellationToken.None);

			await using AuditDbContext verify = factory.CreateDbContext();
			ActiveBlock row = await verify.ActiveBlocks.FirstAsync();
			Assert.Equal(ActiveBlockStatus.Active, row.Status);
			Assert.Null(row.LastError);
		}
		finally
		{
			await conn.DisposeAsync();
		}
	}

	// --- v1.3.2 guarded cleanup operations (Req A / Req B) ---------------------------------------

	private static async Task SeedBlocklistAsync(
		IDbContextFactory<AuditDbContext> factory, string ip, bool enabled)
	{
		await using AuditDbContext db = factory.CreateDbContext();
		db.BlocklistEntries.Add(new BlocklistEntry
		{
			Ip = ip,
			Reason = "test",
			AddedUtc = DateTime.UtcNow,
			Source = BlocklistSource.Manual,
			IsEnabled = enabled,
		});
		await db.SaveChangesAsync();
	}

	[Fact]
	public async Task ClearAllBlocklistAsync_DisablesEnabledRows_RemovesRules_AndMarksActiveBlocks()
	{
		(IDbContextFactory<AuditDbContext> factory, SqliteConnection conn) = await CreateDbAsync();
		try
		{
			await SeedBlocklistAsync(factory, "203.0.113.10", enabled: true);
			await SeedBlocklistAsync(factory, "203.0.113.11", enabled: true);
			await SeedBlockAsync(factory, "203.0.113.10", ActiveBlockStatus.Active);
			await SeedBlockAsync(factory, "203.0.113.11", ActiveBlockStatus.Pending);
			StubScanner scanner = new(new FirewallScanResult(
				true,
				new[] { BlockRule("203.0.113.10"), BlockRule("203.0.113.11") },
				null));
			MockFirewallProvider provider = new();
			EnforcementReconciliationService svc = MakeService(factory, scanner, provider);

			BlocklistClearResultDto result = await svc.ClearAllBlocklistAsync(CancellationToken.None);

			Assert.Equal(2, result.BlocklistRowsAffected);
			Assert.Equal(2, result.IpsSynchronized);
			Assert.Equal(2, result.ActiveBlocksRemoved);
			Assert.Equal(2, result.FirewallRulesRemoved);
			Assert.Equal(0, result.Errors);
			Assert.Equal(IpcResultStatus.Success, result.Status);

			await using AuditDbContext verify = factory.CreateDbContext();
			Assert.Equal(0, await verify.BlocklistEntries.CountAsync(b => b.IsEnabled));
			Assert.Equal(0, await verify.ActiveBlocks.CountAsync(b =>
				b.Status == ActiveBlockStatus.Active || b.Status == ActiveBlockStatus.Pending));
		}
		finally
		{
			await conn.DisposeAsync();
		}
	}

	[Fact]
	public async Task ClearAllBlocklistAsync_DuplicateIps_CountsRowsButSynchronizesIpOnce()
	{
		(IDbContextFactory<AuditDbContext> factory, SqliteConnection conn) = await CreateDbAsync();
		try
		{
			// Two enabled rows for the same IP plus one already-disabled row for it.
			await SeedBlocklistAsync(factory, "203.0.113.10", enabled: true);
			await SeedBlocklistAsync(factory, "203.0.113.10", enabled: true);
			await SeedBlocklistAsync(factory, "203.0.113.10", enabled: false);
			await SeedBlockAsync(factory, "203.0.113.10", ActiveBlockStatus.Active);
			StubScanner scanner = new(new FirewallScanResult(
				true, new[] { BlockRule("203.0.113.10") }, null));
			MockFirewallProvider provider = new();
			EnforcementReconciliationService svc = MakeService(factory, scanner, provider);

			BlocklistClearResultDto result = await svc.ClearAllBlocklistAsync(CancellationToken.None);

			// Only the two enabled rows are affected; the IP is synchronized exactly once.
			Assert.Equal(2, result.BlocklistRowsAffected);
			Assert.Equal(1, result.IpsSynchronized);
			Assert.Equal(1, result.ActiveBlocksRemoved);
			Assert.Equal(1, result.FirewallRulesRemoved);
			Assert.Equal(IpcResultStatus.Success, result.Status);
		}
		finally
		{
			await conn.DisposeAsync();
		}
	}

	[Fact]
	public async Task ClearAllBlocklistAsync_AlreadyDisabledRow_IsLeftUntouched_AndNoFirewallTouch()
	{
		(IDbContextFactory<AuditDbContext> factory, SqliteConnection conn) = await CreateDbAsync();
		try
		{
			await SeedBlocklistAsync(factory, "203.0.113.10", enabled: false);
			StubScanner scanner = new(new FirewallScanResult(
				true, new[] { BlockRule("203.0.113.10") }, null));
			MockFirewallProvider provider = new();
			EnforcementReconciliationService svc = MakeService(factory, scanner, provider);

			BlocklistClearResultDto result = await svc.ClearAllBlocklistAsync(CancellationToken.None);

			Assert.Equal(0, result.BlocklistRowsAffected);
			Assert.Equal(0, result.IpsSynchronized);
			Assert.Equal(0, result.FirewallRulesRemoved);
			Assert.Empty(provider.UnblockCalls);
			Assert.Equal(IpcResultStatus.Success, result.Status);
		}
		finally
		{
			await conn.DisposeAsync();
		}
	}

	[Fact]
	public async Task ClearAllBlocklistAsync_OrphanRuleForSameIp_IsCleanedAsOrphan()
	{
		(IDbContextFactory<AuditDbContext> factory, SqliteConnection conn) = await CreateDbAsync();
		try
		{
			await SeedBlocklistAsync(factory, "203.0.113.10", enabled: true);
			// Two live rules for the same IP: the first is the backing rule, the second an orphan.
			StubScanner scanner = new(new FirewallScanResult(
				true,
				new[] { BlockRule("203.0.113.10"), BlockRule("203.0.113.10") },
				null));
			MockFirewallProvider provider = new();
			EnforcementReconciliationService svc = MakeService(factory, scanner, provider);

			BlocklistClearResultDto result = await svc.ClearAllBlocklistAsync(CancellationToken.None);

			Assert.Equal(1, result.FirewallRulesRemoved);
			Assert.Equal(1, result.OrphanRulesRemoved);
			Assert.Equal(0, result.Errors);
			Assert.Equal(IpcResultStatus.Success, result.Status);
		}
		finally
		{
			await conn.DisposeAsync();
		}
	}

	[Fact]
	public async Task ClearAllBlocklistAsync_AlreadyEmpty_IsSuccessfulNoOp()
	{
		(IDbContextFactory<AuditDbContext> factory, SqliteConnection conn) = await CreateDbAsync();
		try
		{
			StubScanner scanner = new(new FirewallScanResult(true, Array.Empty<DiscoveredBlockRule>(), null));
			MockFirewallProvider provider = new();
			EnforcementReconciliationService svc = MakeService(factory, scanner, provider);

			BlocklistClearResultDto result = await svc.ClearAllBlocklistAsync(CancellationToken.None);

			Assert.Equal(0, result.BlocklistRowsAffected);
			Assert.Equal(0, result.IpsSynchronized);
			Assert.Equal(0, result.FirewallRulesRemoved);
			Assert.Equal(0, result.Errors);
			Assert.Empty(provider.UnblockCalls);
			Assert.Equal(IpcResultStatus.Success, result.Status);
		}
		finally
		{
			await conn.DisposeAsync();
		}
	}

	[Fact]
	public async Task ClearAllRdpAuditFirewallAsync_RemovesAllRules_AndMarksActiveBlocks()
	{
		(IDbContextFactory<AuditDbContext> factory, SqliteConnection conn) = await CreateDbAsync();
		try
		{
			await SeedBlockAsync(factory, "203.0.113.10", ActiveBlockStatus.Active);
			await SeedBlockAsync(factory, "203.0.113.11", ActiveBlockStatus.Failed);
			StubScanner scanner = new(new FirewallScanResult(
				true,
				new[] { BlockRule("203.0.113.10"), BlockRule("203.0.113.11") },
				null));
			MockFirewallProvider provider = new();
			EnforcementReconciliationService svc = MakeService(factory, scanner, provider);

			FirewallClearResultDto result = await svc.ClearAllRdpAuditFirewallAsync(CancellationToken.None);

			Assert.Equal(2, result.FirewallRulesFound);
			Assert.Equal(2, result.FirewallRulesRemoved);
			Assert.Equal(2, result.ActiveBlocksUpdated);
			Assert.Equal(0, result.Errors);
			Assert.Equal(IpcResultStatus.Success, result.Status);

			await using AuditDbContext verify = factory.CreateDbContext();
			Assert.Equal(0, await verify.ActiveBlocks.CountAsync(b =>
				b.Status == ActiveBlockStatus.Active
				|| b.Status == ActiveBlockStatus.Pending
				|| b.Status == ActiveBlockStatus.Failed));
			// The BlockList table is never touched by the firewall cleanup.
			Assert.Equal(0, await verify.BlocklistEntries.CountAsync());
		}
		finally
		{
			await conn.DisposeAsync();
		}
	}

	[Fact]
	public async Task ClearAllRdpAuditFirewallAsync_Unscannable_RemovesNothing()
	{
		(IDbContextFactory<AuditDbContext> factory, SqliteConnection conn) = await CreateDbAsync();
		try
		{
			await SeedBlockAsync(factory, "203.0.113.10", ActiveBlockStatus.Active);
			StubScanner scanner = new(new FirewallScanResult(false, Array.Empty<DiscoveredBlockRule>(), "not scannable"));
			MockFirewallProvider provider = new();
			EnforcementReconciliationService svc = MakeService(factory, scanner, provider);

			FirewallClearResultDto result = await svc.ClearAllRdpAuditFirewallAsync(CancellationToken.None);

			Assert.Equal(0, result.FirewallRulesRemoved);
			Assert.Equal(0, result.ActiveBlocksUpdated);
			Assert.Empty(provider.UnblockCalls);
			Assert.Equal(IpcResultStatus.Unavailable, result.Status);

			await using AuditDbContext verify = factory.CreateDbContext();
			Assert.Equal(1, await verify.ActiveBlocks.CountAsync(b => b.Status == ActiveBlockStatus.Active));
		}
		finally
		{
			await conn.DisposeAsync();
		}
	}
}
