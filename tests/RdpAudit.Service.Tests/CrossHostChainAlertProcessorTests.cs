/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// File   : CrossHostChainAlertProcessorTests.cs
// Project: RdpAudit.Service.Tests (RdpAudit.Service.Tests)
// Purpose: Verification for the P4-18 alert phase: the processor raises exactly one
//          CROSS_HOST_CHAIN alert per newly detected chain and the chain row's AlertId link is
//          the durable dedup gate, so repeated AlertWorker passes never duplicate alerts.
//          Acknowledged chains are skipped entirely. Uses the real processor against an
//          in-memory SQLite AuditDbContext.
// Depends: CrossHostChainAlertProcessor, CrossHostChain, CrossHostLink, Microsoft.Data.Sqlite
// Extends: Add throttle-budget coverage when the alert layer gains per-rule budgets.

using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using RdpAudit.Core.CrossHost;
using RdpAudit.Core.Data;
using RdpAudit.Core.Models;
using RdpAudit.Service.Workers;
using Xunit;

namespace RdpAudit.Service.Tests;

public sealed class CrossHostChainAlertProcessorTests
{
	private static async Task<(AuditDbContext Db, SqliteConnection Conn)> CreateDbAsync()
	{
		SqliteConnection conn = new("DataSource=:memory:");
		await conn.OpenAsync();
		DbContextOptions<AuditDbContext> options = new DbContextOptionsBuilder<AuditDbContext>()
			.UseSqlite(conn)
			.Options;

		AuditDbContext db = new(options);
		await db.Database.EnsureCreatedAsync();
		return (db, conn);
	}

	private static async Task<long> SeedChainAsync(
		AuditDbContext db,
		string chainKey,
		string ruleId = "RDP_LATERAL_MOVEMENT",
		bool acknowledged = false)
	{
		DateTime now = DateTime.UtcNow;
		CrossHostChain chain = new()
		{
			ChainKey = chainKey,
			RuleId = ruleId,
			NormalizedUserName = "attacker",
			FirstSeenUtc = now.AddMinutes(-20),
			LastSeenUtc = now,
			Score = 85,
			FailedAttemptCount = 3,
			DetectedUtc = now,
			IsAcknowledged = acknowledged,
		};
		chain.Links.Add(new CrossHostLink { Ordinal = 0, HostName = "SRV-A", Kind = CrossHostFactKind.FailedLogon, EventId = 4625, TimeUtc = now.AddMinutes(-20) });
		chain.Links.Add(new CrossHostLink { Ordinal = 1, HostName = "SRV-B", Kind = CrossHostFactKind.SuccessfulLogon, EventId = 4624, TimeUtc = now.AddMinutes(-10) });
		chain.Links.Add(new CrossHostLink { Ordinal = 2, HostName = "SRV-C", Kind = CrossHostFactKind.PrivilegedLogon, EventId = 4672, TimeUtc = now });
		db.CrossHostChains.Add(chain);
		await db.SaveChangesAsync();
		return chain.Id;
	}

	private static async Task<int> RunPassAsync(AuditDbContext db)
	{
		int raised = await CrossHostChainAlertProcessor.ProcessAsync(db, NullLogger.Instance, CancellationToken.None);
		await db.SaveChangesAsync();
		return raised;
	}

	[Fact]
	public async Task TwoPasses_SingleChain_RaisesExactlyOneAlert_SecondPassRaisesZero()
	{
		(AuditDbContext db, SqliteConnection conn) = await CreateDbAsync();
		try
		{
			long chainId = await SeedChainAsync(db, "chain-key-1");

			int firstPass = await RunPassAsync(db);
			int secondPass = await RunPassAsync(db);

			Assert.Equal(1, firstPass);
			Assert.Equal(0, secondPass);

			List<Alert> alerts = await db.Alerts.ToListAsync();
			Alert alert = Assert.Single(alerts);
			Assert.Equal(CrossHostChainAlertFactory.RuleId, alert.RuleId);
			Assert.Equal(AlertSeverity.Critical, alert.Severity);
			Assert.Equal("attacker", alert.UserName);
			Assert.False(alert.Acknowledged);
			Assert.Equal(chainId, alert.TriggerEventId);

			CrossHostChain stored = await db.CrossHostChains.SingleAsync();
			Assert.Equal(alert.Id, stored.AlertId);
		}
		finally
		{
			await db.DisposeAsync();
			await conn.DisposeAsync();
		}
	}

	[Fact]
	public async Task MultipleChains_SinglePass_RaisesOneAlertPerChain()
	{
		(AuditDbContext db, SqliteConnection conn) = await CreateDbAsync();
		try
		{
			long firstChainId = await SeedChainAsync(db, "chain-key-1");
			long secondChainId = await SeedChainAsync(db, "chain-key-2");

			int raised = await RunPassAsync(db);

			Assert.Equal(2, raised);
			List<Alert> alerts = await db.Alerts.ToListAsync();
			Assert.Equal(2, alerts.Count);
			Assert.Equal(2, alerts.Select(a => a.Id).Distinct().Count());

			List<CrossHostChain> chains = await db.CrossHostChains.OrderBy(c => c.Id).ToListAsync();
			Assert.Equal(firstChainId, chains[0].Id);
			Assert.Equal(secondChainId, chains[1].Id);
			Assert.NotNull(chains[0].AlertId);
			Assert.NotNull(chains[1].AlertId);
			Assert.NotEqual(chains[0].AlertId, chains[1].AlertId);
		}
		finally
		{
			await db.DisposeAsync();
			await conn.DisposeAsync();
		}
	}

	[Fact]
	public async Task AcknowledgedChain_IsSkipped_NoAlertRaised()
	{
		(AuditDbContext db, SqliteConnection conn) = await CreateDbAsync();
		try
		{
			await SeedChainAsync(db, "chain-key-ack", acknowledged: true);

			int raised = await RunPassAsync(db);

			Assert.Equal(0, raised);
			Assert.Empty(await db.Alerts.ToListAsync());
			CrossHostChain stored = await db.CrossHostChains.SingleAsync();
			Assert.Null(stored.AlertId);
		}
		finally
		{
			await db.DisposeAsync();
			await conn.DisposeAsync();
		}
	}

	[Fact]
	public async Task AlertLinkedChain_ThenAcknowledged_StillNeverDuplicates()
	{
		(AuditDbContext db, SqliteConnection conn) = await CreateDbAsync();
		try
		{
			await SeedChainAsync(db, "chain-key-1");
			Assert.Equal(1, await RunPassAsync(db));

			// Operator acknowledges the chain AND its linked alert, then AlertWorker runs again.
			CrossHostChain chain = await db.CrossHostChains.SingleAsync();
			chain.IsAcknowledged = true;
			Alert alert = await db.Alerts.SingleAsync();
			alert.Acknowledged = true;
			await db.SaveChangesAsync();

			int repeatPass = await RunPassAsync(db);

			Assert.Equal(0, repeatPass);
			Assert.Single(await db.Alerts.ToListAsync());
		}
		finally
		{
			await db.DisposeAsync();
			await conn.DisposeAsync();
		}
	}
}
