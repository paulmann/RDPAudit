// File:    tests/RdpAudit.Service.Tests/AttackStatsIpNormalizationTests.cs
// Module:  RdpAudit.Service.Tests
// Purpose: v1.2.1 — pin the IP normalisation contract at the aggregation boundary. The real-host
//          bug report: a Security 4776 NTLM failure with attempted login "34asdf" surfaced in
//          Live Events as ".77.37.192.246" (note the leading dot) but Attack Statistics showed
//          the row under "(unresolved)". Cause: the punctuation-wrapped form failed
//          IPAddress.TryParse, so the AuthAttemptFact landed with a null IP and the aggregator
//          bucketed the failure under the unresolved sentinel.
//          The fix: every layer that writes / reads an IP runs the value through IpNormalizer
//          first, so ".77.37.192.246", " 77.37.192.246", and "::ffff:77.37.192.246" all collapse
//          to the same canonical aggregation key "77.37.192.246".
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using RdpAudit.Core.Data;
using RdpAudit.Core.Models;
using RdpAudit.Service.Workers;
using Xunit;

namespace RdpAudit.Service.Tests;

public class AttackStatsIpNormalizationTests
{
	// Anchor all seeded timestamps two days in the past so every fact stays inside the
	// AttackStatsRefreshWorker 30-day look-back window (DateTime.UtcNow - 30d) while remaining
	// strictly in the past. A fixed calendar date would silently expire 30 days after it was
	// written, which is exactly the regression this constant prevents. Captured once at class
	// load to guarantee a stable value across all reads within a single test run.
	private static readonly DateTime Now = DateTime.UtcNow.AddDays(-2).Date.AddHours(12);

	private static async Task<(IDbContextFactory<AuditDbContext>, SqliteConnection)> CreateDbAsync()
	{
		SqliteConnection conn = new("DataSource=:memory:");
		await conn.OpenAsync();
		DbContextOptions<AuditDbContext> options = new DbContextOptionsBuilder<AuditDbContext>()
			.UseSqlite(conn)
			.Options;
		await using (AuditDbContext db = new(options))
		{
			await db.Database.EnsureCreatedAsync();
		}

		return (new TestFactoryLocal(options), conn);
	}

	[Fact]
	public async Task FailedFact_4776_WithLeadingDotIp_AggregatesUnderCanonicalIp_NotUnresolved()
	{
		(IDbContextFactory<AuditDbContext> factory, SqliteConnection conn) = await CreateDbAsync();
		try
		{
			DateTime first = Now.AddMinutes(-5);
			DateTime last = Now;

			await using (AuditDbContext db = factory.CreateDbContext())
			{
				// Real-host evidence: a 4776 NTLM failure where the IP arrived punctuation-wrapped
				// (".77.37.192.246") and the attempted user is "34asdf" (nonexistent).
				db.AuthAttemptFacts.Add(new AuthAttemptFact
				{
					TimeUtc = first,
					SourceIp = ".77.37.192.246",
					TargetUser = "34asdf",
					NormalizedUserName = "34asdf",
					Outcome = AuthAttemptOutcome.Failed,
					EvidenceChannel = "Security",
					EvidenceEventId = 4776,
					EnrichmentSource = "LogonIdChain",
					EnrichmentConfidence = "Medium",
					IngestedUtc = Now,
				});
				db.AuthAttemptFacts.Add(new AuthAttemptFact
				{
					TimeUtc = last,
					SourceIp = " 77.37.192.246", // whitespace-prefixed variant
					TargetUser = "34asdf",
					NormalizedUserName = "34asdf",
					Outcome = AuthAttemptOutcome.Failed,
					EvidenceChannel = "Security",
					EvidenceEventId = 4776,
					EnrichmentSource = "LogonIdChain",
					EnrichmentConfidence = "Medium",
					IngestedUtc = Now,
				});

				await db.SaveChangesAsync();
			}

			AttackStatsRefreshWorker worker = new(factory, NullLogger<AttackStatsRefreshWorker>.Instance);
			await worker.RefreshOnceAsync(CancellationToken.None);

			await using AuditDbContext verify = factory.CreateDbContext();

			// The two facts MUST aggregate under the single canonical key, never the unresolved
			// sentinel — this is the entire point of the v1.2.1 fix.
			AttackStat? row = await verify.AttackStats.FirstOrDefaultAsync(s => s.Ip == "77.37.192.246");
			Assert.NotNull(row);
			Assert.Equal(2, row!.Failed);
			Assert.Equal(0, row.Successful);
			Assert.Equal(2, row.TotalAttempts);
			Assert.Equal(first, row.FirstSeenUtc);
			Assert.Equal(last, row.LastSeenUtc);
			Assert.Contains("34asdf", row.Top10AttemptedLogins ?? string.Empty, StringComparison.Ordinal);

			// And the unresolved sentinel must NOT receive these facts.
			AttackStat? sentinel = await verify.AttackStats.FirstOrDefaultAsync(
				s => s.Ip == AttackStatsAggregator.SentinelUnresolvedIp);
			Assert.Null(sentinel);
		}
		finally
		{
			await conn.DisposeAsync();
		}
	}

	[Fact]
	public async Task FailedFact_4625_WithDirectIp_AggregatesUnderDirectIp()
	{
		(IDbContextFactory<AuditDbContext> factory, SqliteConnection conn) = await CreateDbAsync();
		try
		{
			await using (AuditDbContext db = factory.CreateDbContext())
			{
				db.AuthAttemptFacts.Add(new AuthAttemptFact
				{
					TimeUtc = Now,
					SourceIp = "77.37.192.246",
					TargetUser = "md",
					NormalizedUserName = "md",
					Outcome = AuthAttemptOutcome.Failed,
					EvidenceChannel = "Security",
					EvidenceEventId = 4625,
					EnrichmentSource = "DirectXml",
					EnrichmentConfidence = "High",
					IngestedUtc = Now,
				});

				await db.SaveChangesAsync();
			}

			AttackStatsRefreshWorker worker = new(factory, NullLogger<AttackStatsRefreshWorker>.Instance);
			await worker.RefreshOnceAsync(CancellationToken.None);

			await using AuditDbContext verify = factory.CreateDbContext();
			AttackStat row = await verify.AttackStats.FirstAsync(s => s.Ip == "77.37.192.246");
			Assert.Equal(1, row.Failed);
		}
		finally
		{
			await conn.DisposeAsync();
		}
	}

	[Fact]
	public async Task FailedFact_Ipv4MappedIpv6_CollapsesToDottedQuadKey()
	{
		(IDbContextFactory<AuditDbContext> factory, SqliteConnection conn) = await CreateDbAsync();
		try
		{
			await using (AuditDbContext db = factory.CreateDbContext())
			{
				db.AuthAttemptFacts.Add(new AuthAttemptFact
				{
					TimeUtc = Now,
					SourceIp = "::ffff:77.37.192.246",
					TargetUser = "34asdf",
					NormalizedUserName = "34asdf",
					Outcome = AuthAttemptOutcome.Failed,
					EvidenceChannel = "Security",
					EvidenceEventId = 4625,
					EnrichmentSource = "DirectXml",
					EnrichmentConfidence = "High",
					IngestedUtc = Now,
				});

				await db.SaveChangesAsync();
			}

			AttackStatsRefreshWorker worker = new(factory, NullLogger<AttackStatsRefreshWorker>.Instance);
			await worker.RefreshOnceAsync(CancellationToken.None);

			await using AuditDbContext verify = factory.CreateDbContext();
			AttackStat? canonical = await verify.AttackStats.FirstOrDefaultAsync(s => s.Ip == "77.37.192.246");
			Assert.NotNull(canonical);
			Assert.Equal(1, canonical!.Failed);
		}
		finally
		{
			await conn.DisposeAsync();
		}
	}

	[Fact]
	public async Task FailedFact_WithUnparseableIp_StillAggregatesUnderUnresolvedSentinel()
	{
		// Negative path — an IP that even after sanitisation cannot parse must NOT silently
		// collapse to a real address; it should fall back to the unresolved-IP sentinel so the
		// brute-force pressure is still surfaced to operators.
		(IDbContextFactory<AuditDbContext> factory, SqliteConnection conn) = await CreateDbAsync();
		try
		{
			await using (AuditDbContext db = factory.CreateDbContext())
			{
				db.AuthAttemptFacts.Add(new AuthAttemptFact
				{
					TimeUtc = Now,
					SourceIp = "not-an-ip",
					TargetUser = "34asdf",
					NormalizedUserName = "34asdf",
					Outcome = AuthAttemptOutcome.Failed,
					EvidenceChannel = "Security",
					EvidenceEventId = 4625,
					EnrichmentSource = "DirectXml",
					EnrichmentConfidence = "None",
					IngestedUtc = Now,
				});

				await db.SaveChangesAsync();
			}

			AttackStatsRefreshWorker worker = new(factory, NullLogger<AttackStatsRefreshWorker>.Instance);
			await worker.RefreshOnceAsync(CancellationToken.None);

			await using AuditDbContext verify = factory.CreateDbContext();
			AttackStat sentinel = await verify.AttackStats.FirstAsync(
				s => s.Ip == AttackStatsAggregator.SentinelUnresolvedIp);
			Assert.Equal(1, sentinel.Failed);
		}
		finally
		{
			await conn.DisposeAsync();
		}
	}

	private sealed class TestFactoryLocal : IDbContextFactory<AuditDbContext>
	{
		private readonly DbContextOptions<AuditDbContext> _options;
		public TestFactoryLocal(DbContextOptions<AuditDbContext> options) { _options = options; }
		public AuditDbContext CreateDbContext() => new(_options);
	}
}
