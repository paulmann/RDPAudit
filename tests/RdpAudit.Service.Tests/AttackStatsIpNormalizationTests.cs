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

	[Fact]
	public async Task Ntlm4776_WithoutAddress_IsSkipped_NotFiledAsUnresolved()
	{
		// Real-host shape: one failed RDP attempt writes 4625 (with the address) and 4776 (NTLM
		// validation, no address field at all). The 4776 must not become an "(unresolved)" event.
		(IDbContextFactory<AuditDbContext> factory, SqliteConnection conn) = await CreateDbAsync();
		try
		{
			await using (AuditDbContext db = factory.CreateDbContext())
			{
				db.AuthAttemptFacts.Add(new AuthAttemptFact
				{
					TimeUtc = Now,
					SourceIp = "77.37.192.246",
					TargetUser = "34asdf",
					NormalizedUserName = "34asdf",
					Outcome = AuthAttemptOutcome.Failed,
					EvidenceChannel = "Security",
					EvidenceEventId = 4625,
					EnrichmentSource = "DirectXml",
					EnrichmentConfidence = "High",
					IngestedUtc = Now,
				});
				db.AuthAttemptFacts.Add(new AuthAttemptFact
				{
					TimeUtc = Now,
					SourceIp = null,
					TargetUser = "34asdf",
					NormalizedUserName = "34asdf",
					Outcome = AuthAttemptOutcome.Failed,
					EvidenceChannel = "Security",
					EvidenceEventId = 4776,
					EnrichmentSource = "None",
					EnrichmentConfidence = "None",
					IngestedUtc = Now,
				});

				await db.SaveChangesAsync();
			}

			AttackStatsRefreshWorker worker = new(factory, NullLogger<AttackStatsRefreshWorker>.Instance);
			await worker.RefreshOnceAsync(CancellationToken.None);

			await using AuditDbContext verify = factory.CreateDbContext();
			AttackStat row = await verify.AttackStats.FirstAsync(s => s.Ip == "77.37.192.246");
			Assert.Equal(1, row.Failed);

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
	public async Task Ntlm4776_TwinOf4625_IsCountedOnce()
	{
		// Windows writes BOTH records for one failed attempt; counting both doubles Total/Failed.
		(IDbContextFactory<AuditDbContext> factory, SqliteConnection conn) = await CreateDbAsync();
		try
		{
			await using (AuditDbContext db = factory.CreateDbContext())
			{
				db.AuthAttemptFacts.Add(new AuthAttemptFact
				{
					TimeUtc = Now,
					SourceIp = "77.37.192.246",
					TargetUser = "34asdf",
					NormalizedUserName = "34asdf",
					Outcome = AuthAttemptOutcome.Failed,
					EvidenceChannel = "Security",
					EvidenceEventId = 4625,
					EnrichmentSource = "DirectXml",
					EnrichmentConfidence = "High",
					IngestedUtc = Now,
				});
				db.AuthAttemptFacts.Add(new AuthAttemptFact
				{
					TimeUtc = Now.AddSeconds(1),
					SourceIp = "77.37.192.246",
					TargetUser = "34asdf",
					NormalizedUserName = "34asdf",
					Outcome = AuthAttemptOutcome.Failed,
					EvidenceChannel = "Security",
					EvidenceEventId = 4776,
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
			Assert.Equal(1, row.TotalAttempts);
		}
		finally
		{
			await conn.DisposeAsync();
		}
	}

	[Fact]
	public async Task Ntlm4776_Without4625Twin_StillCountsAsItsOwnFailure()
	{
		// NTLM failures that never produced a 4625 (SMB / other NLA paths) stay visible: the
		// de-duplication must not swallow an independent signal.
		(IDbContextFactory<AuditDbContext> factory, SqliteConnection conn) = await CreateDbAsync();
		try
		{
			await using (AuditDbContext db = factory.CreateDbContext())
			{
				db.AuthAttemptFacts.Add(new AuthAttemptFact
				{
					TimeUtc = Now,
					SourceIp = "203.0.113.55",
					TargetUser = "administrator",
					NormalizedUserName = "administrator",
					Outcome = AuthAttemptOutcome.Failed,
					EvidenceChannel = "Security",
					EvidenceEventId = 4776,
					EnrichmentSource = "DirectXml",
					EnrichmentConfidence = "High",
					IngestedUtc = Now,
				});

				await db.SaveChangesAsync();
			}

			AttackStatsRefreshWorker worker = new(factory, NullLogger<AttackStatsRefreshWorker>.Instance);
			await worker.RefreshOnceAsync(CancellationToken.None);

			await using AuditDbContext verify = factory.CreateDbContext();
			AttackStat row = await verify.AttackStats.FirstAsync(s => s.Ip == "203.0.113.55");
			Assert.Equal(1, row.Failed);
		}
		finally
		{
			await conn.DisposeAsync();
		}
	}

	[Fact]
	public async Task NtlmAndExplicitCredentialSuccess_DoNotBecomeRdpSessionSuccess()
	{
		// Fleet finding (23.10.2026): an external address with 8 failed RDP attempts reported 2 870
		// "successful RDP logons" — Security 4776 (NTLM) and 4648 (explicit credentials) successes
		// were folded into a synthetic 4624 by the worker.
		(IDbContextFactory<AuditDbContext> factory, SqliteConnection conn) = await CreateDbAsync();
		try
		{
			await using (AuditDbContext db = factory.CreateDbContext())
			{
				db.AuthAttemptFacts.Add(new AuthAttemptFact
				{
					TimeUtc = Now,
					SourceIp = "91.245.149.108",
					TargetUser = "administrator",
					NormalizedUserName = "administrator",
					Outcome = AuthAttemptOutcome.Succeeded,
					EvidenceChannel = "Security",
					EvidenceEventId = 4776,
					EnrichmentSource = "DirectXml",
					EnrichmentConfidence = "High",
					IngestedUtc = Now,
				});
				db.AuthAttemptFacts.Add(new AuthAttemptFact
				{
					TimeUtc = Now.AddSeconds(5),
					SourceIp = "91.245.149.108",
					TargetUser = "administrator",
					NormalizedUserName = "administrator",
					Outcome = AuthAttemptOutcome.Succeeded,
					EvidenceChannel = "Security",
					EvidenceEventId = 4648,
					EnrichmentSource = "DirectXml",
					EnrichmentConfidence = "High",
					IngestedUtc = Now,
				});
				db.AuthAttemptFacts.Add(new AuthAttemptFact
				{
					TimeUtc = Now.AddSeconds(9),
					SourceIp = "91.245.149.108",
					TargetUser = "administrator",
					NormalizedUserName = "administrator",
					Outcome = AuthAttemptOutcome.Failed,
					EvidenceChannel = "Security",
					EvidenceEventId = 4625,
					LogonType = 10,
					EnrichmentSource = "DirectXml",
					EnrichmentConfidence = "High",
					IngestedUtc = Now,
				});

				await db.SaveChangesAsync();
			}

			AttackStatsRefreshWorker worker = new(factory, NullLogger<AttackStatsRefreshWorker>.Instance);
			await worker.RefreshOnceAsync(CancellationToken.None);

			await using AuditDbContext verify = factory.CreateDbContext();
			AttackStat row = await verify.AttackStats.FirstAsync(s => s.Ip == "91.245.149.108");
			Assert.Equal(1, row.Failed);
			Assert.Equal(0, row.Successful);
			Assert.Equal(1, row.TotalAttempts);
		}
		finally
		{
			await conn.DisposeAsync();
		}
	}

	[Fact]
	public async Task ConsoleLogon_IsNotCountedAsRdpSuccess()
	{
		// Interactive console (LogonType 2) is not an RDP session and must not appear as a success.
		(IDbContextFactory<AuditDbContext> factory, SqliteConnection conn) = await CreateDbAsync();
		try
		{
			await using (AuditDbContext db = factory.CreateDbContext())
			{
				db.AuthAttemptFacts.Add(new AuthAttemptFact
				{
					TimeUtc = Now,
					SourceIp = "203.0.113.77",
					TargetUser = "operator",
					NormalizedUserName = "operator",
					Outcome = AuthAttemptOutcome.Succeeded,
					EvidenceChannel = "Security",
					EvidenceEventId = 4624,
					LogonType = 2,
					EnrichmentSource = "DirectXml",
					EnrichmentConfidence = "High",
					IngestedUtc = Now,
				});

				await db.SaveChangesAsync();
			}

			AttackStatsRefreshWorker worker = new(factory, NullLogger<AttackStatsRefreshWorker>.Instance);
			await worker.RefreshOnceAsync(CancellationToken.None);

			await using AuditDbContext verify = factory.CreateDbContext();
			Assert.Null(await verify.AttackStats.FirstOrDefaultAsync(s => s.Ip == "203.0.113.77"));
		}
		finally
		{
			await conn.DisposeAsync();
		}
	}

	    [Fact]
    public async Task NetworkLogonFromBruteForceAddress_IsNotAnRdpSuccess()
    {
        // Real-host shape: a NAT address brute-forcing RDP also opens successful SMB / SSH / NLA
        // network logons (4624 LogonType 3). They must not be reported as RDP sessions.
        (IDbContextFactory<AuditDbContext> factory, SqliteConnection conn) = await CreateDbAsync();
        try
        {
            await using (AuditDbContext db = factory.CreateDbContext())
            {
                db.AuthAttemptFacts.Add(new AuthAttemptFact
                {
                    TimeUtc = Now,
                    SourceIp = "95.189.92.122",
                    TargetUser = "md",
                    NormalizedUserName = "md",
                    Outcome = AuthAttemptOutcome.Succeeded,
                    EvidenceChannel = "Security",
                    EvidenceEventId = 4624,
                    LogonType = 3,
                    EnrichmentSource = "DirectXml",
                    EnrichmentConfidence = "High",
                    IngestedUtc = Now,
                });
                db.AuthAttemptFacts.Add(new AuthAttemptFact
                {
                    TimeUtc = Now.AddSeconds(1),
                    SourceIp = "95.189.92.122",
                    TargetUser = "md",
                    NormalizedUserName = "md",
                    Outcome = AuthAttemptOutcome.Failed,
                    EvidenceChannel = "Security",
                    EvidenceEventId = 4625,
                    LogonType = 10,
                    EnrichmentSource = "DirectXml",
                    EnrichmentConfidence = "High",
                    IngestedUtc = Now,
                });

                await db.SaveChangesAsync();
            }

            AttackStatsRefreshWorker worker = new(factory, NullLogger<AttackStatsRefreshWorker>.Instance);
            await worker.RefreshOnceAsync(CancellationToken.None);

            await using AuditDbContext verify = factory.CreateDbContext();
            AttackStat row = await verify.AttackStats.FirstAsync(s => s.Ip == "95.189.92.122");
            Assert.Equal(0, row.Successful);
            Assert.Equal(1, row.Failed);
            Assert.Equal(2, row.TotalAttempts);
        }
        finally
        {
            await conn.DisposeAsync();
        }
    }
    [Fact]
    public async Task FullRebuild_RepairsRowWhosePhantomSuccessCameFromAnOlderClassifier()
    {
        // A row outside the 30-day refresh window keeps the counters of whatever classifier ran
        // back then. Measured on the fleet: 3 953 "successful RDP logons" for an address whose
        // facts contain no RemoteInteractive logon at all. A full rebuild must re-derive it.
        (IDbContextFactory<AuditDbContext> factory, SqliteConnection conn) = await CreateDbAsync();
        try
        {
            DateTime old = Now.AddDays(-120);

            await using (AuditDbContext db = factory.CreateDbContext())
            {
                // Evidence: one network logon (SMB / SSH / NLA stage) — never an RDP session.
                db.AuthAttemptFacts.Add(new AuthAttemptFact
                {
                    TimeUtc = old,
                    SourceIp = "46.138.11.138",
                    TargetUser = "administrator",
                    NormalizedUserName = "administrator",
                    Outcome = AuthAttemptOutcome.Succeeded,
                    EvidenceChannel = "Security",
                    EvidenceEventId = 4624,
                    LogonType = 3,
                    EnrichmentSource = "DirectXml",
                    EnrichmentConfidence = "High",
                    IngestedUtc = old,
                });

                // The stale row an older build left behind.
                db.AttackStats.Add(new AttackStat
                {
                    Ip = "46.138.11.138",
                    TotalAttempts = 3204,
                    Successful = 3201,
                    Failed = 3,
                    FirstSeenUtc = old,
                    LastSeenUtc = old,
                    DurationSeconds = 60,
                    Top10AttemptedLogins = "administrator",
                    LastLoginType = 3,
                    ThreatScore = 0,
                    IsBlocked = false,
                    LastUpdatedUtc = old,
                });

                await db.SaveChangesAsync();
            }

            AttackStatsRefreshWorker worker = new(factory, NullLogger<AttackStatsRefreshWorker>.Instance);
            await worker.RefreshOnceDetailedAsync(fullRebuild: true, CancellationToken.None);

            await using AuditDbContext verify = factory.CreateDbContext();
            AttackStat row = await verify.AttackStats.FirstAsync(s => s.Ip == "46.138.11.138");
            Assert.Equal(0, row.Successful);
            Assert.Equal(0, row.Failed);
            Assert.Equal(1, row.TotalAttempts);
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
