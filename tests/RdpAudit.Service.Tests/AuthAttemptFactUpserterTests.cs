// File:    tests/RdpAudit.Service.Tests/AuthAttemptFactUpserterTests.cs
// Module:  RdpAudit.Service.Tests
// Purpose: v3 invariant coverage (Detect_Attack_Strategy_v3.md §6.3, §8.1, §17). Pins the
//          atomic-fact contract: every authoritative outcome event creates exactly one
//          AuthAttemptFact, RdpCoreTS / TCP / WTS never do, NLA-stripped 4625 recovers its IP
//          from RdpCoreTS 131/140 (−2s … +15s) at High confidence, and a 4625 with LogonType 3
//          is still classified as Failed.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using RdpAudit.Core.Data;
using RdpAudit.Core.Models;
using RdpAudit.Service.Processors;
using Xunit;

namespace RdpAudit.Service.Tests;

public class AuthAttemptFactUpserterTests
{
	private const string RdpCoreTs = "Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational";
	private const string TsRcm = "Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational";
	private const string TsLsm = "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational";

	private static DateTime Now => new(2026, 5, 26, 12, 0, 0, DateTimeKind.Utc);

	private static async Task<(IDbContextFactory<AuditDbContext> factory, SqliteConnection conn)> CreateDbAsync()
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

		return (new TestDbContextFactoryLocal(options), conn);
	}

	[Fact]
	public async Task FailedLogon_LogonType3_WithIp_CreatesFailedFact()
	{
		(IDbContextFactory<AuditDbContext> factory, SqliteConnection conn) = await CreateDbAsync();
		try
		{
			RdpTransportIpCache cache = new();
			AuthAttemptFactUpserter upserter = new(cache);

			RawEvent failed = new()
			{
				EventId = 4625,
				Channel = "Security",
				TimeUtc = Now,
				SourceIp = "203.0.113.10",
				UserName = "md",
				LogonType = 3, // NLA path commonly produces LT3 — v3 §1.2.
				Details = "{\"SubStatus\":\"0xC000006A\"}",
			};

			await using AuditDbContext db = factory.CreateDbContext();
			db.RawEvents.Add(failed);
			await db.SaveChangesAsync();

			AuthAttemptFactBatchResult result = await upserter.ApplyAsync(
				db, new[] { failed }, CancellationToken.None);
			await db.SaveChangesAsync();

			Assert.Equal(1, result.FailedCreated);
			Assert.Equal(0, result.SucceededCreated);
			AuthAttemptFact fact = Assert.Single(db.AuthAttemptFacts);
			Assert.Equal(AuthAttemptOutcome.Failed, fact.Outcome);
			Assert.Equal("203.0.113.10", fact.SourceIp);
			Assert.Equal("md", fact.TargetUser);
			Assert.Equal(3, fact.LogonType);
			Assert.Equal("0xC000006A", fact.SubStatus);
			Assert.Equal("Bad Password", fact.SubStatusMeaning);
			Assert.False(fact.IpFromCorrelation);
			Assert.Equal("High", fact.EnrichmentConfidence);
		}
		finally
		{
			await conn.DisposeAsync();
		}
	}

	[Fact]
	public async Task FailedLogon_LogonType3_NoIp_RecoversFromRdpCoreTs131()
	{
		(IDbContextFactory<AuditDbContext> factory, SqliteConnection conn) = await CreateDbAsync();
		try
		{
			RdpTransportIpCache cache = new();
			AuthAttemptFactUpserter upserter = new(cache);

			// RdpCoreTS 131 arrives 1 second before the stripped 4625.
			RawEvent rdpCore = new()
			{
				EventId = 131,
				Channel = RdpCoreTs,
				TimeUtc = Now.AddSeconds(-1),
				SourceIp = "198.51.100.42",
			};

			RawEvent stripped4625 = new()
			{
				EventId = 4625,
				Channel = "Security",
				TimeUtc = Now,
				SourceIp = null, // NLA strip per v3 §1.2.
				SourceIpUnresolved = true,
				UserName = "md",
				LogonType = 3,
			};

			await using AuditDbContext db = factory.CreateDbContext();
			db.RawEvents.Add(rdpCore);
			db.RawEvents.Add(stripped4625);
			await db.SaveChangesAsync();

			AuthAttemptFactBatchResult result = await upserter.ApplyAsync(
				db, new[] { rdpCore, stripped4625 }, CancellationToken.None);
			await db.SaveChangesAsync();

			Assert.Equal(1, result.FailedCreated);
			AuthAttemptFact fact = Assert.Single(db.AuthAttemptFacts);
			Assert.Equal(AuthAttemptOutcome.Failed, fact.Outcome);
			Assert.Equal("198.51.100.42", fact.SourceIp);
			Assert.Equal("md", fact.TargetUser);
			Assert.True(fact.IpFromCorrelation);
			Assert.Equal("High", fact.EnrichmentConfidence);
			Assert.Equal("RdpCoreTs131", fact.EnrichmentSource);
			Assert.False(fact.NeedsCorrelation);
		}
		finally
		{
			await conn.DisposeAsync();
		}
	}

	[Fact]
	public async Task RdpCoreTs131_Alone_DoesNotCreateAnyFact()
	{
		(IDbContextFactory<AuditDbContext> factory, SqliteConnection conn) = await CreateDbAsync();
		try
		{
			AuthAttemptFactUpserter upserter = new(new RdpTransportIpCache());

			RawEvent rdpCore = new()
			{
				EventId = 131,
				Channel = RdpCoreTs,
				TimeUtc = Now,
				SourceIp = "203.0.113.50",
			};
			RawEvent rdpCore140 = new()
			{
				EventId = 140,
				Channel = RdpCoreTs,
				TimeUtc = Now,
				SourceIp = "203.0.113.51",
			};
			RawEvent tsRcm261 = new()
			{
				EventId = 261,
				Channel = TsRcm,
				TimeUtc = Now,
				SourceIp = "203.0.113.52",
			};
			RawEvent tsLsm21 = new()
			{
				EventId = 21,
				Channel = TsLsm,
				TimeUtc = Now,
				SourceIp = "203.0.113.53",
				UserName = "alice",
			};

			await using AuditDbContext db = factory.CreateDbContext();
			AuthAttemptFactBatchResult result = await upserter.ApplyAsync(
				db, new[] { rdpCore, rdpCore140, tsRcm261, tsLsm21 }, CancellationToken.None);
			await db.SaveChangesAsync();

			Assert.Equal(0, result.FailedCreated);
			Assert.Equal(0, result.SucceededCreated);
			Assert.Empty(db.AuthAttemptFacts);
		}
		finally
		{
			await conn.DisposeAsync();
		}
	}

	[Fact]
	public async Task FailedLogon_NoIp_NoTransportCandidate_PersistsWithNeedsCorrelation()
	{
		(IDbContextFactory<AuditDbContext> factory, SqliteConnection conn) = await CreateDbAsync();
		try
		{
			AuthAttemptFactUpserter upserter = new(new RdpTransportIpCache());

			RawEvent stripped4625 = new()
			{
				EventId = 4625,
				Channel = "Security",
				TimeUtc = Now,
				SourceIp = null,
				SourceIpUnresolved = true,
				UserName = "md",
				LogonType = 3,
			};

			await using AuditDbContext db = factory.CreateDbContext();
			AuthAttemptFactBatchResult result = await upserter.ApplyAsync(
				db, new[] { stripped4625 }, CancellationToken.None);
			await db.SaveChangesAsync();

			Assert.Equal(1, result.FailedCreated);
			AuthAttemptFact fact = Assert.Single(db.AuthAttemptFacts);
			Assert.Equal(AuthAttemptOutcome.Failed, fact.Outcome);
			Assert.Null(fact.SourceIp);
			Assert.True(fact.NeedsCorrelation);
		}
		finally
		{
			await conn.DisposeAsync();
		}
	}

	[Fact]
	public async Task SuccessfulLogon_4624_CreatesSucceededFact()
	{
		(IDbContextFactory<AuditDbContext> factory, SqliteConnection conn) = await CreateDbAsync();
		try
		{
			AuthAttemptFactUpserter upserter = new(new RdpTransportIpCache());

			RawEvent success = new()
			{
				EventId = 4624,
				Channel = "Security",
				TimeUtc = Now,
				SourceIp = "10.0.0.7",
				UserName = "alice",
				LogonType = 10,
				LogonId = "0x1A2B",
			};

			await using AuditDbContext db = factory.CreateDbContext();
			AuthAttemptFactBatchResult result = await upserter.ApplyAsync(
				db, new[] { success }, CancellationToken.None);
			await db.SaveChangesAsync();

			Assert.Equal(0, result.FailedCreated);
			Assert.Equal(1, result.SucceededCreated);
			AuthAttemptFact fact = Assert.Single(db.AuthAttemptFacts);
			Assert.Equal(AuthAttemptOutcome.Succeeded, fact.Outcome);
			Assert.Equal("10.0.0.7", fact.SourceIp);
			Assert.Equal(10, fact.LogonType);
			Assert.Equal("0x1A2B", fact.LogonId);
		}
		finally
		{
			await conn.DisposeAsync();
		}
	}

	[Fact]
	public void TransportIpCache_AmbiguousCandidatesDoNotInventASingleHigh()
	{
		// Two distinct candidate IPs inside the window → must drop to Medium confidence with
		// the ambiguous flag set (v3 §6.3 rule 5).
		RdpTransportIpCache cache = new();
		cache.Record("198.51.100.42", Now.AddSeconds(-1), 131);
		cache.Record("203.0.113.99", Now.AddSeconds(2), 131);

		TransportIpLookup lookup = cache.FindCandidate(Now);
		Assert.Equal(TransportIpConfidence.AmbiguousMediumConfidence, lookup.Confidence);
	}

	[Fact]
	public void TransportIpCache_OutOfWindow_ReturnsNone()
	{
		RdpTransportIpCache cache = new();
		cache.Record("198.51.100.42", Now.AddMinutes(-2), 131);

		TransportIpLookup lookup = cache.FindCandidate(Now);
		Assert.Equal(TransportIpConfidence.None, lookup.Confidence);
		Assert.Null(lookup.Ip);
	}

	private sealed class TestDbContextFactoryLocal : IDbContextFactory<AuditDbContext>
	{
		private readonly DbContextOptions<AuditDbContext> _options;

		public TestDbContextFactoryLocal(DbContextOptions<AuditDbContext> options)
		{
			_options = options;
		}

		public AuditDbContext CreateDbContext() => new(_options);
	}
}
