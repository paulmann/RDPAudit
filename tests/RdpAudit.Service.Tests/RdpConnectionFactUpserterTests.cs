// File:    tests/RdpAudit.Service.Tests/RdpConnectionFactUpserterTests.cs
// Module:  RdpAudit.Service.Tests
// Purpose: Verifies RdpConnectionFactUpserter merge semantics — creates facts from authoritative
//          events, updates lifecycle timestamps and counters, rejects hostnames, refuses to create
//          facts from derived-IP observations, increments FailedLogons / SuccessfulLogons by the
//          configured event-id taxonomy, and avoids producing duplicates for the same key per batch.
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

public class RdpConnectionFactUpserterTests
{
	private const string TsLsm = "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational";
	private const string TsRcm = "Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational";
	private const string Security = "Security";

	private static async Task<(DbContextOptions<AuditDbContext>, SqliteConnection)> CreateDbAsync()
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

		return (options, conn);
	}

	private static RawEvent Event(
		string channel,
		int eventId,
		DateTime t,
		string? ip,
		string? userName,
		string? logonId = null,
		int? wts = null,
		int? logonType = null,
		bool derived = false,
		string? domain = null,
		bool unresolved = false)
	{
		return new RawEvent
		{
			Channel = channel,
			EventId = eventId,
			TimeUtc = t,
			SourceIp = ip,
			SourceIpDerived = derived,
			SourceIpUnresolved = unresolved,
			UserName = userName,
			Domain = domain,
			LogonId = logonId,
			SessionId = wts,
			LogonType = logonType,
		};
	}

	[Fact]
	public async Task TsRcm1149_CreatesAuthenticatedFact_WithIp()
	{
		(DbContextOptions<AuditDbContext> options, SqliteConnection conn) = await CreateDbAsync();
		try
		{
			RdpConnectionFactUpserter upserter = new();
			DateTime t = new(2026, 5, 20, 10, 0, 0, DateTimeKind.Utc);
			RawEvent e = Event(TsRcm, 1149, t, "203.0.113.5", "alice", logonId: "0x42", wts: 3, domain: "CORP");

			await using AuditDbContext db = new(options);
			await upserter.ApplyAsync(db, new[] { e }, CancellationToken.None);
			await db.SaveChangesAsync();

			RdpConnectionFact fact = await db.RdpConnectionFacts.SingleAsync();
			Assert.Equal("203.0.113.5", fact.Ip);
			Assert.Equal("alice", fact.UserName);
			Assert.Equal("CORP", fact.Domain);
			Assert.Equal("0x42", fact.LogonId);
			Assert.Equal(3, fact.WtsSessionId);
			Assert.Equal(t, fact.FirstSeenUtc);
			Assert.Equal(t, fact.LastSeenUtc);
			Assert.Equal(t, fact.AuthenticatedUtc);
			Assert.NotNull(fact.ConnectedUtc);
			Assert.Contains("1149", fact.ObservedEventIds);
			Assert.True(fact.IsActive);
		}
		finally
		{
			await conn.DisposeAsync();
		}
	}

	[Fact]
	public async Task TsLsm21_ThenDisconnectReconnectLogoff_UpdatesLifecycleTimestamps()
	{
		(DbContextOptions<AuditDbContext> options, SqliteConnection conn) = await CreateDbAsync();
		try
		{
			RdpConnectionFactUpserter upserter = new();
			DateTime t0 = new(2026, 5, 20, 9, 0, 0, DateTimeKind.Utc);
			DateTime t1 = t0.AddMinutes(5);
			DateTime t2 = t0.AddMinutes(10);
			DateTime t3 = t0.AddMinutes(15);

			RawEvent connect = Event(TsLsm, 21, t0, "203.0.113.7", "bob", logonId: "0x99", wts: 5);
			RawEvent disconnect = Event(TsLsm, 24, t1, "203.0.113.7", "bob", logonId: "0x99", wts: 5);
			RawEvent reconnect = Event(TsLsm, 25, t2, "203.0.113.7", "bob", logonId: "0x99", wts: 5);
			RawEvent logoff = Event(TsLsm, 23, t3, "203.0.113.7", "bob", logonId: "0x99", wts: 5);

			await using AuditDbContext db = new(options);
			await upserter.ApplyAsync(db, new[] { connect, disconnect, reconnect, logoff }, CancellationToken.None);
			await db.SaveChangesAsync();

			RdpConnectionFact fact = await db.RdpConnectionFacts.SingleAsync();
			Assert.Equal(t0, fact.ConnectedUtc);
			Assert.Equal(t1, fact.DisconnectedUtc);
			Assert.Equal(t2, fact.ReconnectedUtc);
			Assert.Equal(t3, fact.LoggedOffUtc);
			Assert.Equal(t3, fact.LastSeenUtc);
			Assert.False(fact.IsActive); // logoff is the most recent marker
		}
		finally
		{
			await conn.DisposeAsync();
		}
	}

	[Fact]
	public async Task Security4625_IncrementsFailedLogons_ByIp_WithoutHostnamePollution()
	{
		(DbContextOptions<AuditDbContext> options, SqliteConnection conn) = await CreateDbAsync();
		try
		{
			RdpConnectionFactUpserter upserter = new();
			DateTime t0 = new(2026, 5, 20, 9, 0, 0, DateTimeKind.Utc);
			RawEvent fail1 = Event(Security, 4625, t0, "198.51.100.7", "carol", logonType: 10);
			RawEvent fail2 = Event(Security, 4625, t0.AddSeconds(2), "198.51.100.7", "carol", logonType: 10);
			// SourceIp is null here (we model PerEventIpResolver having rejected the hostname).
			RawEvent failNoIp = Event(Security, 4625, t0.AddSeconds(3), null, "carol", logonType: 10);

			await using AuditDbContext db = new(options);
			await upserter.ApplyAsync(db, new[] { fail1, fail2, failNoIp }, CancellationToken.None);
			await db.SaveChangesAsync();

			RdpConnectionFact fact = await db.RdpConnectionFacts.SingleAsync();
			Assert.Equal("198.51.100.7", fact.Ip);
			// All three share the same U:carol key and merge into a single fact; the no-IP event
			// still increments the counter once a row exists.
			Assert.Equal(3, fact.FailedLogons);
			Assert.Equal(0, fact.SuccessfulLogons);
		}
		finally
		{
			await conn.DisposeAsync();
		}
	}

	[Fact]
	public async Task Security4625_NoIpAndNoExistingRow_DoesNotCreateFact()
	{
		(DbContextOptions<AuditDbContext> options, SqliteConnection conn) = await CreateDbAsync();
		try
		{
			RdpConnectionFactUpserter upserter = new();
			DateTime t = new(2026, 5, 20, 9, 0, 0, DateTimeKind.Utc);
			RawEvent fail = Event(Security, 4625, t, null, "ghost", logonType: 10);

			await using AuditDbContext db = new(options);
			await upserter.ApplyAsync(db, new[] { fail }, CancellationToken.None);
			await db.SaveChangesAsync();

			Assert.Equal(0, await db.RdpConnectionFacts.CountAsync());
		}
		finally
		{
			await conn.DisposeAsync();
		}
	}

	[Fact]
	public async Task Security4624_OnlyRelevantLogonType_IncrementsSuccessfulLogons()
	{
		(DbContextOptions<AuditDbContext> options, SqliteConnection conn) = await CreateDbAsync();
		try
		{
			RdpConnectionFactUpserter upserter = new();
			DateTime t = new(2026, 5, 20, 9, 0, 0, DateTimeKind.Utc);

			RawEvent remoteInteractive = Event(Security, 4624, t, "203.0.113.50", "dave",
				logonId: "0xAA", wts: 8, logonType: 10);
			// LogonType 5 (Service) — must be classified as unrelated for the connection-fact view.
			RawEvent serviceLogon = Event(Security, 4624, t.AddSeconds(1), "203.0.113.50", "dave",
				logonId: "0xAA", wts: 8, logonType: 5);

			await using AuditDbContext db = new(options);
			await upserter.ApplyAsync(db, new[] { remoteInteractive, serviceLogon }, CancellationToken.None);
			await db.SaveChangesAsync();

			RdpConnectionFact fact = await db.RdpConnectionFacts.SingleAsync();
			Assert.Equal(1, fact.SuccessfulLogons);
			Assert.Equal(0, fact.FailedLogons);
		}
		finally
		{
			await conn.DisposeAsync();
		}
	}

	[Fact]
	public async Task DuplicateBatchEvents_UpdateOneFact_NoDuplicates()
	{
		(DbContextOptions<AuditDbContext> options, SqliteConnection conn) = await CreateDbAsync();
		try
		{
			RdpConnectionFactUpserter upserter = new();
			DateTime t = new(2026, 5, 20, 9, 0, 0, DateTimeKind.Utc);

			RawEvent e1 = Event(TsRcm, 1149, t, "203.0.113.80", "eve", logonId: "0xBB", wts: 12);
			RawEvent e2 = Event(TsLsm, 21, t.AddSeconds(5), "203.0.113.80", "eve", logonId: "0xBB", wts: 12);
			RawEvent e3 = Event(TsLsm, 21, t.AddSeconds(10), "203.0.113.80", "eve", logonId: "0xBB", wts: 12);

			await using AuditDbContext db = new(options);
			await upserter.ApplyAsync(db, new[] { e1, e2, e3 }, CancellationToken.None);
			await db.SaveChangesAsync();

			Assert.Equal(1, await db.RdpConnectionFacts.CountAsync());
			RdpConnectionFact fact = await db.RdpConnectionFacts.SingleAsync();
			Assert.Contains("1149", fact.ObservedEventIds);
			Assert.Contains("21", fact.ObservedEventIds);
			Assert.Equal(t.AddSeconds(10), fact.LastSeenUtc);
		}
		finally
		{
			await conn.DisposeAsync();
		}
	}

	[Fact]
	public async Task DerivedIp_DoesNotCreateNewFact_ButRefreshesExistingFact()
	{
		(DbContextOptions<AuditDbContext> options, SqliteConnection conn) = await CreateDbAsync();
		try
		{
			RdpConnectionFactUpserter upserter = new();
			DateTime t0 = new(2026, 5, 20, 9, 0, 0, DateTimeKind.Utc);

			// Direct seed.
			RawEvent direct = Event(TsRcm, 1149, t0, "203.0.113.90", "frank", logonId: "0xCC", wts: 14);

			// Subsequent event with derived IP and a later time should NOT create a separate row;
			// it should refresh LastSeenUtc on the existing row.
			RawEvent derivedLater = Event(Security, 4634, t0.AddMinutes(2), "203.0.113.90", "frank",
				logonId: "0xCC", wts: 14, derived: true);

			await using AuditDbContext db = new(options);
			await upserter.ApplyAsync(db, new[] { direct, derivedLater }, CancellationToken.None);
			await db.SaveChangesAsync();

			RdpConnectionFact fact = await db.RdpConnectionFacts.SingleAsync();
			Assert.Equal(t0.AddMinutes(2), fact.LastSeenUtc);
			Assert.NotNull(fact.LoggedOffUtc);
		}
		finally
		{
			await conn.DisposeAsync();
		}
	}

	[Fact]
	public async Task DerivedIp_AloneInBatch_DoesNotCreateFact()
	{
		(DbContextOptions<AuditDbContext> options, SqliteConnection conn) = await CreateDbAsync();
		try
		{
			RdpConnectionFactUpserter upserter = new();
			DateTime t = new(2026, 5, 20, 9, 0, 0, DateTimeKind.Utc);
			RawEvent derived = Event(Security, 4624, t, "203.0.113.99", "ghost",
				logonId: "0xDD", wts: 18, logonType: 10, derived: true);

			await using AuditDbContext db = new(options);
			await upserter.ApplyAsync(db, new[] { derived }, CancellationToken.None);
			await db.SaveChangesAsync();

			Assert.Equal(0, await db.RdpConnectionFacts.CountAsync());
		}
		finally
		{
			await conn.DisposeAsync();
		}
	}

	[Fact]
	public async Task HostnameLikeIp_IsRejected()
	{
		(DbContextOptions<AuditDbContext> options, SqliteConnection conn) = await CreateDbAsync();
		try
		{
			RdpConnectionFactUpserter upserter = new();
			DateTime t = DateTime.UtcNow;
			RawEvent e = Event(TsRcm, 1149, t, "WORKSTATION01", "alice", logonId: "0xEE", wts: 1);

			await using AuditDbContext db = new(options);
			await upserter.ApplyAsync(db, new[] { e }, CancellationToken.None);
			await db.SaveChangesAsync();

			Assert.Equal(0, await db.RdpConnectionFacts.CountAsync());
		}
		finally
		{
			await conn.DisposeAsync();
		}
	}

	[Fact]
	public async Task UnrelatedEvent_IsIgnored()
	{
		(DbContextOptions<AuditDbContext> options, SqliteConnection conn) = await CreateDbAsync();
		try
		{
			RdpConnectionFactUpserter upserter = new();
			DateTime t = DateTime.UtcNow;
			// Security 4768 (Kerberos TGT) is unrelated to the RDP connection-fact lens.
			RawEvent e = Event(Security, 4768, t, "203.0.113.200", "alice", logonId: "0xFF");

			await using AuditDbContext db = new(options);
			await upserter.ApplyAsync(db, new[] { e }, CancellationToken.None);
			await db.SaveChangesAsync();

			Assert.Equal(0, await db.RdpConnectionFacts.CountAsync());
		}
		finally
		{
			await conn.DisposeAsync();
		}
	}

	[Fact]
	public void AppendEventId_KeepsListBoundedAndDeduplicated()
	{
		string current = null!;
		for (int i = 1; i <= 40; i++)
		{
			current = RdpConnectionFactUpserter.AppendEventId(current, i);
		}

		Assert.True(current.Length <= RdpConnectionFactUpserter.ObservedEventIdsMaxLength);
		string[] parts = current.Split(',');
		Assert.True(parts.Length <= RdpConnectionFactUpserter.MaxObservedEventIds);
		Assert.Equal(parts.Distinct().Count(), parts.Length);
	}

	[Fact]
	public void AppendUserName_DeduplicatesCaseInsensitive()
	{
		string? current = null;
		current = RdpConnectionFactUpserter.AppendUserName(current, "alice");
		current = RdpConnectionFactUpserter.AppendUserName(current, "ALICE");
		current = RdpConnectionFactUpserter.AppendUserName(current, "bob");

		Assert.Equal("ALICE,bob", current);
	}

	// --- Stage 6 ----------------------------------------------------------------------------

	[Fact]
	public async Task Stage6_UnresolvedSentinel4625_CreatesFactUnderZeroIpKeyedByUser()
	{
		(DbContextOptions<AuditDbContext> options, SqliteConnection conn) = await CreateDbAsync();
		try
		{
			RdpConnectionFactUpserter upserter = new();
			DateTime t = new(2026, 5, 26, 10, 0, 0, DateTimeKind.Utc);
			RawEvent fail = Event(Security, 4625, t, ip: null, userName: "victim",
				logonType: 3, unresolved: true);

			await using AuditDbContext db = new(options);
			await upserter.ApplyAsync(db, new[] { fail }, CancellationToken.None);
			await db.SaveChangesAsync();

			RdpConnectionFact row = await db.RdpConnectionFacts.SingleAsync();
			Assert.Equal(RdpConnectionFactUpserter.UnresolvedIpSentinel, row.Ip);
			Assert.Equal("victim", row.UserName);
			Assert.Equal(1, row.FailedLogons);
			Assert.Equal(0, row.SuccessfulLogons);
			Assert.False(row.IsActive);
			Assert.Contains("victim", row.UserNamesAttempted!);
		}
		finally
		{
			await conn.DisposeAsync();
		}
	}

	[Fact]
	public async Task Stage6_UnresolvedSentinel_DoesNotOverwriteRealIpOnExistingFact()
	{
		(DbContextOptions<AuditDbContext> options, SqliteConnection conn) = await CreateDbAsync();
		try
		{
			RdpConnectionFactUpserter upserter = new();
			DateTime t = new(2026, 5, 26, 10, 0, 0, DateTimeKind.Utc);
			// Real-IP failure first creates the fact.
			RawEvent realFail = Event(Security, 4625, t, ip: "203.0.113.5", userName: "victim", logonType: 3);
			// Unresolved sentinel follows for the same username — must increment counter but
			// must NOT overwrite the real IP with "0.0.0.0".
			RawEvent unresolvedFail = Event(Security, 4625, t.AddSeconds(5), ip: null,
				userName: "victim", logonType: 3, unresolved: true);

			await using AuditDbContext db = new(options);
			await upserter.ApplyAsync(db, new[] { realFail, unresolvedFail }, CancellationToken.None);
			await db.SaveChangesAsync();

			RdpConnectionFact row = await db.RdpConnectionFacts.SingleAsync();
			Assert.Equal("203.0.113.5", row.Ip);
			Assert.Equal(2, row.FailedLogons);
		}
		finally
		{
			await conn.DisposeAsync();
		}
	}

	[Fact]
	public async Task Stage6_TsRcm261_ObservationOnly_NoCounters()
	{
		(DbContextOptions<AuditDbContext> options, SqliteConnection conn) = await CreateDbAsync();
		try
		{
			RdpConnectionFactUpserter upserter = new();
			DateTime t0 = new(2026, 5, 26, 10, 0, 0, DateTimeKind.Utc);
			// First create a fact via 1149.
			RawEvent auth = Event(TsRcm, 1149, t0, "203.0.113.5", "alice", logonId: "0x42", wts: 3);
			// Then a 261 pre-auth observation arrives — must update LastSeen and ObservedEventIds
			// only, no fail/success counter movement.
			RawEvent preauth = Event(TsRcm, 261, t0.AddSeconds(30), "203.0.113.5", "alice",
				logonId: "0x42", wts: 3);

			await using AuditDbContext db = new(options);
			await upserter.ApplyAsync(db, new[] { auth, preauth }, CancellationToken.None);
			await db.SaveChangesAsync();

			RdpConnectionFact row = await db.RdpConnectionFacts.SingleAsync();
			Assert.Contains("261", row.ObservedEventIds);
			Assert.Equal(t0.AddSeconds(30), row.LastSeenUtc);
			Assert.Equal(0, row.FailedLogons);
			// 1149 counted as success (Stage 6). The 261 must not add another.
			Assert.Equal(1, row.SuccessfulLogons);
		}
		finally
		{
			await conn.DisposeAsync();
		}
	}

	[Fact]
	public async Task Stage6_Security4648_ExplicitCreds_DoesNotCountAsSuccess()
	{
		(DbContextOptions<AuditDbContext> options, SqliteConnection conn) = await CreateDbAsync();
		try
		{
			RdpConnectionFactUpserter upserter = new();
			DateTime t0 = new(2026, 5, 26, 10, 0, 0, DateTimeKind.Utc);
			// Seed with a real connection.
			RawEvent auth = Event(TsRcm, 1149, t0, "203.0.113.5", "alice", logonId: "0x42", wts: 3);
			// Then a 4648 explicit-creds event for the same key.
			RawEvent explicitCreds = Event(Security, 4648, t0.AddSeconds(10), "203.0.113.5",
				"alice2", logonId: "0x42", wts: 3);

			await using AuditDbContext db = new(options);
			await upserter.ApplyAsync(db, new[] { auth, explicitCreds }, CancellationToken.None);
			await db.SaveChangesAsync();

			RdpConnectionFact row = await db.RdpConnectionFacts.SingleAsync();
			Assert.Equal(1, row.SuccessfulLogons); // unchanged: 4648 alone is not a success
			Assert.Contains("4648", row.ObservedEventIds);
			Assert.Contains("alice2", row.UserNamesAttempted!);
		}
		finally
		{
			await conn.DisposeAsync();
		}
	}

	[Fact]
	public async Task Stage6_TsRcm1149_IncrementsSuccessCounter()
	{
		(DbContextOptions<AuditDbContext> options, SqliteConnection conn) = await CreateDbAsync();
		try
		{
			RdpConnectionFactUpserter upserter = new();
			DateTime t0 = new(2026, 5, 26, 10, 0, 0, DateTimeKind.Utc);
			RawEvent auth1 = Event(TsRcm, 1149, t0, "203.0.113.5", "alice", logonId: "0x42", wts: 3);
			RawEvent auth2 = Event(TsRcm, 1149, t0.AddSeconds(60), "203.0.113.5", "alice",
				logonId: "0x42", wts: 3);

			await using AuditDbContext db = new(options);
			await upserter.ApplyAsync(db, new[] { auth1, auth2 }, CancellationToken.None);
			await db.SaveChangesAsync();

			RdpConnectionFact row = await db.RdpConnectionFacts.SingleAsync();
			Assert.Equal(2, row.SuccessfulLogons);
		}
		finally
		{
			await conn.DisposeAsync();
		}
	}

	[Fact]
	public async Task Stage6_TsLsm21_IncrementsSuccessCounter()
	{
		(DbContextOptions<AuditDbContext> options, SqliteConnection conn) = await CreateDbAsync();
		try
		{
			RdpConnectionFactUpserter upserter = new();
			DateTime t0 = new(2026, 5, 26, 10, 0, 0, DateTimeKind.Utc);
			RawEvent logon1 = Event(TsLsm, 21, t0, "203.0.113.6", "bob", logonId: "0x55", wts: 4);
			RawEvent logon2 = Event(TsLsm, 21, t0.AddMinutes(5), "203.0.113.6", "bob",
				logonId: "0x55", wts: 4);

			await using AuditDbContext db = new(options);
			await upserter.ApplyAsync(db, new[] { logon1, logon2 }, CancellationToken.None);
			await db.SaveChangesAsync();

			RdpConnectionFact row = await db.RdpConnectionFacts.SingleAsync();
			Assert.Equal(2, row.SuccessfulLogons);
		}
		finally
		{
			await conn.DisposeAsync();
		}
	}
}
