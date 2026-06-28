// File:    tests/RdpAudit.Service.Tests/SessionIpCorrelationUpserterTests.cs
// Module:  RdpAudit.Service.Tests
// Purpose: Verifies SessionIpCorrelationUpserter merge semantics — first observation creates a
//          row, subsequent observations under the same key refresh LastSeenUtc / ObservedEventIds
//          without producing duplicates, hostnames are rejected, and at most one logical upsert
//          per unique correlation key occurs per batch.
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

public class SessionIpCorrelationUpserterTests
{
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

	[Fact]
	public async Task ApplyAsync_DirectEvent_InsertsRow()
	{
		(DbContextOptions<AuditDbContext> options, SqliteConnection conn) = await CreateDbAsync();
		try
		{
			SessionIpCorrelationUpserter upserter = new();
			DateTime t = new(2026, 5, 20, 10, 0, 0, DateTimeKind.Utc);

			SessionIpCorrelationCandidate c = new(
				LogonId: "0x42",
				WtsSessionId: 3,
				UserName: "alice",
				Domain: "CORP",
				Ip: "203.0.113.5",
				ObservedUtc: t,
				EventId: 4624,
				IsDirectObservation: true);

			await using (AuditDbContext db = new(options))
			{
				await upserter.ApplyAsync(db, new[] { c }, CancellationToken.None);
				await db.SaveChangesAsync();
			}

			await using (AuditDbContext db = new(options))
			{
				SessionIpCorrelation row = await db.SessionIpCorrelations.SingleAsync();
				Assert.Equal("0x42", row.LogonId);
				Assert.Equal(3, row.WtsSessionId);
				Assert.Equal("alice", row.UserName);
				Assert.Equal("203.0.113.5", row.Ip);
				Assert.Equal(t, row.FirstSeenUtc);
				Assert.Equal(t, row.LastSeenUtc);
				Assert.Equal("4624", row.ObservedEventIds);
				Assert.True(row.IsDirectObservation);
			}
		}
		finally
		{
			await conn.DisposeAsync();
		}
	}

	[Fact]
	public async Task ApplyAsync_SameLogonIdRepeated_RefreshesRowAndDoesNotDuplicate()
	{
		(DbContextOptions<AuditDbContext> options, SqliteConnection conn) = await CreateDbAsync();
		try
		{
			SessionIpCorrelationUpserter upserter = new();
			DateTime t1 = new(2026, 5, 20, 10, 0, 0, DateTimeKind.Utc);
			DateTime t2 = t1.AddMinutes(5);

			SessionIpCorrelationCandidate c1 = new("0x99", 5, "bob", null, "203.0.113.7", t1, 4624, true);
			SessionIpCorrelationCandidate c2 = new("0x99", 5, "bob", null, "203.0.113.7", t2, 4634, true);

			await using (AuditDbContext db = new(options))
			{
				await upserter.ApplyAsync(db, new[] { c1 }, CancellationToken.None);
				await db.SaveChangesAsync();
			}

			await using (AuditDbContext db = new(options))
			{
				await upserter.ApplyAsync(db, new[] { c2 }, CancellationToken.None);
				await db.SaveChangesAsync();
			}

			await using (AuditDbContext db = new(options))
			{
				Assert.Equal(1, await db.SessionIpCorrelations.CountAsync());
				SessionIpCorrelation row = await db.SessionIpCorrelations.SingleAsync();
				Assert.Equal(t1, row.FirstSeenUtc);
				Assert.Equal(t2, row.LastSeenUtc);
				Assert.Contains("4624", row.ObservedEventIds);
				Assert.Contains("4634", row.ObservedEventIds);
			}
		}
		finally
		{
			await conn.DisposeAsync();
		}
	}

	[Fact]
	public async Task ApplyAsync_HostnameInIp_IsRejected()
	{
		(DbContextOptions<AuditDbContext> options, SqliteConnection conn) = await CreateDbAsync();
		try
		{
			SessionIpCorrelationUpserter upserter = new();
			DateTime t = DateTime.UtcNow;

			SessionIpCorrelationCandidate c = new(
				LogonId: "0xAA",
				WtsSessionId: 1,
				UserName: "x",
				Domain: null,
				Ip: "WORKSTATION01",
				ObservedUtc: t,
				EventId: 4776,
				IsDirectObservation: true);

			await using AuditDbContext db = new(options);
			await upserter.ApplyAsync(db, new[] { c }, CancellationToken.None);
			await db.SaveChangesAsync();

			Assert.Equal(0, await db.SessionIpCorrelations.CountAsync());
		}
		finally
		{
			await conn.DisposeAsync();
		}
	}

	[Fact]
	public async Task ApplyAsync_DuplicateKeyInSameBatch_ProducesSingleRow()
	{
		(DbContextOptions<AuditDbContext> options, SqliteConnection conn) = await CreateDbAsync();
		try
		{
			SessionIpCorrelationUpserter upserter = new();
			DateTime t1 = new(2026, 5, 20, 10, 0, 0, DateTimeKind.Utc);
			DateTime t2 = t1.AddSeconds(30);

			SessionIpCorrelationCandidate c1 = new("0xDE", 8, "dave", null, "203.0.113.20", t1, 4624, true);
			SessionIpCorrelationCandidate c2 = new("0xDE", 8, "dave", null, "203.0.113.21", t2, 4624, true);

			await using AuditDbContext db = new(options);
			await upserter.ApplyAsync(db, new[] { c1, c2 }, CancellationToken.None);
			await db.SaveChangesAsync();

			SessionIpCorrelation row = await db.SessionIpCorrelations.SingleAsync();
			Assert.Equal(t2, row.LastSeenUtc);
			Assert.Equal("203.0.113.21", row.Ip);
		}
		finally
		{
			await conn.DisposeAsync();
		}
	}

	[Fact]
	public async Task ApplyAsync_WtsSessionIdAndUserName_ResolvesWithoutLogonId()
	{
		(DbContextOptions<AuditDbContext> options, SqliteConnection conn) = await CreateDbAsync();
		try
		{
			SessionIpCorrelationUpserter upserter = new();
			DateTime t1 = DateTime.UtcNow.AddMinutes(-10);
			DateTime t2 = DateTime.UtcNow;

			SessionIpCorrelationCandidate seed = new(null, 11, "carol", null, "198.51.100.5", t1, 1149, true);
			SessionIpCorrelationCandidate update = new(null, 11, "carol", null, "198.51.100.5", t2, 21, true);

			await using AuditDbContext db = new(options);
			await upserter.ApplyAsync(db, new[] { seed }, CancellationToken.None);
			await db.SaveChangesAsync();

			await upserter.ApplyAsync(db, new[] { update }, CancellationToken.None);
			await db.SaveChangesAsync();

			Assert.Equal(1, await db.SessionIpCorrelations.CountAsync());
			SessionIpCorrelation row = await db.SessionIpCorrelations.SingleAsync();
			Assert.Equal(t2, row.LastSeenUtc);
			Assert.Contains("1149", row.ObservedEventIds);
			Assert.Contains("21", row.ObservedEventIds);
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
		for (int i = 1; i <= 25; i++)
		{
			current = SessionIpCorrelationUpserter.AppendEventId(current, i);
		}

		Assert.NotNull(current);
		Assert.True(current!.Length <= SessionIpCorrelationUpserter.ObservedEventIdsMaxLength);
		string[] parts = current.Split(',');
		Assert.True(parts.Length <= SessionIpCorrelationUpserter.MaxObservedEventIds);
		Assert.Equal("25", parts[^1]);

		// Re-appending an existing id moves it to the tail without producing a duplicate.
		string twice = SessionIpCorrelationUpserter.AppendEventId(current, 25);
		string[] twiceParts = twice.Split(',');
		Assert.Equal(twiceParts.Distinct().Count(), twiceParts.Length);
	}
}
