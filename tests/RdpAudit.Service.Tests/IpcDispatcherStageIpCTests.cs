// File:    tests/RdpAudit.Service.Tests/IpcDispatcherStageIpCTests.cs
// Module:  RdpAudit.Service.Tests
// Purpose: Stage IP-C Remote RDP Clients enrichment tests — exercises the dispatcher's
//          IpcDispatcher.EnrichSessionsFromConnectionFactsAsync helper. Verifies that the
//          connection-fact fallback only fills empty ClientAddress slots and prefers
//          (WtsSessionId, UserName) matches over a UserName fallback.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using RdpAudit.Core.Data;
using RdpAudit.Core.Ipc.Contracts;
using RdpAudit.Core.Models;
using RdpAudit.Service.Ipc;
using Xunit;

namespace RdpAudit.Service.Tests;

public class IpcDispatcherStageIpCTests
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
	public async Task FactEnrichment_FillsEmptyClientAddressBy_WtsSessionId_UserName()
	{
		(DbContextOptions<AuditDbContext> options, SqliteConnection conn) = await CreateDbAsync();
		try
		{
			DateTime now = DateTime.UtcNow;
			await using (AuditDbContext seed = new(options))
			{
				seed.RdpConnectionFacts.Add(new RdpConnectionFact
				{
					WtsSessionId = 7,
					UserName = "alice",
					Ip = "203.0.113.10",
					FirstSeenUtc = now.AddMinutes(-30),
					LastSeenUtc = now.AddMinutes(-1),
				});
				await seed.SaveChangesAsync();
			}

			List<RdpSessionDto> sessions = new()
			{
				new RdpSessionDto { SessionId = 7, UserName = "alice", ClientAddress = null },
			};

			await using AuditDbContext db = new(options);
			await IpcDispatcher.EnrichSessionsFromConnectionFactsAsync(db, sessions, CancellationToken.None);

			Assert.Equal("203.0.113.10", sessions[0].ClientAddress);
		}
		finally
		{
			await conn.DisposeAsync();
		}
	}

	[Fact]
	public async Task FactEnrichment_FallsBackToUserName_WhenNoWtsMatch()
	{
		(DbContextOptions<AuditDbContext> options, SqliteConnection conn) = await CreateDbAsync();
		try
		{
			DateTime now = DateTime.UtcNow;
			await using (AuditDbContext seed = new(options))
			{
				seed.RdpConnectionFacts.Add(new RdpConnectionFact
				{
					WtsSessionId = 42,
					UserName = "alice",
					Ip = "203.0.113.20",
					FirstSeenUtc = now.AddMinutes(-30),
					LastSeenUtc = now.AddMinutes(-1),
				});
				await seed.SaveChangesAsync();
			}

			List<RdpSessionDto> sessions = new()
			{
				new RdpSessionDto { SessionId = 7, UserName = "alice", ClientAddress = null },
			};

			await using AuditDbContext db = new(options);
			await IpcDispatcher.EnrichSessionsFromConnectionFactsAsync(db, sessions, CancellationToken.None);

			Assert.Equal("203.0.113.20", sessions[0].ClientAddress);
		}
		finally
		{
			await conn.DisposeAsync();
		}
	}

	[Fact]
	public async Task FactEnrichment_DoesNotOverwriteExistingClientAddress()
	{
		(DbContextOptions<AuditDbContext> options, SqliteConnection conn) = await CreateDbAsync();
		try
		{
			DateTime now = DateTime.UtcNow;
			await using (AuditDbContext seed = new(options))
			{
				seed.RdpConnectionFacts.Add(new RdpConnectionFact
				{
					WtsSessionId = 5,
					UserName = "bob",
					Ip = "203.0.113.30",
					FirstSeenUtc = now,
					LastSeenUtc = now,
				});
				await seed.SaveChangesAsync();
			}

			const string Existing = "198.51.100.99";
			List<RdpSessionDto> sessions = new()
			{
				new RdpSessionDto { SessionId = 5, UserName = "bob", ClientAddress = Existing },
			};

			await using AuditDbContext db = new(options);
			await IpcDispatcher.EnrichSessionsFromConnectionFactsAsync(db, sessions, CancellationToken.None);

			Assert.Equal(Existing, sessions[0].ClientAddress);
		}
		finally
		{
			await conn.DisposeAsync();
		}
	}

	[Fact]
	public async Task FactEnrichment_NoMatchingFact_LeavesAddressEmpty()
	{
		(DbContextOptions<AuditDbContext> options, SqliteConnection conn) = await CreateDbAsync();
		try
		{
			List<RdpSessionDto> sessions = new()
			{
				new RdpSessionDto { SessionId = 1, UserName = "nobody", ClientAddress = null },
			};

			await using AuditDbContext db = new(options);
			await IpcDispatcher.EnrichSessionsFromConnectionFactsAsync(db, sessions, CancellationToken.None);

			Assert.Null(sessions[0].ClientAddress);
		}
		finally
		{
			await conn.DisposeAsync();
		}
	}
}
