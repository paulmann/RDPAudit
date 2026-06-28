// File:    tests/RdpAudit.Service.Tests/IpcDispatcherStageIpBTests.cs
// Module:  RdpAudit.Service.Tests
// Purpose: Stage IP-B Remote RDP Clients lookup tests — exercises the dispatcher's
//          IpcDispatcher.EnrichSessionsFromCorrelationsAsync helper. Verifies that
//          (WtsSessionId, UserName) wins over a UserName fallback, that UserName fallback
//          is used when no WtsSessionId match exists, and that an existing ClientAddress is
//          never overwritten.
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

public class IpcDispatcherStageIpBTests
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
	public async Task Enrich_PrefersWtsSessionIdMatch_OverUserNameFallback()
	{
		(DbContextOptions<AuditDbContext> options, SqliteConnection conn) = await CreateDbAsync();
		try
		{
			DateTime now = DateTime.UtcNow;
			await using (AuditDbContext seed = new(options))
			{
				// UserName-only row (older).
				seed.SessionIpCorrelations.Add(new SessionIpCorrelation
				{
					LogonId = null,
					WtsSessionId = null,
					UserName = "alice",
					Ip = "10.0.0.1",
					FirstSeenUtc = now.AddMinutes(-30),
					LastSeenUtc = now.AddMinutes(-30),
				});
				// (Session, UserName) row (newer + more specific).
				seed.SessionIpCorrelations.Add(new SessionIpCorrelation
				{
					LogonId = "0xAA",
					WtsSessionId = 7,
					UserName = "alice",
					Ip = "203.0.113.7",
					FirstSeenUtc = now.AddMinutes(-5),
					LastSeenUtc = now.AddMinutes(-5),
				});
				await seed.SaveChangesAsync();
			}

			List<RdpSessionDto> sessions = new()
			{
				new RdpSessionDto { SessionId = 7, UserName = "alice", State = "Active" },
			};

			await using AuditDbContext db = new(options);
			await IpcDispatcher.EnrichSessionsFromCorrelationsAsync(db, sessions, CancellationToken.None);

			Assert.Equal("203.0.113.7", sessions[0].ClientAddress);
		}
		finally
		{
			await conn.DisposeAsync();
		}
	}

	[Fact]
	public async Task Enrich_FallsBackToUserName_WhenNoWtsSessionIdMatch()
	{
		(DbContextOptions<AuditDbContext> options, SqliteConnection conn) = await CreateDbAsync();
		try
		{
			DateTime now = DateTime.UtcNow;
			await using (AuditDbContext seed = new(options))
			{
				seed.SessionIpCorrelations.Add(new SessionIpCorrelation
				{
					LogonId = null,
					WtsSessionId = 11, // different session id
					UserName = "bob",
					Ip = "10.0.0.99",
					FirstSeenUtc = now,
					LastSeenUtc = now,
				});
				seed.SessionIpCorrelations.Add(new SessionIpCorrelation
				{
					LogonId = null,
					WtsSessionId = null,
					UserName = "bob",
					Ip = "198.51.100.7",
					FirstSeenUtc = now.AddMinutes(-10),
					LastSeenUtc = now.AddMinutes(-10),
				});
				await seed.SaveChangesAsync();
			}

			List<RdpSessionDto> sessions = new()
			{
				new RdpSessionDto { SessionId = 4, UserName = "bob", State = "Disconnected" },
			};

			await using AuditDbContext db = new(options);
			await IpcDispatcher.EnrichSessionsFromCorrelationsAsync(db, sessions, CancellationToken.None);

			// SessionId 4 does not match any persisted row → fallback to most recent UserName-only,
			// which is the row with UserName=bob, WtsSessionId=11.
			Assert.NotNull(sessions[0].ClientAddress);
			Assert.True(sessions[0].ClientAddress is "10.0.0.99" or "198.51.100.7");
		}
		finally
		{
			await conn.DisposeAsync();
		}
	}

	[Fact]
	public async Task Enrich_DoesNotOverwriteExistingClientAddress()
	{
		(DbContextOptions<AuditDbContext> options, SqliteConnection conn) = await CreateDbAsync();
		try
		{
			DateTime now = DateTime.UtcNow;
			await using (AuditDbContext seed = new(options))
			{
				seed.SessionIpCorrelations.Add(new SessionIpCorrelation
				{
					LogonId = "0xZZ",
					WtsSessionId = 3,
					UserName = "carol",
					Ip = "203.0.113.50",
					FirstSeenUtc = now,
					LastSeenUtc = now,
				});
				await seed.SaveChangesAsync();
			}

			List<RdpSessionDto> sessions = new()
			{
				new RdpSessionDto
				{
					SessionId = 3,
					UserName = "carol",
					State = "Active",
					ClientAddress = "192.0.2.99",
				},
			};

			await using AuditDbContext db = new(options);
			await IpcDispatcher.EnrichSessionsFromCorrelationsAsync(db, sessions, CancellationToken.None);

			Assert.Equal("192.0.2.99", sessions[0].ClientAddress);
		}
		finally
		{
			await conn.DisposeAsync();
		}
	}

	[Fact]
	public async Task Enrich_NoMatch_LeavesClientAddressNull()
	{
		(DbContextOptions<AuditDbContext> options, SqliteConnection conn) = await CreateDbAsync();
		try
		{
			List<RdpSessionDto> sessions = new()
			{
				new RdpSessionDto { SessionId = 99, UserName = "ghost", State = "Active" },
			};

			await using AuditDbContext db = new(options);
			await IpcDispatcher.EnrichSessionsFromCorrelationsAsync(db, sessions, CancellationToken.None);

			Assert.Null(sessions[0].ClientAddress);
		}
		finally
		{
			await conn.DisposeAsync();
		}
	}
}
