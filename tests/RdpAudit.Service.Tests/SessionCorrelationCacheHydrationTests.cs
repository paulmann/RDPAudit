// File:    tests/RdpAudit.Service.Tests/SessionCorrelationCacheHydrationTests.cs
// Module:  RdpAudit.Service.Tests
// Purpose: Verifies the Stage IP-B hydration path — SessionCorrelationCache populates its
//          three indexes from persisted SessionIpCorrelations and resolves lookups by LogonId,
//          (SessionId, UserName), and UserName after a single hydration pass.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using RdpAudit.Core.Data;
using RdpAudit.Core.Models;
using RdpAudit.Service.Processors;
using RdpAudit.Service.Workers;
using Xunit;

namespace RdpAudit.Service.Tests;

public class SessionCorrelationCacheHydrationTests
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

	[Fact]
	public async Task HydrateOnceAsync_SeedsLogonIdIndex_FromPersistedRows()
	{
		(IDbContextFactory<AuditDbContext> factory, SqliteConnection conn) = await CreateDbAsync();
		try
		{
			DateTime now = DateTime.UtcNow;
			await using (AuditDbContext seed = factory.CreateDbContext())
			{
				seed.SessionIpCorrelations.Add(new SessionIpCorrelation
				{
					LogonId = "0x1a2b",
					WtsSessionId = 4,
					UserName = "alice",
					Ip = "203.0.113.30",
					FirstSeenUtc = now,
					LastSeenUtc = now,
					IsDirectObservation = true,
				});
				await seed.SaveChangesAsync();
			}

			SessionCorrelationCache cache = new();
			SessionCorrelationHydrationWorker worker = new(
				factory, cache, NullLogger<SessionCorrelationHydrationWorker>.Instance);

			await worker.HydrateOnceAsync(CancellationToken.None);

			Assert.True(cache.IsHydrated);
			Assert.Equal("203.0.113.30", cache.Lookup("0x1a2b", sessionId: null, userName: null));
			Assert.Equal("203.0.113.30", cache.Lookup(logonId: null, sessionId: 4, userName: "alice"));
			Assert.Equal("203.0.113.30", cache.Lookup(logonId: null, sessionId: null, userName: "alice"));
		}
		finally
		{
			await conn.DisposeAsync();
		}
	}

	[Fact]
	public async Task HydrateOnceAsync_SkipsStaleRows_BeyondLookback()
	{
		(IDbContextFactory<AuditDbContext> factory, SqliteConnection conn) = await CreateDbAsync();
		try
		{
			DateTime now = DateTime.UtcNow;
			await using (AuditDbContext seed = factory.CreateDbContext())
			{
				// One stale row, one fresh row.
				seed.SessionIpCorrelations.Add(new SessionIpCorrelation
				{
					LogonId = "0xOLD",
					Ip = "198.51.100.99",
					FirstSeenUtc = now.AddDays(-10),
					LastSeenUtc = now.AddDays(-10),
				});
				seed.SessionIpCorrelations.Add(new SessionIpCorrelation
				{
					LogonId = "0xNEW",
					Ip = "203.0.113.7",
					FirstSeenUtc = now.AddMinutes(-30),
					LastSeenUtc = now.AddMinutes(-30),
				});
				await seed.SaveChangesAsync();
			}

			SessionCorrelationCache cache = new();
			SessionCorrelationHydrationWorker worker = new(
				factory, cache, NullLogger<SessionCorrelationHydrationWorker>.Instance);

			await worker.HydrateOnceAsync(CancellationToken.None);

			Assert.Null(cache.Lookup("0xOLD", null, null));
			Assert.Equal("203.0.113.7", cache.Lookup("0xNEW", null, null));
		}
		finally
		{
			await conn.DisposeAsync();
		}
	}

	[Fact]
	public async Task HydrateOnceAsync_IsIdempotent_AndDoesNotReload()
	{
		(IDbContextFactory<AuditDbContext> factory, SqliteConnection conn) = await CreateDbAsync();
		try
		{
			DateTime now = DateTime.UtcNow;
			await using (AuditDbContext seed = factory.CreateDbContext())
			{
				seed.SessionIpCorrelations.Add(new SessionIpCorrelation
				{
					LogonId = "0xKEEP",
					Ip = "203.0.113.55",
					FirstSeenUtc = now,
					LastSeenUtc = now,
				});
				await seed.SaveChangesAsync();
			}

			SessionCorrelationCache cache = new();
			SessionCorrelationHydrationWorker worker = new(
				factory, cache, NullLogger<SessionCorrelationHydrationWorker>.Instance);

			await worker.HydrateOnceAsync(CancellationToken.None);
			int initialCount = cache.Count;

			// Append more rows to the DB; second invocation must short-circuit.
			await using (AuditDbContext extra = factory.CreateDbContext())
			{
				extra.SessionIpCorrelations.Add(new SessionIpCorrelation
				{
					LogonId = "0xSECOND",
					Ip = "203.0.113.66",
					FirstSeenUtc = now,
					LastSeenUtc = now,
				});
				await extra.SaveChangesAsync();
			}

			await worker.HydrateOnceAsync(CancellationToken.None);
			Assert.Equal(initialCount, cache.Count);
			Assert.Null(cache.Lookup("0xSECOND", null, null));
		}
		finally
		{
			await conn.DisposeAsync();
		}
	}
}
