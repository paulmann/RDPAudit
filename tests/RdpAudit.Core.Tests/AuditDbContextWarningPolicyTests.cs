// File:    tests/RdpAudit.Core.Tests/AuditDbContextWarningPolicyTests.cs
// Module:  RdpAudit.Core.Tests
// Purpose: Pins the P4 warning-as-error policy: any EF Core Skip/Take that runs without a
//          deterministic prior ORDER BY must throw at query time (RowLimitingOperationWithoutOrderBy
//          escalated by AuditDbContextOptions.ApplyWarningPolicy), while a bounded query with an
//          explicit total order keeps working.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using RdpAudit.Core.Data;
using RdpAudit.Core.Models;
using Xunit;

namespace RdpAudit.Core.Tests;

/// <summary>P4 EF Core warning-policy tests.</summary>
public class AuditDbContextWarningPolicyTests
{
	private static (DbContextOptions<AuditDbContext>, SqliteConnection) CreatePolicyOptions()
	{
		SqliteConnection connection = new("DataSource=:memory:");
		connection.Open();
		DbContextOptionsBuilder<AuditDbContext> builder = new();
		builder.UseSqlite(connection);
		AuditDbContextOptions.ApplyWarningPolicy(builder);
		return (builder.Options, connection);
	}

	[Fact]
	public async Task WarningPolicy_Throws_WhenTakeRunsWithoutOrderBy()
	{
		(DbContextOptions<AuditDbContext> options, SqliteConnection connection) = CreatePolicyOptions();
		try
		{
			await using (AuditDbContext db = new(options))
			{
				await db.Database.EnsureCreatedAsync();
				db.RawEvents.Add(new RawEvent
				{
					EventId = 4625,
					Channel = "Security",
					TimeUtc = DateTime.UtcNow,
					UserName = "alice",
				});
				await db.SaveChangesAsync();
			}

			await using (AuditDbContext db = new(options))
			{
				// Take with no prior OrderBy must be rejected by the escalated warning.
				await Assert.ThrowsAsync<InvalidOperationException>(
					() => db.RawEvents.Take(5).ToListAsync());
			}
		}
		finally
		{
			await connection.DisposeAsync();
		}
	}

	[Fact]
	public async Task WarningPolicy_Throws_WhenSkipTakeRunsWithoutOrderBy()
	{
		(DbContextOptions<AuditDbContext> options, SqliteConnection connection) = CreatePolicyOptions();
		try
		{
			await using (AuditDbContext db = new(options))
			{
				await db.Database.EnsureCreatedAsync();
				db.RawEvents.Add(new RawEvent
				{
					EventId = 4625,
					Channel = "Security",
					TimeUtc = DateTime.UtcNow,
					UserName = "alice",
				});
				await db.SaveChangesAsync();
			}

			await using (AuditDbContext db = new(options))
			{
				// Skip/Take paging with no prior OrderBy must be rejected.
				await Assert.ThrowsAsync<InvalidOperationException>(
					() => db.RawEvents.Skip(1).Take(4).ToListAsync());
			}
		}
		finally
		{
			await connection.DisposeAsync();
		}
	}

	[Fact]
	public async Task WarningPolicy_AllowsBoundedQuery_WithDeterministicTotalOrder()
	{
		(DbContextOptions<AuditDbContext> options, SqliteConnection connection) = CreatePolicyOptions();
		try
		{
			await using (AuditDbContext db = new(options))
			{
				await db.Database.EnsureCreatedAsync();
				for (int i = 0; i < 6; i++)
				{
					db.RawEvents.Add(new RawEvent
					{
						EventId = 4625,
						Channel = "Security",
						TimeUtc = DateTime.UtcNow.AddMinutes(-i),
						UserName = "user" + i.ToString(System.Globalization.CultureInfo.InvariantCulture),
					});
				}
				await db.SaveChangesAsync();
			}

			await using (AuditDbContext db = new(options))
			{
				// Deterministic timestamp + stable key tie-break: policy must stay silent.
				List<RawEvent> rows = await db.RawEvents
					.AsNoTracking()
					.OrderByDescending(e => e.TimeUtc)
					.ThenByDescending(e => e.Id)
					.Take(3)
					.ToListAsync();

				Assert.Equal(3, rows.Count);
			}
		}
		finally
		{
			await connection.DisposeAsync();
		}
	}

	[Fact]
	public async Task WarningPolicy_DistinctThenOrderByThenTake_ReturnsDeterministicTopRows()
	{
		// EF Core issue 23392 guard: an ORDER BY applied BEFORE Distinct is stripped by the
		// provider, so the service re-sorts AFTER Distinct to keep bounded label queries
		// deterministic. Pin that pattern here: Distinct -> OrderBy -> Take must evaluate
		// deterministically and return the alphabetically first distinct values.
		(DbContextOptions<AuditDbContext> options, SqliteConnection connection) = CreatePolicyOptions();
		try
		{
			await using (AuditDbContext db = new(options))
			{
				await db.Database.EnsureCreatedAsync();
				string[] names = { "dave", "alice", "carol", "alice", "bob", "carol" };
				foreach (string name in names)
				{
					db.RawEvents.Add(new RawEvent
					{
						EventId = 4625,
						Channel = "Security",
						TimeUtc = DateTime.UtcNow,
						UserName = name,
					});
				}
				await db.SaveChangesAsync();
			}

			await using (AuditDbContext db = new(options))
			{
				List<string> top = await db.RawEvents.AsNoTracking()
					.Where(e => e.UserName != null && e.UserName != string.Empty)
					.Select(e => e.UserName!)
					.Distinct()
					.OrderBy(u => u)
					.Take(3)
					.ToListAsync();

				Assert.Equal(new[] { "alice", "bob", "carol" }, top);
			}
		}
		finally
		{
			await connection.DisposeAsync();
		}
	}
}
