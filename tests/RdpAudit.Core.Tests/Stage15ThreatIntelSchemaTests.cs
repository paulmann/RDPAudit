// File:    tests/RdpAudit.Core.Tests/Stage15ThreatIntelSchemaTests.cs
// Module:  RdpAudit.Core.Tests
// Purpose: Validates the Backlog #5 threat-intelligence persistence surface - the
//          ThreatIntelLookups cache table and the ThreatIntelUsageCounters daily budget table:
//          EF mapping, primary-key semantics, and the supporting retry/freshness indexes.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using RdpAudit.Core.Data;
using RdpAudit.Core.Models;
using Xunit;

namespace RdpAudit.Core.Tests;

/// <summary>Schema tests for Stage 15 threat-intelligence persistence.</summary>
public class Stage15ThreatIntelSchemaTests : IDisposable
{
	private readonly SqliteConnection _connection;
	private readonly DbContextOptions<AuditDbContext> _options;

	public Stage15ThreatIntelSchemaTests()
	{
		_connection = new SqliteConnection("DataSource=:memory:");
		_connection.Open();
		_options = new DbContextOptionsBuilder<AuditDbContext>()
			.UseSqlite(_connection)
			.Options;

		using AuditDbContext db = new(_options);
		db.Database.EnsureCreated();
	}

	public void Dispose()
	{
		_connection.Dispose();
	}

	[Fact]
	public void DbContext_ExposesThreatIntelDbSets()
	{
		using AuditDbContext db = new(_options);
		Assert.NotNull(db.ThreatIntelLookups);
		Assert.NotNull(db.ThreatIntelUsageCounters);
	}

	[Fact]
	public void ThreatIntelLookup_PersistsAndReads()
	{
		DateTime now = DateTime.UtcNow;
		using (AuditDbContext db = new(_options))
		{
			db.ThreatIntelLookups.Add(new ThreatIntelLookup
			{
				Ip = "203.0.113.77",
				LookedUpUtc = now,
				Outcome = 0,
				Score = 92,
				TotalReports = 15,
				IsWhitelisted = false,
				IsPublic = true,
				UsageType = "Data Center/Web Hosting/Transit",
				CountryCode = "US",
				NextRetryUtc = now.AddMinutes(30),
			});
			db.SaveChanges();
		}

		using (AuditDbContext db = new(_options))
		{
			ThreatIntelLookup? row = db.ThreatIntelLookups.SingleOrDefault();
			Assert.NotNull(row);
			Assert.Equal("203.0.113.77", row!.Ip);
			Assert.Equal(0, row.Outcome);
			Assert.Equal(92, row.Score);
			Assert.Equal(15, row.TotalReports);
			Assert.False(row.IsWhitelisted);
			Assert.True(row.IsPublic);
			Assert.Equal("Data Center/Web Hosting/Transit", row.UsageType);
			Assert.Equal("US", row.CountryCode);
			Assert.NotNull(row.NextRetryUtc);
		}
	}

	[Fact]
	public void ThreatIntelLookup_RejectsDuplicateIp()
	{
		using (AuditDbContext db = new(_options))
		{
			db.ThreatIntelLookups.Add(new ThreatIntelLookup
			{
				Ip = "198.51.100.9",
				LookedUpUtc = DateTime.UtcNow,
				Outcome = 0,
				Score = 5,
			});
			db.SaveChanges();
		}

		using (AuditDbContext db = new(_options))
		{
			db.ThreatIntelLookups.Add(new ThreatIntelLookup
			{
				Ip = "198.51.100.9",
				LookedUpUtc = DateTime.UtcNow,
				Outcome = 2,
				NextRetryUtc = DateTime.UtcNow.AddMinutes(1),
			});
			Assert.Throws<DbUpdateException>(() => db.SaveChanges());
		}
	}

	[Fact]
	public void ThreatIntelUsageCounter_RejectsDuplicateDay()
	{
		using (AuditDbContext db = new(_options))
		{
			db.ThreatIntelUsageCounters.Add(new ThreatIntelUsageCounter
			{
				DayDateUtc = "2026-09-12",
				Count = 3,
			});
			db.SaveChanges();
		}

		using (AuditDbContext db = new(_options))
		{
			db.ThreatIntelUsageCounters.Add(new ThreatIntelUsageCounter
			{
				DayDateUtc = "2026-09-12",
				Count = 1,
			});
			Assert.Throws<DbUpdateException>(() => db.SaveChanges());
		}
	}

	[Fact]
	public void MigrationsAssembly_DeclaresStage15Migration()
	{
		using SqliteConnection connection = new("DataSource=:memory:");
		connection.Open();
		DbContextOptions<AuditDbContext> options = new DbContextOptionsBuilder<AuditDbContext>()
			.UseSqlite(connection)
			.Options;

		using AuditDbContext db = new(options);
		IEnumerable<string> migrations = db.Database.GetMigrations();
		Assert.Contains(migrations, m => m.EndsWith("_Stage15ThreatIntel", StringComparison.Ordinal));
	}

	[Fact]
	public void Indexes_AllPresent_OnThreatIntelLookups()
	{
		using AuditDbContext db = new(_options);
		using SqliteCommand cmd = _connection.CreateCommand();
		cmd.CommandText = "SELECT name FROM sqlite_master WHERE type = 'index' AND tbl_name = 'ThreatIntelLookups';";
		using SqliteDataReader rd = cmd.ExecuteReader();
		HashSet<string> indexes = new(StringComparer.OrdinalIgnoreCase);
		while (rd.Read())
		{
			indexes.Add(rd.GetString(0));
		}

		Assert.Contains("IX_ThreatIntelLookups_LookedUpUtc", indexes);
		Assert.Contains("IX_ThreatIntelLookups_NextRetryUtc", indexes);
	}
}
