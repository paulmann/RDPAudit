// File:    tests/RdpAudit.Core.Tests/Stage2MigrationUpgradeTests.cs
// Module:  RdpAudit.Core.Tests
// Purpose: Validates that Stage 2 EF Core migrations apply cleanly both on a fresh database and on
//          a Stage-1-only database. Confirms the Stage 2 migration is present, that the upgrade
//          path preserves Stage 1 rows, and that the down-migration removes Stage 2 tables.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;
using RdpAudit.Core.Data;
using RdpAudit.Core.Models;
using Xunit;

namespace RdpAudit.Core.Tests;

/// <summary>Migration upgrade tests for Stage 2.</summary>
public class Stage2MigrationUpgradeTests
{
	private const string Stage1Migration = "20260504215120_InitialCreate";
	private const string Stage2MigrationSuffix = "Stage2FirewallStats";

	[Fact]
	public void MigrationsAssembly_DeclaresStage2Migration()
	{
		using SqliteConnection connection = new("DataSource=:memory:");
		connection.Open();

		DbContextOptions<AuditDbContext> options = new DbContextOptionsBuilder<AuditDbContext>()
			.UseSqlite(connection)
			.Options;

		using AuditDbContext db = new(options);
		IEnumerable<string> migrations = db.Database.GetMigrations();

		Assert.Contains(migrations, m => m.EndsWith("_" + Stage2MigrationSuffix, StringComparison.Ordinal));
		Assert.Contains(migrations, m => m == Stage1Migration);
	}

	[Fact]
	public void MigrateAsync_OnFreshDatabase_CreatesAllStage2Tables()
	{
		using SqliteConnection connection = new("DataSource=:memory:");
		connection.Open();

		DbContextOptions<AuditDbContext> options = new DbContextOptionsBuilder<AuditDbContext>()
			.UseSqlite(connection)
			.Options;

		using AuditDbContext db = new(options);
		db.Database.Migrate();

		HashSet<string> tables = ListTables(connection);

		Assert.Contains("BlocklistEntries", tables);
		Assert.Contains("WhitelistEntries", tables);
		Assert.Contains("LoginRules", tables);
		Assert.Contains("ActiveBlocks", tables);
		Assert.Contains("AbuseReports", tables);
		Assert.Contains("AttackStats", tables);
	}

	[Fact]
	public void Stage2Migration_PreservesStage1RowsOnUpgrade()
	{
		using SqliteConnection connection = new("DataSource=:memory:");
		connection.Open();

		DbContextOptions<AuditDbContext> options = new DbContextOptionsBuilder<AuditDbContext>()
			.UseSqlite(connection)
			.Options;

		using (AuditDbContext db = new(options))
		{
			IMigrator migrator = db.GetService<IMigrator>();
			migrator.Migrate(Stage1Migration);
		}

		using (AuditDbContext db = new(options))
		{
			db.Addresses.Add(new Address
			{
				Ip = "1.1.1.1",
				FirstSeen = DateTime.UtcNow,
				LastSeen = DateTime.UtcNow,
			});
			db.Alerts.Add(new Alert
			{
				RuleId = "rule",
				TimeUtc = DateTime.UtcNow,
				Message = "msg",
				Severity = AlertSeverity.Medium,
			});
			db.SaveChanges();
		}

		using (AuditDbContext db = new(options))
		{
			db.Database.Migrate();

			Assert.Single(db.Addresses);
			Assert.Single(db.Alerts);
			Assert.Empty(db.BlocklistEntries);
			Assert.Empty(db.WhitelistEntries);
			Assert.Empty(db.LoginRules);
			Assert.Empty(db.ActiveBlocks);
			Assert.Empty(db.AbuseReports);
			Assert.Empty(db.AttackStats);
		}
	}

	[Fact]
	public void Stage2Migration_DownRemovesStage2TablesAndKeepsStage1()
	{
		using SqliteConnection connection = new("DataSource=:memory:");
		connection.Open();

		DbContextOptions<AuditDbContext> options = new DbContextOptionsBuilder<AuditDbContext>()
			.UseSqlite(connection)
			.Options;

		using (AuditDbContext db = new(options))
		{
			db.Database.Migrate();
			Assert.Contains("BlocklistEntries", ListTables(connection));
		}

		using (AuditDbContext db = new(options))
		{
			IMigrator migrator = db.GetService<IMigrator>();
			migrator.Migrate(Stage1Migration);
		}

		HashSet<string> tables = ListTables(connection);

		Assert.DoesNotContain("BlocklistEntries", tables);
		Assert.DoesNotContain("WhitelistEntries", tables);
		Assert.DoesNotContain("LoginRules", tables);
		Assert.DoesNotContain("ActiveBlocks", tables);
		Assert.DoesNotContain("AbuseReports", tables);
		Assert.DoesNotContain("AttackStats", tables);
		Assert.Contains("Addresses", tables);
		Assert.Contains("Alerts", tables);
	}

	private static HashSet<string> ListTables(SqliteConnection connection)
	{
		HashSet<string> tables = new(StringComparer.Ordinal);
		using SqliteCommand cmd = connection.CreateCommand();
		cmd.CommandText = "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' AND name NOT LIKE '__EF%'";
		using SqliteDataReader reader = cmd.ExecuteReader();
		while (reader.Read())
		{
			tables.Add(reader.GetString(0));
		}
		return tables;
	}
}
