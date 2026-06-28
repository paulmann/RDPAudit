// File:    tests/RdpAudit.Core.Tests/Stage6EventCorrectnessSchemaTests.cs
// Module:  RdpAudit.Core.Tests
// Purpose: Validates the Stage 6 RawEvent schema change — adds SourceIpUnresolved with a
//          false default, applies cleanly on a fresh database and as an upgrade from Stage 5,
//          and preserves Stage 5 rows during the upgrade.
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

public class Stage6EventCorrectnessSchemaTests
{
	private const string Stage5Migration = "20260520110000_Stage5RdpConnectionFact";
	private const string Stage6MigrationSuffix = "Stage6EventCorrectness";

	[Fact]
	public void MigrationsAssembly_DeclaresStage6Migration()
	{
		using SqliteConnection connection = new("DataSource=:memory:");
		connection.Open();
		DbContextOptions<AuditDbContext> options = new DbContextOptionsBuilder<AuditDbContext>()
			.UseSqlite(connection)
			.Options;

		using AuditDbContext db = new(options);
		IEnumerable<string> migrations = db.Database.GetMigrations();
		Assert.Contains(migrations, m => m.EndsWith("_" + Stage6MigrationSuffix, StringComparison.Ordinal));
	}

	[Fact]
	public void SourceIpUnresolved_DefaultsFalse_OnEnsureCreated()
	{
		using SqliteConnection connection = new("DataSource=:memory:");
		connection.Open();
		DbContextOptions<AuditDbContext> options = new DbContextOptionsBuilder<AuditDbContext>()
			.UseSqlite(connection)
			.Options;

		using (AuditDbContext db = new(options))
		{
			db.Database.EnsureCreated();
			db.RawEvents.Add(new RawEvent
			{
				EventId = 4625,
				Channel = "Security",
				TimeUtc = DateTime.UtcNow,
				UserName = "alice",
			});
			db.SaveChanges();
		}

		using (AuditDbContext db = new(options))
		{
			RawEvent row = db.RawEvents.Single();
			Assert.False(row.SourceIpUnresolved);
		}
	}

	[Fact]
	public void SourceIpUnresolved_RoundTripsTrue()
	{
		using SqliteConnection connection = new("DataSource=:memory:");
		connection.Open();
		DbContextOptions<AuditDbContext> options = new DbContextOptionsBuilder<AuditDbContext>()
			.UseSqlite(connection)
			.Options;

		using (AuditDbContext db = new(options))
		{
			db.Database.EnsureCreated();
			db.RawEvents.Add(new RawEvent
			{
				EventId = 4625,
				Channel = "Security",
				TimeUtc = DateTime.UtcNow,
				UserName = "carol",
				SourceIpUnresolved = true,
			});
			db.SaveChanges();
		}

		using (AuditDbContext db = new(options))
		{
			RawEvent row = db.RawEvents.Single();
			Assert.True(row.SourceIpUnresolved);
		}
	}

	[Fact]
	public void Stage6Migration_AppliesOnTopOfStage5_PreservesRows()
	{
		using SqliteConnection connection = new("DataSource=:memory:");
		connection.Open();
		DbContextOptions<AuditDbContext> options = new DbContextOptionsBuilder<AuditDbContext>()
			.UseSqlite(connection)
			.Options;

		using (AuditDbContext db = new(options))
		{
			IMigrator migrator = db.GetService<IMigrator>();
			migrator.Migrate(Stage5Migration);
		}

		using (AuditDbContext db = new(options))
		{
			db.RawEvents.Add(new RawEvent
			{
				EventId = 4624,
				Channel = "Security",
				TimeUtc = DateTime.UtcNow,
				UserName = "bob",
				SourceIp = "203.0.113.10",
			});
			db.SaveChanges();
		}

		using (AuditDbContext db = new(options))
		{
			db.Database.Migrate();

			RawEvent row = db.RawEvents.Single();
			Assert.Equal("bob", row.UserName);
			Assert.False(row.SourceIpUnresolved);
		}
	}
}
