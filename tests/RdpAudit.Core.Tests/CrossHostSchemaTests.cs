// File:    tests/RdpAudit.Core.Tests/CrossHostSchemaTests.cs
// Module:  RdpAudit.Core.Tests
// Purpose: Validates the Stage 13 cross-host correlation schema - EF mapping of the four entities,
//          fresh-database migration, the down-migration path (tables removed, Stage 12 tables
//          preserved), unique constraints (fact DedupKey, per-rule chain key, host state host name)
//          and the chain -> link cascade delete.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;
using RdpAudit.Core.CrossHost;
using RdpAudit.Core.Data;
using RdpAudit.Core.Models;
using Xunit;

namespace RdpAudit.Core.Tests;

public class CrossHostSchemaTests
{
	private const string Stage12Migration = "20260814082809_Stage12PartialIngestionSequenceUnique";
	private const string Stage13MigrationSuffix = "Stage13CrossHostCorrelation";
	private const string Stage14MigrationSuffix = "Stage14ChainAlertLinking";

	private static DbContextOptions<AuditDbContext> CreateOptions(SqliteConnection connection) =>
		new DbContextOptionsBuilder<AuditDbContext>().UseSqlite(connection).Options;

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

	private static void EnableForeignKeys(SqliteConnection connection)
	{
		using SqliteCommand cmd = connection.CreateCommand();
		cmd.CommandText = "PRAGMA foreign_keys = ON;";
		cmd.ExecuteNonQuery();
	}

	[Fact]
	public void MigrationsAssembly_DeclaresStage13Migration()
	{
		using SqliteConnection connection = new("DataSource=:memory:");
		connection.Open();

		using AuditDbContext db = new(CreateOptions(connection));
		IEnumerable<string> migrations = db.Database.GetMigrations();

		Assert.Contains(migrations, m => m.EndsWith("_" + Stage13MigrationSuffix, StringComparison.Ordinal));
		Assert.Contains(migrations, m => m.EndsWith("_" + Stage14MigrationSuffix, StringComparison.Ordinal));
		Assert.Contains(migrations, m => m == Stage12Migration);
	}

	[Fact]
	public void Migrate_OnFreshDatabase_CreatesCrossHostTables()
	{
		using SqliteConnection connection = new("DataSource=:memory:");
		connection.Open();

		using AuditDbContext db = new(CreateOptions(connection));
		db.Database.Migrate();

		HashSet<string> tables = ListTables(connection);
		Assert.Contains("CrossHostFacts", tables);
		Assert.Contains("CrossHostLinks", tables);
		Assert.Contains("CrossHostChains", tables);
		Assert.Contains("CrossHostHostStates", tables);
	}

	[Fact]
	public void Stage13Migration_DownRemovesCrossHostTablesAndKeepsStage12()
	{
		using SqliteConnection connection = new("DataSource=:memory:");
		connection.Open();

		using (AuditDbContext db = new(CreateOptions(connection)))
		{
			db.Database.Migrate();
		}

		using (AuditDbContext db = new(CreateOptions(connection)))
		{
			IMigrator migrator = db.GetService<IMigrator>();
			migrator.Migrate(Stage12Migration);
		}

		HashSet<string> tables = ListTables(connection);
		Assert.DoesNotContain("CrossHostFacts", tables);
		Assert.DoesNotContain("CrossHostLinks", tables);
		Assert.DoesNotContain("CrossHostChains", tables);
		Assert.DoesNotContain("CrossHostHostStates", tables);
		Assert.Contains("RawEvents", tables);
		Assert.Contains("Addresses", tables);
	}

	[Fact]
	public void CrossHostFact_PersistsAndReads()
	{
		using SqliteConnection connection = new("DataSource=:memory:");
		connection.Open();

		DbContextOptions<AuditDbContext> options = CreateOptions(connection);
		using (AuditDbContext db = new(options))
		{
			db.Database.EnsureCreated();
			db.CrossHostFacts.Add(new CrossHostFact
			{
				HostName = "SRV-A",
				TimeUtc = new DateTime(2026, 9, 10, 12, 0, 0, DateTimeKind.Utc),
				UserName = "CORP\\alice",
				NormalizedUserName = "alice",
				SourceIp = "198.51.100.7",
				LogonType = 10,
				Kind = CrossHostFactKind.FailedLogon,
				EventId = 4625,
				DedupKey = "aa",
				IngestedUtc = DateTime.UtcNow,
			});
			db.SaveChanges();
		}

		using (AuditDbContext db = new(options))
		{
			CrossHostFact? row = db.CrossHostFacts.Single();
			Assert.NotNull(row);
			Assert.Equal("SRV-A", row!.HostName);
			Assert.Equal("alice", row.NormalizedUserName);
			Assert.Equal("198.51.100.7", row.SourceIp);
			Assert.Equal(10, row.LogonType);
			Assert.Equal(CrossHostFactKind.FailedLogon, row.Kind);
			Assert.Equal(4625, row.EventId);
			Assert.Equal("aa", row.DedupKey);
		}
	}

	[Fact]
	public void CrossHostFact_DedupKeyIsUnique()
	{
		using SqliteConnection connection = new("DataSource=:memory:");
		connection.Open();

		DbContextOptions<AuditDbContext> options = CreateOptions(connection);
		using (AuditDbContext db = new(options))
		{
			db.Database.EnsureCreated();
			DateTime now = DateTime.UtcNow;
			db.CrossHostFacts.Add(new CrossHostFact
			{
				HostName = "SRV-A",
				TimeUtc = now,
				NormalizedUserName = "bob",
				Kind = CrossHostFactKind.FailedLogon,
				EventId = 4625,
				DedupKey = "same-key",
				IngestedUtc = now,
			});
			db.CrossHostFacts.Add(new CrossHostFact
			{
				HostName = "SRV-B",
				TimeUtc = now.AddSeconds(1),
				NormalizedUserName = "bob",
				Kind = CrossHostFactKind.FailedLogon,
				EventId = 4625,
				DedupKey = "same-key",
				IngestedUtc = now,
			});

			Assert.Throws<DbUpdateException>(() => db.SaveChanges());
		}
	}

	[Fact]
	public void CrossHostHostState_HostNameIsUnique_AndRoundTrips()
	{
		using SqliteConnection connection = new("DataSource=:memory:");
		connection.Open();

		DbContextOptions<AuditDbContext> options = CreateOptions(connection);
		using (AuditDbContext db = new(options))
		{
			db.Database.EnsureCreated();
			DateTime now = DateTime.UtcNow;
			db.CrossHostHostStates.Add(new CrossHostHostState
			{
				HostName = "SRV-A",
				Availability = CrossHostAvailability.Unavailable,
				LastError = "pipe timeout",
				LastPolledUtc = now,
			});
			db.SaveChanges();

			db.ChangeTracker.Clear();
			db.CrossHostHostStates.Add(new CrossHostHostState
			{
				HostName = "SRV-A",
				Availability = CrossHostAvailability.Available,
				LastSeenUtc = now,
				LastPolledUtc = now,
			});

			Assert.Throws<DbUpdateException>(() => db.SaveChanges());
		}

		using (AuditDbContext db = new(options))
		{
			CrossHostHostState row = db.CrossHostHostStates.Single();
			Assert.Equal(CrossHostAvailability.Unavailable, row.Availability);
			Assert.Equal("pipe timeout", row.LastError);
		}
	}

	[Fact]
	public void CrossHostChain_WithLinks_PersistsAndCascades()
	{
		using SqliteConnection connection = new("DataSource=:memory:");
		connection.Open();
		EnableForeignKeys(connection);

		DbContextOptions<AuditDbContext> options = CreateOptions(connection);
		long chainId;
		using (AuditDbContext db = new(options))
		{
			db.Database.EnsureCreated();
			DateTime now = DateTime.UtcNow;
			CrossHostChain chain = new()
			{
				ChainKey = "chain-key",
				RuleId = "RDP_LATERAL_MOVEMENT",
				NormalizedUserName = "alice",
				FirstSeenUtc = now,
				LastSeenUtc = now,
				Score = 80,
				FailedAttemptCount = 5,
				DetectedUtc = now,
			};
			chain.Links.Add(new CrossHostLink { Ordinal = 0, HostName = "SRV-A", Kind = CrossHostFactKind.FailedLogon, EventId = 4625, TimeUtc = now });
			chain.Links.Add(new CrossHostLink { Ordinal = 1, HostName = "SRV-B", Kind = CrossHostFactKind.SuccessfulLogon, EventId = 4624, TimeUtc = now.AddMinutes(1) });
			db.CrossHostChains.Add(chain);
			db.SaveChanges();
			chainId = chain.Id;
		}

		using (AuditDbContext db = new(options))
		{
			CrossHostChain stored = db.CrossHostChains.Include(c => c.Links).Single();
			Assert.Equal("RDP_LATERAL_MOVEMENT", stored.RuleId);
			Assert.Equal(2, stored.Links.Count);
			Assert.Equal(80, stored.Score);
		}

		// Delete the chain via raw SQL: the ON DELETE CASCADE must remove the links at the DB level.
		using (SqliteCommand cmd = connection.CreateCommand())
		{
			cmd.CommandText = "DELETE FROM CrossHostChains WHERE Id = $id";
			cmd.Parameters.AddWithValue("$id", chainId);
			Assert.Equal(1, cmd.ExecuteNonQuery());
		}

		using (AuditDbContext db = new(options))
		{
			Assert.Empty(db.CrossHostChains);
			Assert.Empty(db.CrossHostLinks);
		}
	}
}
