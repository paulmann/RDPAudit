/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 2.0.0
// File   : Stage17EventDeletionLedgerSchemaTests.cs
// Project: RdpAudit.Core.Tests (RdpAudit.Core.Tests)
// Purpose: Proves the Stage 17 migration is the schema the EF model describes. It applies the WHOLE
//          migration chain to a temporary database (never EnsureCreated), then checks that the ledger
//          table, its exact column set and its three indexes exist, that the chain and the model agree
//          on the complete table set, that the table round-trips every documented field, and that the
//          Down migration removes only the ledger table.
// Depends: AuditDbContext, EventDeletionLedger, Microsoft.Data.Sqlite, Xunit
// Extends: Extend the expected-column assertion whenever the ledger gains a column.

using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Metadata;
using Microsoft.EntityFrameworkCore.Migrations;
using RdpAudit.Core.Data;
using RdpAudit.Core.Models;
using Xunit;

namespace RdpAudit.Core.Tests;

/// <summary>Migration and schema tests for the Stage 17 evidence-deletion ledger.</summary>
public class Stage17EventDeletionLedgerSchemaTests
{
	private const string PreviousMigration = "20260913123419_Stage16ProcessMonitoring";

	private static readonly string[] ExpectedLedgerColumns =
	[
		"Id",
		"EventCode",
		"Scope",
		"IpBinary16",
		"WindowStartUtc",
		"WindowEndUtc",
		"RowsDeleted",
		"Trigger",
		"RuleVersion",
		"Reason",
		"InitiatedBy",
		"CreatedUtc",
		// Stage 18 appended the hash-chain link. The column set is asserted exactly, so a future change to
		// the ledger shape has to be a deliberate edit here rather than a silent schema drift.
		"EntryHash",
		"PreviousHash",
	];

	private static readonly string[] ExpectedLedgerIndexes =
	[
		"IX_EventDeletionLedger_CreatedUtc",
		"IX_EventDeletionLedger_EventCode_CreatedUtc",
		"IX_EventDeletionLedger_IpBinary16",
	];

	private static DbContextOptions<AuditDbContext> OptionsFor(SqliteConnection connection)
		=> new DbContextOptionsBuilder<AuditDbContext>().UseSqlite(connection).Options;

	[Fact]
	public void MigrationsAssembly_DeclaresStage17Migration()
	{
		using SqliteConnection connection = new("DataSource=:memory:");
		connection.Open();

		using AuditDbContext db = new(OptionsFor(connection));
		Assert.Contains(
			db.Database.GetMigrations(),
			m => m.EndsWith("_Stage17EventDeletionLedger", StringComparison.Ordinal));
	}

	[Fact]
	public void Migrate_OnFreshDatabase_AppliesTheWholeChain()
	{
		using SqliteConnection connection = new("DataSource=:memory:");
		connection.Open();

		using (AuditDbContext db = new(OptionsFor(connection)))
		{
			db.Database.Migrate();
			Assert.Empty(db.Database.GetPendingMigrations());
		}

		HashSet<string> tables = ReadTableNames(connection);
		Assert.Contains("EventDeletionLedger", tables);
		Assert.Contains("RawEvents", tables);
		Assert.Contains("AuthAttemptFacts", tables);
		Assert.Contains("ProcessObservations", tables);
	}

	[Fact]
	public void Migrate_OnFreshDatabase_CreatesTheLedgerWithTheExactColumnSet()
	{
		using SqliteConnection connection = new("DataSource=:memory:");
		connection.Open();

		using (AuditDbContext db = new(OptionsFor(connection)))
		{
			db.Database.Migrate();
		}

		List<string> columns = ReadLedgerColumns(connection);
		Assert.Equal(ExpectedLedgerColumns, columns);
	}

	[Fact]
	public void Migrate_OnFreshDatabase_CreatesEveryLedgerIndex()
	{
		using SqliteConnection connection = new("DataSource=:memory:");
		connection.Open();

		using (AuditDbContext db = new(OptionsFor(connection)))
		{
			db.Database.Migrate();
		}

		HashSet<string> indexes = ReadLedgerIndexes(connection);
		foreach (string expected in ExpectedLedgerIndexes)
		{
			Assert.Contains(expected, indexes);
		}
	}

	[Fact]
	public void MigrationChain_AndTheModel_AgreeOnTheTableSet()
	{
		using SqliteConnection migrated = new("DataSource=:memory:");
		migrated.Open();
		using (AuditDbContext db = new(OptionsFor(migrated)))
		{
			db.Database.Migrate();
		}

		using SqliteConnection created = new("DataSource=:memory:");
		created.Open();
		using (AuditDbContext db = new(OptionsFor(created)))
		{
			db.Database.EnsureCreated();
		}

		HashSet<string> migratedTables = ReadTableNames(migrated);
		HashSet<string> modelTables = ReadTableNames(created);
		migratedTables.SymmetricExceptWith(modelTables);
		Assert.Empty(migratedTables);
	}

	[Fact]
	public void MigrationChain_AndTheModel_AgreeOnTheLedgerColumns()
	{
		using SqliteConnection connection = new("DataSource=:memory:");
		connection.Open();

		using (AuditDbContext db = new(OptionsFor(connection)))
		{
			db.Database.Migrate();
		}

		using AuditDbContext model = new(OptionsFor(connection));
		IEntityType? entity = model.Model.FindEntityType(typeof(EventDeletionLedger));
		Assert.NotNull(entity);
		Assert.Equal("EventDeletionLedger", entity.GetTableName());

		string[] modelColumns = entity.GetProperties()
			.Select(property => property.GetColumnName())
			.OrderBy(name => name, StringComparer.Ordinal)
			.ToArray();
		string[] databaseColumns = [.. ReadLedgerColumns(connection).OrderBy(name => name, StringComparer.Ordinal)];

		Assert.Equal(modelColumns, databaseColumns);
	}

	[Fact]
	public void DownMigration_RemovesOnlyTheLedgerTable()
	{
		using SqliteConnection connection = new("DataSource=:memory:");
		connection.Open();

		using (AuditDbContext db = new(OptionsFor(connection)))
		{
			db.Database.Migrate();
			Assert.Contains("EventDeletionLedger", ReadTableNames(connection));
			db.GetService<IMigrator>().Migrate(PreviousMigration);
		}

		HashSet<string> tables = ReadTableNames(connection);
		Assert.DoesNotContain("EventDeletionLedger", tables);
		Assert.Contains("RawEvents", tables);
		Assert.Contains("AuthAttemptFacts", tables);
		Assert.Contains("ProcessObservations", tables);
		Assert.Contains("OperationLogs", tables);
	}

	[Fact]
	public void DbContext_ExposesTheLedgerDbSet()
	{
		using SqliteConnection connection = new("DataSource=:memory:");
		connection.Open();
		using AuditDbContext db = new(OptionsFor(connection));
		Assert.NotNull(db.EventDeletionLedger);
	}

	[Fact]
	public void Ledger_RoundTripsEveryDocumentedField()
	{
		using SqliteConnection connection = new("DataSource=:memory:");
		connection.Open();
		DbContextOptions<AuditDbContext> options = OptionsFor(connection);

		using (AuditDbContext db = new(options))
		{
			db.Database.Migrate();
			db.EventDeletionLedger.Add(new EventDeletionLedger
			{
				EventCode = 4625,
				Scope = EventDeletionScope.PerIp,
				IpBinary16 = [0xC0, 0xA8, 0x01, 0x02],
				WindowStartUtc = new DateTime(2026, 8, 1, 0, 0, 0, DateTimeKind.Utc),
				WindowEndUtc = new DateTime(2026, 8, 9, 23, 59, 59, DateTimeKind.Utc),
				RowsDeleted = 412_300,
				Trigger = EventDeletionTrigger.DatabaseBytes,
				RuleVersion = 1,
				Reason = "IDR-1 information-density retention; trigger=DatabaseBytes; code=Security/4625",
				InitiatedBy = "Service",
				CreatedUtc = new DateTime(2026, 9, 14, 12, 0, 0, DateTimeKind.Utc),
			});
			db.SaveChanges();
		}

		using (AuditDbContext db = new(options))
		{
			EventDeletionLedger row = Assert.Single(db.EventDeletionLedger);
			Assert.Equal(4625, row.EventCode);
			Assert.Equal(EventDeletionScope.PerIp, row.Scope);
			Assert.Equal([0xC0, 0xA8, 0x01, 0x02], row.IpBinary16);
			Assert.Equal(new DateTime(2026, 8, 1, 0, 0, 0, DateTimeKind.Utc), row.WindowStartUtc);
			Assert.Equal(new DateTime(2026, 8, 9, 23, 59, 59, DateTimeKind.Utc), row.WindowEndUtc);
			Assert.Equal(412_300L, row.RowsDeleted);
			Assert.Equal(EventDeletionTrigger.DatabaseBytes, row.Trigger);
			Assert.Equal(1, row.RuleVersion);
			Assert.Contains("IDR-1", row.Reason);
			Assert.Equal("Service", row.InitiatedBy);
			Assert.Equal(new DateTime(2026, 9, 14, 12, 0, 0, DateTimeKind.Utc), row.CreatedUtc);
		}
	}

	[Fact]
	public void Ledger_AcceptsEveryDocumentedEnumOrdinal()
	{
		using SqliteConnection connection = new("DataSource=:memory:");
		connection.Open();
		DbContextOptions<AuditDbContext> options = OptionsFor(connection);

		using (AuditDbContext db = new(options))
		{
			db.Database.Migrate();
			foreach (EventDeletionScope scope in Enum.GetValues<EventDeletionScope>())
			{
				foreach (EventDeletionTrigger trigger in Enum.GetValues<EventDeletionTrigger>())
				{
					db.EventDeletionLedger.Add(new EventDeletionLedger
					{
						EventCode = 4625,
						Scope = scope,
						WindowStartUtc = DateTime.UnixEpoch,
						WindowEndUtc = DateTime.UnixEpoch,
						RowsDeleted = 0,
						Trigger = trigger,
						RuleVersion = 1,
						Reason = "test",
						InitiatedBy = "Service",
						CreatedUtc = DateTime.UnixEpoch,
					});
				}
			}

			db.SaveChanges();
		}

		using (AuditDbContext db = new(options))
		{
			int expected = Enum.GetValues<EventDeletionScope>().Length * Enum.GetValues<EventDeletionTrigger>().Length;
			Assert.Equal(expected, db.EventDeletionLedger.Count());
		}
	}

	[Fact]
	public void Ledger_AllowsANullIpForAHostWideDeletion()
	{
		using SqliteConnection connection = new("DataSource=:memory:");
		connection.Open();
		DbContextOptions<AuditDbContext> options = OptionsFor(connection);

		using (AuditDbContext db = new(options))
		{
			db.Database.Migrate();
			db.EventDeletionLedger.Add(new EventDeletionLedger
			{
				EventCode = 4624,
				Scope = EventDeletionScope.Global,
				IpBinary16 = null,
				WindowStartUtc = DateTime.UnixEpoch,
				WindowEndUtc = DateTime.UnixEpoch,
				RowsDeleted = 1,
				Trigger = EventDeletionTrigger.RawEventRows,
				RuleVersion = 1,
				Reason = "test",
				InitiatedBy = "Service",
				CreatedUtc = DateTime.UnixEpoch,
			});
			db.SaveChanges();
		}

		using (AuditDbContext db = new(options))
		{
			EventDeletionLedger row = Assert.Single(db.EventDeletionLedger);
			Assert.Null(row.IpBinary16);
			Assert.Equal(EventDeletionScope.Global, row.Scope);
		}
	}

	private static HashSet<string> ReadTableNames(SqliteConnection connection)
	{
		using SqliteCommand command = connection.CreateCommand();
		command.CommandText =
			"SELECT name FROM sqlite_master WHERE type='table' " +
			"AND name NOT LIKE 'sqlite_%' AND name NOT LIKE '__EF%';";
		HashSet<string> names = new(StringComparer.Ordinal);
		using SqliteDataReader reader = command.ExecuteReader();
		while (reader.Read())
		{
			names.Add(reader.GetString(0));
		}

		return names;
	}

	private static List<string> ReadLedgerColumns(SqliteConnection connection)
	{
		using SqliteCommand command = connection.CreateCommand();
		command.CommandText = "PRAGMA table_info(\"EventDeletionLedger\");";
		List<string> columns = [];
		using SqliteDataReader reader = command.ExecuteReader();
		while (reader.Read())
		{
			columns.Add(reader.GetString(1));
		}

		return columns;
	}

	private static HashSet<string> ReadLedgerIndexes(SqliteConnection connection)
	{
		using SqliteCommand command = connection.CreateCommand();
		command.CommandText =
			"SELECT name FROM sqlite_master WHERE type='index' AND tbl_name='EventDeletionLedger';";
		HashSet<string> names = new(StringComparer.Ordinal);
		using SqliteDataReader reader = command.ExecuteReader();
		while (reader.Read())
		{
			names.Add(reader.GetString(0));
		}

		return names;
	}
}
