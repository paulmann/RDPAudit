/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 2.2.0
// File   : 20260814000000_Stage10IpShardsRetention.cs
// Project: RdpAudit.Core (RdpAudit.Core.Data.Migrations)
// Purpose: Adds IpEventSummary + IpEventTypeCounter tables, monotonic IngestionSequence,
//          EventCollectionAudit change-log table, per-event retention/config tables,
//          and the indexes required for O(1) IP summary lookup and shard reconciliation.
// Depends: AuditDbContext, EF Core 8+
// Extends: Whenever a new IP-attributed enrichment field is added, extend IpEventSummary
//          here and rev the migration id; do not mutate existing columns in place.

using Microsoft.EntityFrameworkCore.Migrations;

#nullable enable

namespace RdpAudit.Core.Data.Migrations;

/// <inheritdoc />
public sealed partial class Stage10IpShardsRetention : Migration
{
	// ── Public API ───────────────────────────────────────────────────────────────

	/// <inheritdoc />
	protected override void Up(MigrationBuilder migrationBuilder)
	{
		// ── IpEventSummary: one row per resolved source IP ───────────────────
		migrationBuilder.CreateTable(
			name: "IpEventSummary",
			columns: table => new
			{
				IpBinary16 = table.Column<byte[]>(type: "BLOB", fixedLength: true, maxLength: 16, nullable: false),
				IpText = table.Column<string>(type: "TEXT", maxLength: 45, nullable: false),
				AddressFamily = table.Column<int>(type: "INTEGER", nullable: false),
				FirstEventUtc = table.Column<long>(type: "INTEGER", nullable: false),
				FirstEventId = table.Column<int>(type: "INTEGER", nullable: false),
				FirstEventSequence = table.Column<long>(type: "INTEGER", nullable: false),
				FirstEventSnapshot = table.Column<byte[]>(type: "BLOB", nullable: false),
				LastEventUtc = table.Column<long>(type: "INTEGER", nullable: false),
				LastEventId = table.Column<int>(type: "INTEGER", nullable: false),
				LastEventSequence = table.Column<long>(type: "INTEGER", nullable: false),
				LastEventSnapshot = table.Column<byte[]>(type: "BLOB", nullable: false),
				TotalEventCount = table.Column<long>(type: "INTEGER", nullable: false, defaultValue: 0L),
				SuccessCount = table.Column<long>(type: "INTEGER", nullable: false, defaultValue: 0L),
				FailureCount = table.Column<long>(type: "INTEGER", nullable: false, defaultValue: 0L),
				ShardRelativePath = table.Column<string>(type: "TEXT", maxLength: 260, nullable: false),
				ShardRecordCount = table.Column<long>(type: "INTEGER", nullable: false, defaultValue: 0L),
				ShardBytes = table.Column<long>(type: "INTEGER", nullable: false, defaultValue: 0L),
				ShardFormatVersion = table.Column<int>(type: "INTEGER", nullable: false, defaultValue: 1),
				ShardEvictedCount = table.Column<long>(type: "INTEGER", nullable: false, defaultValue: 0L),
				ShardOldestRetainedUtc = table.Column<long>(type: "INTEGER", nullable: true),
				IsSubnetAggregate = table.Column<bool>(type: "INTEGER", nullable: false, defaultValue: false),
				Flags = table.Column<int>(type: "INTEGER", nullable: false, defaultValue: 0),
			},
			constraints: table =>
			{
				table.PrimaryKey("PK_IpEventSummary", x => x.IpBinary16);
			});

		migrationBuilder.CreateIndex(
			name: "IX_IpEventSummary_LastEventUtc",
			table: "IpEventSummary",
			column: "LastEventUtc");

		migrationBuilder.CreateIndex(
			name: "IX_IpEventSummary_IpText",
			table: "IpEventSummary",
			column: "IpText",
			unique: true);

		// ── IpEventTypeCounter: (IP, EventId) counter ────────────────────────
		migrationBuilder.CreateTable(
			name: "IpEventTypeCounter",
			columns: table => new
			{
				IpBinary16 = table.Column<byte[]>(type: "BLOB", fixedLength: true, maxLength: 16, nullable: false),
				EventId = table.Column<int>(type: "INTEGER", nullable: false),
				Count = table.Column<long>(type: "INTEGER", nullable: false, defaultValue: 0L),
				FirstUtc = table.Column<long>(type: "INTEGER", nullable: false),
				LastUtc = table.Column<long>(type: "INTEGER", nullable: false),
			},
			constraints: table =>
			{
				table.PrimaryKey("PK_IpEventTypeCounter", x => new { x.IpBinary16, x.EventId });
			});

		migrationBuilder.CreateIndex(
			name: "IX_IpEventTypeCounter_EventId_LastUtc",
			table: "IpEventTypeCounter",
			columns: new[] { "EventId", "LastUtc" });

		// ── IngestionSequence sidecar: monotonic seq shared with shards ──────
		// SQLite path: no true sequence type; use an INTEGER PRIMARY KEY table
		// touched by the writer under the same transaction.
		migrationBuilder.CreateTable(
			name: "IngestionSequence",
			columns: table => new
			{
				Id = table.Column<int>(type: "INTEGER", nullable: false)
					.Annotation("Sqlite:Autoincrement", false),
				NextValue = table.Column<long>(type: "INTEGER", nullable: false, defaultValue: 1L),
			},
			constraints: table => table.PrimaryKey("PK_IngestionSequence", x => x.Id));

		migrationBuilder.Sql("INSERT INTO IngestionSequence (Id, NextValue) VALUES (1, 1);");

		// ── EventCollectionAudit: SOC2 change log for the collection UI ──────
		migrationBuilder.CreateTable(
			name: "EventCollectionAudit",
			columns: table => new
			{
				Id = table.Column<long>(type: "INTEGER", nullable: false)
					.Annotation("Sqlite:Autoincrement", true),
				OccurredUtc = table.Column<long>(type: "INTEGER", nullable: false),
				InvokerSid = table.Column<string>(type: "TEXT", maxLength: 128, nullable: false),
				InvokerAccount = table.Column<string>(type: "TEXT", maxLength: 260, nullable: false),
				Kind = table.Column<int>(type: "INTEGER", nullable: false),
				EventId = table.Column<int>(type: "INTEGER", nullable: true),
				OldValue = table.Column<string>(type: "TEXT", maxLength: 512, nullable: true),
				NewValue = table.Column<string>(type: "TEXT", maxLength: 512, nullable: true),
				Note = table.Column<string>(type: "TEXT", maxLength: 512, nullable: true),
			},
			constraints: table => table.PrimaryKey("PK_EventCollectionAudit", x => x.Id));

		migrationBuilder.CreateIndex(
			name: "IX_EventCollectionAudit_OccurredUtc",
			table: "EventCollectionAudit",
			column: "OccurredUtc");

		// ── Per-event retention override table ───────────────────────────────
		migrationBuilder.CreateTable(
			name: "EventRetention",
			columns: table => new
			{
				EventId = table.Column<int>(type: "INTEGER", nullable: false),
				RetentionDays = table.Column<int>(type: "INTEGER", nullable: false),
				UpdatedUtc = table.Column<long>(type: "INTEGER", nullable: false),
			},
			constraints: table => table.PrimaryKey("PK_EventRetention", x => x.EventId));

		// ── Per-event enable/disable override table ──────────────────────────
		migrationBuilder.CreateTable(
			name: "EventEnablement",
			columns: table => new
			{
				EventId = table.Column<int>(type: "INTEGER", nullable: false),
				IsEnabled = table.Column<bool>(type: "INTEGER", nullable: false),
				UpdatedUtc = table.Column<long>(type: "INTEGER", nullable: false),
			},
			constraints: table => table.PrimaryKey("PK_EventEnablement", x => x.EventId));

		// ── RawEvents: monotonic sequence + optional shard back-reference ────
		migrationBuilder.AddColumn<long>(
			name: "IngestionSequence",
			table: "RawEvents",
			type: "INTEGER",
			nullable: false,
			defaultValue: 0L);

		migrationBuilder.AddColumn<int>(
			name: "EventLayer",
			table: "RawEvents",
			type: "INTEGER",
			nullable: false,
			defaultValue: 0);

		migrationBuilder.AddColumn<byte[]>(
			name: "SourceIpBinary",
			table: "RawEvents",
			type: "BLOB",
			fixedLength: true,
			maxLength: 16,
			nullable: true);

		migrationBuilder.CreateIndex(
			name: "IX_RawEvents_IngestionSequence",
			table: "RawEvents",
			column: "IngestionSequence",
			unique: true);

		migrationBuilder.CreateIndex(
			name: "IX_RawEvents_SourceIpBinary_TimeUtc",
			table: "RawEvents",
			columns: new[] { "SourceIpBinary", "TimeUtc" });
	}

	/// <inheritdoc />
	protected override void Down(MigrationBuilder migrationBuilder)
	{
		migrationBuilder.DropIndex("IX_RawEvents_SourceIpBinary_TimeUtc", "RawEvents");
		migrationBuilder.DropIndex("IX_RawEvents_IngestionSequence", "RawEvents");
		migrationBuilder.DropColumn("SourceIpBinary", "RawEvents");
		migrationBuilder.DropColumn("EventLayer", "RawEvents");
		migrationBuilder.DropColumn("IngestionSequence", "RawEvents");
		migrationBuilder.DropTable("EventEnablement");
		migrationBuilder.DropTable("EventRetention");
		migrationBuilder.DropTable("EventCollectionAudit");
		migrationBuilder.DropTable("IngestionSequence");
		migrationBuilder.DropTable("IpEventTypeCounter");
		migrationBuilder.DropTable("IpEventSummary");
	}
}
