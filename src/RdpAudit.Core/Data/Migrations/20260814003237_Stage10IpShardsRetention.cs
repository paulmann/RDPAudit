// File:    src/RdpAudit.Core/Data/Migrations/20260814003237_Stage10IpShardsRetention.cs
// Module:  RdpAudit.Core.Data.Migrations
// Purpose: Stage 10 — adds per-IP aggregate tables (IpEventSummary, IpEventTypeCounter), the durable
//          IngestionSequence counter, per-event retention and enablement tables, the event-collection
//          audit trail, and the RawEvents columns that back sharded storage (IngestionSequence,
//          EventLayer, SourceIpBinary) together with their lookup indexes.
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace RdpAudit.Core.Data.Migrations
{
    /// <inheritdoc />
    public partial class Stage10IpShardsRetention : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<int>(
                name: "EventLayer",
                table: "RawEvents",
                type: "INTEGER",
                nullable: false,
                defaultValue: 0);

            migrationBuilder.AddColumn<long>(
                name: "IngestionSequence",
                table: "RawEvents",
                type: "INTEGER",
                nullable: false,
                defaultValue: 0L);

            migrationBuilder.AddColumn<byte[]>(
                name: "SourceIpBinary",
                table: "RawEvents",
                type: "BLOB",
                fixedLength: true,
                maxLength: 16,
                nullable: true);

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
                    Note = table.Column<string>(type: "TEXT", maxLength: 512, nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_EventCollectionAudit", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "EventEnablement",
                columns: table => new
                {
                    EventId = table.Column<int>(type: "INTEGER", nullable: false),
                    IsEnabled = table.Column<bool>(type: "INTEGER", nullable: false),
                    UpdatedUtc = table.Column<long>(type: "INTEGER", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_EventEnablement", x => x.EventId);
                });

            migrationBuilder.CreateTable(
                name: "EventRetention",
                columns: table => new
                {
                    EventId = table.Column<int>(type: "INTEGER", nullable: false),
                    RetentionDays = table.Column<int>(type: "INTEGER", nullable: false),
                    UpdatedUtc = table.Column<long>(type: "INTEGER", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_EventRetention", x => x.EventId);
                });

            migrationBuilder.CreateTable(
                name: "IngestionSequence",
                columns: table => new
                {
                    Id = table.Column<int>(type: "INTEGER", nullable: false),
                    NextValue = table.Column<long>(type: "INTEGER", nullable: false, defaultValue: 1L)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_IngestionSequence", x => x.Id);
                });

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
                    Flags = table.Column<int>(type: "INTEGER", nullable: false, defaultValue: 0)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_IpEventSummary", x => x.IpBinary16);
                });

            migrationBuilder.CreateTable(
                name: "IpEventTypeCounter",
                columns: table => new
                {
                    IpBinary16 = table.Column<byte[]>(type: "BLOB", fixedLength: true, maxLength: 16, nullable: false),
                    EventId = table.Column<int>(type: "INTEGER", nullable: false),
                    Count = table.Column<long>(type: "INTEGER", nullable: false, defaultValue: 0L),
                    FirstUtc = table.Column<long>(type: "INTEGER", nullable: false),
                    LastUtc = table.Column<long>(type: "INTEGER", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_IpEventTypeCounter", x => new { x.IpBinary16, x.EventId });
                });

            migrationBuilder.InsertData(
                table: "IngestionSequence",
                columns: new[] { "Id", "NextValue" },
                values: new object[] { 1, 1L });

            migrationBuilder.CreateIndex(
                name: "IX_RawEvents_IngestionSequence",
                table: "RawEvents",
                column: "IngestionSequence",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_RawEvents_SourceIpBinary_TimeUtc",
                table: "RawEvents",
                columns: new[] { "SourceIpBinary", "TimeUtc" });

            migrationBuilder.CreateIndex(
                name: "IX_EventCollectionAudit_OccurredUtc",
                table: "EventCollectionAudit",
                column: "OccurredUtc");

            migrationBuilder.CreateIndex(
                name: "IX_IpEventSummary_IpText",
                table: "IpEventSummary",
                column: "IpText",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_IpEventSummary_LastEventUtc",
                table: "IpEventSummary",
                column: "LastEventUtc");

            migrationBuilder.CreateIndex(
                name: "IX_IpEventTypeCounter_EventId_LastUtc",
                table: "IpEventTypeCounter",
                columns: new[] { "EventId", "LastUtc" });
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "EventCollectionAudit");

            migrationBuilder.DropTable(
                name: "EventEnablement");

            migrationBuilder.DropTable(
                name: "EventRetention");

            migrationBuilder.DropTable(
                name: "IngestionSequence");

            migrationBuilder.DropTable(
                name: "IpEventSummary");

            migrationBuilder.DropTable(
                name: "IpEventTypeCounter");

            migrationBuilder.DropIndex(
                name: "IX_RawEvents_IngestionSequence",
                table: "RawEvents");

            migrationBuilder.DropIndex(
                name: "IX_RawEvents_SourceIpBinary_TimeUtc",
                table: "RawEvents");

            migrationBuilder.DropColumn(
                name: "EventLayer",
                table: "RawEvents");

            migrationBuilder.DropColumn(
                name: "IngestionSequence",
                table: "RawEvents");

            migrationBuilder.DropColumn(
                name: "SourceIpBinary",
                table: "RawEvents");
        }
    }
}
