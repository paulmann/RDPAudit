using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace RdpAudit.Core.Data.Migrations
{
    /// <inheritdoc />
    public partial class Stage17EventDeletionLedger : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "EventDeletionLedger",
                columns: table => new
                {
                    Id = table.Column<long>(type: "INTEGER", nullable: false)
                        .Annotation("Sqlite:Autoincrement", true),
                    EventCode = table.Column<int>(type: "INTEGER", nullable: false),
                    Scope = table.Column<int>(type: "INTEGER", nullable: false),
                    IpBinary16 = table.Column<byte[]>(type: "BLOB", fixedLength: true, maxLength: 16, nullable: true),
                    WindowStartUtc = table.Column<DateTime>(type: "TEXT", nullable: false),
                    WindowEndUtc = table.Column<DateTime>(type: "TEXT", nullable: false),
                    RowsDeleted = table.Column<long>(type: "INTEGER", nullable: false),
                    Trigger = table.Column<int>(type: "INTEGER", nullable: false),
                    RuleVersion = table.Column<int>(type: "INTEGER", nullable: false),
                    Reason = table.Column<string>(type: "TEXT", maxLength: 512, nullable: false),
                    InitiatedBy = table.Column<string>(type: "TEXT", maxLength: 256, nullable: false),
                    CreatedUtc = table.Column<DateTime>(type: "TEXT", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_EventDeletionLedger", x => x.Id);
                });

            migrationBuilder.CreateIndex(
                name: "IX_EventDeletionLedger_CreatedUtc",
                table: "EventDeletionLedger",
                column: "CreatedUtc");

            migrationBuilder.CreateIndex(
                name: "IX_EventDeletionLedger_EventCode_CreatedUtc",
                table: "EventDeletionLedger",
                columns: new[] { "EventCode", "CreatedUtc" });

            migrationBuilder.CreateIndex(
                name: "IX_EventDeletionLedger_IpBinary16",
                table: "EventDeletionLedger",
                column: "IpBinary16");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "EventDeletionLedger");
        }
    }
}
