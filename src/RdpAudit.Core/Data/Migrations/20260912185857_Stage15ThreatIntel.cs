using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace RdpAudit.Core.Data.Migrations
{
    /// <inheritdoc />
    public partial class Stage15ThreatIntel : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "ThreatIntelLookups",
                columns: table => new
                {
                    Ip = table.Column<string>(type: "TEXT", maxLength: 45, nullable: false),
                    LookedUpUtc = table.Column<DateTime>(type: "TEXT", nullable: false),
                    Outcome = table.Column<int>(type: "INTEGER", nullable: false),
                    Score = table.Column<int>(type: "INTEGER", nullable: true),
                    TotalReports = table.Column<long>(type: "INTEGER", nullable: true),
                    IsWhitelisted = table.Column<bool>(type: "INTEGER", nullable: true),
                    IsPublic = table.Column<bool>(type: "INTEGER", nullable: true),
                    UsageType = table.Column<string>(type: "TEXT", maxLength: 128, nullable: true),
                    CountryCode = table.Column<string>(type: "TEXT", maxLength: 8, nullable: true),
                    NextRetryUtc = table.Column<DateTime>(type: "TEXT", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_ThreatIntelLookups", x => x.Ip);
                });

            migrationBuilder.CreateTable(
                name: "ThreatIntelUsageCounters",
                columns: table => new
                {
                    DayDateUtc = table.Column<string>(type: "TEXT", maxLength: 10, nullable: false),
                    Count = table.Column<int>(type: "INTEGER", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_ThreatIntelUsageCounters", x => x.DayDateUtc);
                });

            migrationBuilder.CreateIndex(
                name: "IX_ThreatIntelLookups_LookedUpUtc",
                table: "ThreatIntelLookups",
                column: "LookedUpUtc");

            migrationBuilder.CreateIndex(
                name: "IX_ThreatIntelLookups_NextRetryUtc",
                table: "ThreatIntelLookups",
                column: "NextRetryUtc");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "ThreatIntelLookups");

            migrationBuilder.DropTable(
                name: "ThreatIntelUsageCounters");
        }
    }
}
