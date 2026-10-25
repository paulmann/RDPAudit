using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace RdpAudit.Core.Data.Migrations
{
    /// <inheritdoc />
    public partial class Stage16ProcessMonitoring : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "KnownProcesses",
                columns: table => new
                {
                    Id = table.Column<long>(type: "INTEGER", nullable: false)
                        .Annotation("Sqlite:Autoincrement", true),
                    ProcessName = table.Column<string>(type: "TEXT", maxLength: 260, nullable: false),
                    UserCategory = table.Column<int>(type: "INTEGER", nullable: false),
                    UserName = table.Column<string>(type: "TEXT", maxLength: 256, nullable: false),
                    FirstObservedUtc = table.Column<DateTime>(type: "TEXT", nullable: false),
                    LastObservedUtc = table.Column<DateTime>(type: "TEXT", nullable: false),
                    ObservationCount = table.Column<long>(type: "INTEGER", nullable: false),
                    FirstObservedProcessId = table.Column<long>(type: "INTEGER", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_KnownProcesses", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "ProcessAlertResponses",
                columns: table => new
                {
                    AlertId = table.Column<long>(type: "INTEGER", nullable: false)
                        .Annotation("Sqlite:Autoincrement", true),
                    SessionId = table.Column<int>(type: "INTEGER", nullable: false),
                    Status = table.Column<int>(type: "INTEGER", nullable: false),
                    ResultText = table.Column<string>(type: "TEXT", maxLength: 2048, nullable: true),
                    RequestedAtUtc = table.Column<DateTime>(type: "TEXT", nullable: false),
                    CompletedAtUtc = table.Column<DateTime>(type: "TEXT", nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_ProcessAlertResponses", x => x.AlertId);
                });

            migrationBuilder.CreateTable(
                name: "ProcessObservations",
                columns: table => new
                {
                    Id = table.Column<long>(type: "INTEGER", nullable: false)
                        .Annotation("Sqlite:Autoincrement", true),
                    ObservedUtc = table.Column<DateTime>(type: "TEXT", nullable: false),
                    ProcessName = table.Column<string>(type: "TEXT", maxLength: 260, nullable: false),
                    UserName = table.Column<string>(type: "TEXT", maxLength: 256, nullable: true),
                    SessionId = table.Column<int>(type: "INTEGER", nullable: true),
                    RawEventId = table.Column<long>(type: "INTEGER", nullable: false),
                    Alerted = table.Column<bool>(type: "INTEGER", nullable: false),
                    IsForced = table.Column<bool>(type: "INTEGER", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_ProcessObservations", x => x.Id);
                });

            migrationBuilder.CreateIndex(
                name: "IX_KnownProcesses_LastObservedUtc",
                table: "KnownProcesses",
                column: "LastObservedUtc");

            migrationBuilder.CreateIndex(
                name: "IX_KnownProcesses_ProcessName_UserCategory_UserName",
                table: "KnownProcesses",
                columns: new[] { "ProcessName", "UserCategory", "UserName" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_ProcessAlertResponses_RequestedAtUtc",
                table: "ProcessAlertResponses",
                column: "RequestedAtUtc");

            migrationBuilder.CreateIndex(
                name: "IX_ProcessAlertResponses_Status",
                table: "ProcessAlertResponses",
                column: "Status");

            migrationBuilder.CreateIndex(
                name: "IX_ProcessObservations_ObservedUtc",
                table: "ProcessObservations",
                column: "ObservedUtc");

            migrationBuilder.CreateIndex(
                name: "IX_ProcessObservations_ProcessName",
                table: "ProcessObservations",
                column: "ProcessName");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "KnownProcesses");

            migrationBuilder.DropTable(
                name: "ProcessAlertResponses");

            migrationBuilder.DropTable(
                name: "ProcessObservations");
        }
    }
}
