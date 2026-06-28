// File:    src/RdpAudit.Core/Data/Migrations/20260610104031_V133OperationLogs.cs
// Module:  RdpAudit.Core.Data.Migrations
// Purpose: v1.3.3 — creates the durable OperationLogs table (operator-facing audit trail of program
//          actions: bans, firewall, settings, maintenance, IPC outcomes, background jobs, startup /
//          crash diagnostics) with indexes on TimeUtc, {Severity,TimeUtc}, {Source,TimeUtc} and
//          {Operation,TimeUtc} so the Logs tab can run bounded, filtered, paged queries without table
//          scans. Detail columns (DetailsJson, StackTrace) are nullable and populated only in DEBUG.
// Extends: Microsoft.EntityFrameworkCore.Migrations.Migration
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace RdpAudit.Core.Data.Migrations
{
    /// <inheritdoc />
    public partial class V133OperationLogs : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "OperationLogs",
                columns: table => new
                {
                    Id = table.Column<long>(type: "INTEGER", nullable: false)
                        .Annotation("Sqlite:Autoincrement", true),
                    TimeUtc = table.Column<DateTime>(type: "TEXT", nullable: false),
                    Severity = table.Column<int>(type: "INTEGER", nullable: false),
                    Source = table.Column<string>(type: "TEXT", maxLength: 64, nullable: false),
                    Operation = table.Column<string>(type: "TEXT", maxLength: 128, nullable: false),
                    Message = table.Column<string>(type: "TEXT", maxLength: 2048, nullable: false),
                    DetailsJson = table.Column<string>(type: "TEXT", maxLength: 65536, nullable: true),
                    ExceptionType = table.Column<string>(type: "TEXT", maxLength: 256, nullable: true),
                    ExceptionMessage = table.Column<string>(type: "TEXT", maxLength: 2048, nullable: true),
                    StackTrace = table.Column<string>(type: "TEXT", maxLength: 65536, nullable: true),
                    CorrelationId = table.Column<string>(type: "TEXT", maxLength: 64, nullable: true),
                    DurationMs = table.Column<long>(type: "INTEGER", nullable: true),
                    IsDebug = table.Column<bool>(type: "INTEGER", nullable: false),
                    Actor = table.Column<string>(type: "TEXT", maxLength: 256, nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_OperationLogs", x => x.Id);
                });

            migrationBuilder.CreateIndex(
                name: "IX_OperationLogs_Operation_TimeUtc",
                table: "OperationLogs",
                columns: new[] { "Operation", "TimeUtc" });

            migrationBuilder.CreateIndex(
                name: "IX_OperationLogs_Severity_TimeUtc",
                table: "OperationLogs",
                columns: new[] { "Severity", "TimeUtc" });

            migrationBuilder.CreateIndex(
                name: "IX_OperationLogs_Source_TimeUtc",
                table: "OperationLogs",
                columns: new[] { "Source", "TimeUtc" });

            migrationBuilder.CreateIndex(
                name: "IX_OperationLogs_TimeUtc",
                table: "OperationLogs",
                column: "TimeUtc");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "OperationLogs");
        }
    }
}
