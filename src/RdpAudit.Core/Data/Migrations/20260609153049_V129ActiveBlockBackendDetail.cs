// File:    src/RdpAudit.Core/Data/Migrations/20260609153049_V129ActiveBlockBackendDetail.cs
// Module:  RdpAudit.Core.Data.Migrations
// Purpose: v1.2.9 — additive per-attempt backend-diagnostic columns on ActiveBlocks so Repair / block
//          attempts persist exactly what ran (BackendCommand, stdout/stderr previews, ExitCode, TimedOut,
//          DurationMs, ScannerBackend, VerifierReason) plus LastAttemptUtc, eliminating opaque
//          "Failed / Failed" per-IP diagnostics. All new columns are nullable; no secret material.
// Extends: Microsoft.EntityFrameworkCore.Migrations.Migration
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace RdpAudit.Core.Data.Migrations
{
    /// <inheritdoc />
    public partial class V129ActiveBlockBackendDetail : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<string>(
                name: "BackendCommand",
                table: "ActiveBlocks",
                type: "TEXT",
                maxLength: 2048,
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "BackendStderrPreview",
                table: "ActiveBlocks",
                type: "TEXT",
                maxLength: 1024,
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "BackendStdoutPreview",
                table: "ActiveBlocks",
                type: "TEXT",
                maxLength: 1024,
                nullable: true);

            migrationBuilder.AddColumn<long>(
                name: "DurationMs",
                table: "ActiveBlocks",
                type: "INTEGER",
                nullable: true);

            migrationBuilder.AddColumn<int>(
                name: "ExitCode",
                table: "ActiveBlocks",
                type: "INTEGER",
                nullable: true);

            migrationBuilder.AddColumn<DateTime>(
                name: "LastAttemptUtc",
                table: "ActiveBlocks",
                type: "TEXT",
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "ScannerBackend",
                table: "ActiveBlocks",
                type: "TEXT",
                maxLength: 64,
                nullable: true);

            migrationBuilder.AddColumn<bool>(
                name: "TimedOut",
                table: "ActiveBlocks",
                type: "INTEGER",
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "VerifierReason",
                table: "ActiveBlocks",
                type: "TEXT",
                maxLength: 512,
                nullable: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "BackendCommand",
                table: "ActiveBlocks");

            migrationBuilder.DropColumn(
                name: "BackendStderrPreview",
                table: "ActiveBlocks");

            migrationBuilder.DropColumn(
                name: "BackendStdoutPreview",
                table: "ActiveBlocks");

            migrationBuilder.DropColumn(
                name: "DurationMs",
                table: "ActiveBlocks");

            migrationBuilder.DropColumn(
                name: "ExitCode",
                table: "ActiveBlocks");

            migrationBuilder.DropColumn(
                name: "LastAttemptUtc",
                table: "ActiveBlocks");

            migrationBuilder.DropColumn(
                name: "ScannerBackend",
                table: "ActiveBlocks");

            migrationBuilder.DropColumn(
                name: "TimedOut",
                table: "ActiveBlocks");

            migrationBuilder.DropColumn(
                name: "VerifierReason",
                table: "ActiveBlocks");
        }
    }
}
