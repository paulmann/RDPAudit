// File:    src/RdpAudit.Core/Data/Migrations/20260609125156_V126AbuseIpDbReportLogColumns.cs
// Module:  RdpAudit.Core.Data.Migrations
// Purpose: v1.2.6 — additive columns on AbuseIpDbReportHistory that turn the report-attempt history
//          into the operator-facing report log: action, reason, classification, AbuseIPDB report id,
//          cooldown-expiry, observed failed/successful counts, first/last seen, usernames sample and a
//          sanitised comment preview. All new columns are nullable or defaulted; no secret material.
// Extends: Microsoft.EntityFrameworkCore.Migrations.Migration
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace RdpAudit.Core.Data.Migrations
{
    /// <inheritdoc />
    public partial class V126AbuseIpDbReportLogColumns : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<int>(
                name: "Action",
                table: "AbuseIpDbReportHistory",
                type: "INTEGER",
                nullable: false,
                defaultValue: 0);

            migrationBuilder.AddColumn<int>(
                name: "Classification",
                table: "AbuseIpDbReportHistory",
                type: "INTEGER",
                nullable: false,
                defaultValue: 0);

            migrationBuilder.AddColumn<string>(
                name: "CommentPreview",
                table: "AbuseIpDbReportHistory",
                type: "TEXT",
                maxLength: 512,
                nullable: true);

            migrationBuilder.AddColumn<DateTime>(
                name: "CooldownExpiresUtc",
                table: "AbuseIpDbReportHistory",
                type: "TEXT",
                nullable: true);

            migrationBuilder.AddColumn<long>(
                name: "FailedCount",
                table: "AbuseIpDbReportHistory",
                type: "INTEGER",
                nullable: false,
                defaultValue: 0L);

            migrationBuilder.AddColumn<DateTime>(
                name: "FirstSeenUtc",
                table: "AbuseIpDbReportHistory",
                type: "TEXT",
                nullable: true);

            migrationBuilder.AddColumn<DateTime>(
                name: "LastSeenUtc",
                table: "AbuseIpDbReportHistory",
                type: "TEXT",
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "Reason",
                table: "AbuseIpDbReportHistory",
                type: "TEXT",
                maxLength: 64,
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "ReportId",
                table: "AbuseIpDbReportHistory",
                type: "TEXT",
                maxLength: 128,
                nullable: true);

            migrationBuilder.AddColumn<long>(
                name: "SuccessfulCount",
                table: "AbuseIpDbReportHistory",
                type: "INTEGER",
                nullable: false,
                defaultValue: 0L);

            migrationBuilder.AddColumn<string>(
                name: "UsernamesSample",
                table: "AbuseIpDbReportHistory",
                type: "TEXT",
                maxLength: 512,
                nullable: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "Action",
                table: "AbuseIpDbReportHistory");

            migrationBuilder.DropColumn(
                name: "Classification",
                table: "AbuseIpDbReportHistory");

            migrationBuilder.DropColumn(
                name: "CommentPreview",
                table: "AbuseIpDbReportHistory");

            migrationBuilder.DropColumn(
                name: "CooldownExpiresUtc",
                table: "AbuseIpDbReportHistory");

            migrationBuilder.DropColumn(
                name: "FailedCount",
                table: "AbuseIpDbReportHistory");

            migrationBuilder.DropColumn(
                name: "FirstSeenUtc",
                table: "AbuseIpDbReportHistory");

            migrationBuilder.DropColumn(
                name: "LastSeenUtc",
                table: "AbuseIpDbReportHistory");

            migrationBuilder.DropColumn(
                name: "Reason",
                table: "AbuseIpDbReportHistory");

            migrationBuilder.DropColumn(
                name: "ReportId",
                table: "AbuseIpDbReportHistory");

            migrationBuilder.DropColumn(
                name: "SuccessfulCount",
                table: "AbuseIpDbReportHistory");

            migrationBuilder.DropColumn(
                name: "UsernamesSample",
                table: "AbuseIpDbReportHistory");
        }
    }
}
