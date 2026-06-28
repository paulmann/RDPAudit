// File:    src/RdpAudit.Core/Data/Migrations/20260609120000_Stage9AbuseIpDbReportHistory.cs
// Module:  RdpAudit.Core.Data.Migrations
// Purpose: Stage 9 (v1.2.5) — creates the AbuseIpDbReportHistory table that backs the configurable
//          AbuseIPDB report cooldown / dedupe. Records every report attempt (success or failure);
//          only successful rows gate future submissions. Append-only; no secret material stored.
// Extends: Microsoft.EntityFrameworkCore.Migrations.Migration
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace RdpAudit.Core.Data.Migrations
{
	/// <inheritdoc />
	public partial class Stage9AbuseIpDbReportHistory : Migration
	{
		/// <inheritdoc />
		protected override void Up(MigrationBuilder migrationBuilder)
		{
			migrationBuilder.CreateTable(
				name: "AbuseIpDbReportHistory",
				columns: table => new
				{
					Id = table.Column<long>(type: "INTEGER", nullable: false)
						.Annotation("Sqlite:Autoincrement", true),
					IpAddress = table.Column<string>(type: "TEXT", maxLength: 45, nullable: false),
					ReportedAtUtc = table.Column<DateTime>(type: "TEXT", nullable: false),
					Succeeded = table.Column<bool>(type: "INTEGER", nullable: false),
					HttpStatusCode = table.Column<int>(type: "INTEGER", nullable: false),
					ResultCode = table.Column<string>(type: "TEXT", maxLength: 64, nullable: true),
					ErrorMessage = table.Column<string>(type: "TEXT", maxLength: 2048, nullable: true),
					AbuseCategories = table.Column<string>(type: "TEXT", maxLength: 256, nullable: false),
					CommentHash = table.Column<string>(type: "TEXT", maxLength: 64, nullable: true),
					RuleId = table.Column<long>(type: "INTEGER", nullable: true),
					Source = table.Column<string>(type: "TEXT", maxLength: 64, nullable: true)
				},
				constraints: table =>
				{
					table.PrimaryKey("PK_AbuseIpDbReportHistory", x => x.Id);
				});

			migrationBuilder.CreateIndex(
				name: "IX_AbuseIpDbReportHistory_IpAddress_Succeeded_ReportedAtUtc",
				table: "AbuseIpDbReportHistory",
				columns: new[] { "IpAddress", "Succeeded", "ReportedAtUtc" });

			migrationBuilder.CreateIndex(
				name: "IX_AbuseIpDbReportHistory_ReportedAtUtc",
				table: "AbuseIpDbReportHistory",
				column: "ReportedAtUtc");
		}

		/// <inheritdoc />
		protected override void Down(MigrationBuilder migrationBuilder)
		{
			migrationBuilder.DropTable(
				name: "AbuseIpDbReportHistory");
		}
	}
}
