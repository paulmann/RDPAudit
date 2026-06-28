using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace RdpAudit.Core.Data.Migrations
{
	/// <inheritdoc />
	public partial class Stage2FirewallStats : Migration
	{
		/// <inheritdoc />
		protected override void Up(MigrationBuilder migrationBuilder)
		{
			migrationBuilder.CreateTable(
				name: "AbuseReports",
				columns: table => new
				{
					Id = table.Column<long>(type: "INTEGER", nullable: false)
						.Annotation("Sqlite:Autoincrement", true),
					Ip = table.Column<string>(type: "TEXT", maxLength: 45, nullable: false),
					ReportedUtc = table.Column<DateTime>(type: "TEXT", nullable: false),
					Categories = table.Column<string>(type: "TEXT", maxLength: 256, nullable: false),
					ResponseCode = table.Column<int>(type: "INTEGER", nullable: false),
					Error = table.Column<string>(type: "TEXT", maxLength: 2048, nullable: true),
					AlertId = table.Column<long>(type: "INTEGER", nullable: true)
				},
				constraints: table =>
				{
					table.PrimaryKey("PK_AbuseReports", x => x.Id);
				});

			migrationBuilder.CreateTable(
				name: "ActiveBlocks",
				columns: table => new
				{
					Id = table.Column<long>(type: "INTEGER", nullable: false)
						.Annotation("Sqlite:Autoincrement", true),
					Ip = table.Column<string>(type: "TEXT", maxLength: 45, nullable: false),
					Provider = table.Column<int>(type: "INTEGER", nullable: false),
					RuleHandle = table.Column<string>(type: "TEXT", maxLength: 256, nullable: true),
					CreatedUtc = table.Column<DateTime>(type: "TEXT", nullable: false),
					ExpiresUtc = table.Column<DateTime>(type: "TEXT", nullable: true),
					Reason = table.Column<string>(type: "TEXT", maxLength: 1024, nullable: false),
					Status = table.Column<int>(type: "INTEGER", nullable: false),
					LastError = table.Column<string>(type: "TEXT", maxLength: 2048, nullable: true)
				},
				constraints: table =>
				{
					table.PrimaryKey("PK_ActiveBlocks", x => x.Id);
				});

			migrationBuilder.CreateTable(
				name: "AttackStats",
				columns: table => new
				{
					Ip = table.Column<string>(type: "TEXT", maxLength: 45, nullable: false),
					TotalAttempts = table.Column<long>(type: "INTEGER", nullable: false),
					Successful = table.Column<long>(type: "INTEGER", nullable: false),
					Failed = table.Column<long>(type: "INTEGER", nullable: false),
					FirstSeenUtc = table.Column<DateTime>(type: "TEXT", nullable: false),
					LastSeenUtc = table.Column<DateTime>(type: "TEXT", nullable: false),
					DurationSeconds = table.Column<long>(type: "INTEGER", nullable: false),
					Top10AttemptedLogins = table.Column<string>(type: "TEXT", maxLength: 4096, nullable: false),
					LastLoginType = table.Column<int>(type: "INTEGER", nullable: true),
					ThreatScore = table.Column<double>(type: "REAL", nullable: false),
					IsBlocked = table.Column<bool>(type: "INTEGER", nullable: false),
					LastUpdatedUtc = table.Column<DateTime>(type: "TEXT", nullable: false)
				},
				constraints: table =>
				{
					table.PrimaryKey("PK_AttackStats", x => x.Ip);
				});

			migrationBuilder.CreateTable(
				name: "BlocklistEntries",
				columns: table => new
				{
					Id = table.Column<long>(type: "INTEGER", nullable: false)
						.Annotation("Sqlite:Autoincrement", true),
					Ip = table.Column<string>(type: "TEXT", maxLength: 45, nullable: true),
					Login = table.Column<string>(type: "TEXT", maxLength: 256, nullable: true),
					Reason = table.Column<string>(type: "TEXT", maxLength: 1024, nullable: false),
					AddedUtc = table.Column<DateTime>(type: "TEXT", nullable: false),
					ExpiresUtc = table.Column<DateTime>(type: "TEXT", nullable: true),
					Source = table.Column<int>(type: "INTEGER", nullable: false),
					LinkedAlertId = table.Column<long>(type: "INTEGER", nullable: true),
					IsEnabled = table.Column<bool>(type: "INTEGER", nullable: false)
				},
				constraints: table =>
				{
					table.PrimaryKey("PK_BlocklistEntries", x => x.Id);
				});

			migrationBuilder.CreateTable(
				name: "LoginRules",
				columns: table => new
				{
					Id = table.Column<long>(type: "INTEGER", nullable: false)
						.Annotation("Sqlite:Autoincrement", true),
					Login = table.Column<string>(type: "TEXT", maxLength: 256, nullable: false),
					Note = table.Column<string>(type: "TEXT", maxLength: 512, nullable: true),
					Enabled = table.Column<bool>(type: "INTEGER", nullable: false),
					AddedUtc = table.Column<DateTime>(type: "TEXT", nullable: false)
				},
				constraints: table =>
				{
					table.PrimaryKey("PK_LoginRules", x => x.Id);
				});

			migrationBuilder.CreateTable(
				name: "WhitelistEntries",
				columns: table => new
				{
					Id = table.Column<long>(type: "INTEGER", nullable: false)
						.Annotation("Sqlite:Autoincrement", true),
					Ip = table.Column<string>(type: "TEXT", maxLength: 45, nullable: false),
					Note = table.Column<string>(type: "TEXT", maxLength: 512, nullable: true),
					AddedUtc = table.Column<DateTime>(type: "TEXT", nullable: false),
					AddedBy = table.Column<string>(type: "TEXT", maxLength: 256, nullable: true)
				},
				constraints: table =>
				{
					table.PrimaryKey("PK_WhitelistEntries", x => x.Id);
				});

			migrationBuilder.CreateIndex(
				name: "IX_AbuseReports_Ip_ReportedUtc",
				table: "AbuseReports",
				columns: new[] { "Ip", "ReportedUtc" });

			migrationBuilder.CreateIndex(
				name: "IX_AbuseReports_ReportedUtc",
				table: "AbuseReports",
				column: "ReportedUtc");

			migrationBuilder.CreateIndex(
				name: "IX_ActiveBlocks_ExpiresUtc",
				table: "ActiveBlocks",
				column: "ExpiresUtc");

			migrationBuilder.CreateIndex(
				name: "IX_ActiveBlocks_Provider_Ip",
				table: "ActiveBlocks",
				columns: new[] { "Provider", "Ip" },
				unique: true);

			migrationBuilder.CreateIndex(
				name: "IX_ActiveBlocks_Provider_RuleHandle",
				table: "ActiveBlocks",
				columns: new[] { "Provider", "RuleHandle" });

			migrationBuilder.CreateIndex(
				name: "IX_ActiveBlocks_Status",
				table: "ActiveBlocks",
				column: "Status");

			migrationBuilder.CreateIndex(
				name: "IX_AttackStats_IsBlocked",
				table: "AttackStats",
				column: "IsBlocked");

			migrationBuilder.CreateIndex(
				name: "IX_AttackStats_LastSeenUtc",
				table: "AttackStats",
				column: "LastSeenUtc");

			migrationBuilder.CreateIndex(
				name: "IX_AttackStats_ThreatScore",
				table: "AttackStats",
				column: "ThreatScore");

			migrationBuilder.CreateIndex(
				name: "IX_BlocklistEntries_ExpiresUtc",
				table: "BlocklistEntries",
				column: "ExpiresUtc");

			migrationBuilder.CreateIndex(
				name: "IX_BlocklistEntries_Ip",
				table: "BlocklistEntries",
				column: "Ip");

			migrationBuilder.CreateIndex(
				name: "IX_BlocklistEntries_IsEnabled_ExpiresUtc",
				table: "BlocklistEntries",
				columns: new[] { "IsEnabled", "ExpiresUtc" });

			migrationBuilder.CreateIndex(
				name: "IX_BlocklistEntries_Login",
				table: "BlocklistEntries",
				column: "Login");

			migrationBuilder.CreateIndex(
				name: "IX_LoginRules_Enabled",
				table: "LoginRules",
				column: "Enabled");

			migrationBuilder.CreateIndex(
				name: "IX_LoginRules_Login",
				table: "LoginRules",
				column: "Login",
				unique: true);

			migrationBuilder.CreateIndex(
				name: "IX_WhitelistEntries_Ip",
				table: "WhitelistEntries",
				column: "Ip",
				unique: true);
		}

		/// <inheritdoc />
		protected override void Down(MigrationBuilder migrationBuilder)
		{
			migrationBuilder.DropTable(
				name: "AbuseReports");

			migrationBuilder.DropTable(
				name: "ActiveBlocks");

			migrationBuilder.DropTable(
				name: "AttackStats");

			migrationBuilder.DropTable(
				name: "BlocklistEntries");

			migrationBuilder.DropTable(
				name: "LoginRules");

			migrationBuilder.DropTable(
				name: "WhitelistEntries");
		}
	}
}
