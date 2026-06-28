using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace RdpAudit.Core.Data.Migrations
{
	/// <inheritdoc />
	public partial class Stage5RdpConnectionFact : Migration
	{
		/// <inheritdoc />
		protected override void Up(MigrationBuilder migrationBuilder)
		{
			migrationBuilder.CreateTable(
				name: "RdpConnectionFacts",
				columns: table => new
				{
					Id = table.Column<long>(type: "INTEGER", nullable: false)
						.Annotation("Sqlite:Autoincrement", true),
					Ip = table.Column<string>(type: "TEXT", maxLength: 45, nullable: false),
					UserName = table.Column<string>(type: "TEXT", maxLength: 256, nullable: true),
					Domain = table.Column<string>(type: "TEXT", maxLength: 256, nullable: true),
					WtsSessionId = table.Column<int>(type: "INTEGER", nullable: true),
					LogonId = table.Column<string>(type: "TEXT", maxLength: 32, nullable: true),
					FirstSeenUtc = table.Column<DateTime>(type: "TEXT", nullable: false),
					LastSeenUtc = table.Column<DateTime>(type: "TEXT", nullable: false),
					ConnectedUtc = table.Column<DateTime>(type: "TEXT", nullable: true),
					AuthenticatedUtc = table.Column<DateTime>(type: "TEXT", nullable: true),
					DisconnectedUtc = table.Column<DateTime>(type: "TEXT", nullable: true),
					ReconnectedUtc = table.Column<DateTime>(type: "TEXT", nullable: true),
					LoggedOffUtc = table.Column<DateTime>(type: "TEXT", nullable: true),
					FailedLogons = table.Column<int>(type: "INTEGER", nullable: false, defaultValue: 0),
					SuccessfulLogons = table.Column<int>(type: "INTEGER", nullable: false, defaultValue: 0),
					ObservedEventIds = table.Column<string>(type: "TEXT", maxLength: 256, nullable: true),
					UserNamesAttempted = table.Column<string>(type: "TEXT", maxLength: 1024, nullable: true),
					IsActive = table.Column<bool>(type: "INTEGER", nullable: false, defaultValue: false)
				},
				constraints: table =>
				{
					table.PrimaryKey("PK_RdpConnectionFacts", x => x.Id);
				});

			migrationBuilder.CreateIndex(
				name: "IX_RdpConnectionFacts_Ip_LastSeenUtc",
				table: "RdpConnectionFacts",
				columns: new[] { "Ip", "LastSeenUtc" });

			migrationBuilder.CreateIndex(
				name: "IX_RdpConnectionFacts_WtsSessionId_UserName",
				table: "RdpConnectionFacts",
				columns: new[] { "WtsSessionId", "UserName" });

			migrationBuilder.CreateIndex(
				name: "IX_RdpConnectionFacts_LogonId",
				table: "RdpConnectionFacts",
				column: "LogonId");

			migrationBuilder.CreateIndex(
				name: "IX_RdpConnectionFacts_LastSeenUtc",
				table: "RdpConnectionFacts",
				column: "LastSeenUtc");

			migrationBuilder.CreateIndex(
				name: "IX_RdpConnectionFacts_UserName_LastSeenUtc",
				table: "RdpConnectionFacts",
				columns: new[] { "UserName", "LastSeenUtc" });
		}

		/// <inheritdoc />
		protected override void Down(MigrationBuilder migrationBuilder)
		{
			migrationBuilder.DropTable(
				name: "RdpConnectionFacts");
		}
	}
}
