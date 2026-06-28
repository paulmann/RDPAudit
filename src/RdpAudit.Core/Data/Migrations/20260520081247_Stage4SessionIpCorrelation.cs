using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace RdpAudit.Core.Data.Migrations
{
	/// <inheritdoc />
	public partial class Stage4SessionIpCorrelation : Migration
	{
		/// <inheritdoc />
		protected override void Up(MigrationBuilder migrationBuilder)
		{
			migrationBuilder.CreateTable(
				name: "SessionIpCorrelations",
				columns: table => new
				{
					Id = table.Column<long>(type: "INTEGER", nullable: false)
						.Annotation("Sqlite:Autoincrement", true),
					LogonId = table.Column<string>(type: "TEXT", maxLength: 32, nullable: true),
					WtsSessionId = table.Column<int>(type: "INTEGER", nullable: true),
					UserName = table.Column<string>(type: "TEXT", maxLength: 256, nullable: true),
					Domain = table.Column<string>(type: "TEXT", maxLength: 256, nullable: true),
					Ip = table.Column<string>(type: "TEXT", maxLength: 45, nullable: false),
					FirstSeenUtc = table.Column<DateTime>(type: "TEXT", nullable: false),
					LastSeenUtc = table.Column<DateTime>(type: "TEXT", nullable: false),
					ObservedEventIds = table.Column<string>(type: "TEXT", maxLength: 128, nullable: true),
					IsDirectObservation = table.Column<bool>(type: "INTEGER", nullable: false, defaultValue: false)
				},
				constraints: table =>
				{
					table.PrimaryKey("PK_SessionIpCorrelations", x => x.Id);
				});

			migrationBuilder.CreateIndex(
				name: "IX_SessionIpCorrelations_LogonId",
				table: "SessionIpCorrelations",
				column: "LogonId");

			migrationBuilder.CreateIndex(
				name: "IX_SessionIpCorrelations_WtsSessionId_UserName",
				table: "SessionIpCorrelations",
				columns: new[] { "WtsSessionId", "UserName" });

			migrationBuilder.CreateIndex(
				name: "IX_SessionIpCorrelations_Ip_LastSeenUtc",
				table: "SessionIpCorrelations",
				columns: new[] { "Ip", "LastSeenUtc" });

			migrationBuilder.CreateIndex(
				name: "IX_SessionIpCorrelations_UserName_LastSeenUtc",
				table: "SessionIpCorrelations",
				columns: new[] { "UserName", "LastSeenUtc" });

			migrationBuilder.CreateIndex(
				name: "IX_SessionIpCorrelations_LastSeenUtc",
				table: "SessionIpCorrelations",
				column: "LastSeenUtc");
		}

		/// <inheritdoc />
		protected override void Down(MigrationBuilder migrationBuilder)
		{
			migrationBuilder.DropTable(
				name: "SessionIpCorrelations");
		}
	}
}
