using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace RdpAudit.Core.Data.Migrations
{
	/// <inheritdoc />
	public partial class Stage7AuthAttemptFact : Migration
	{
		/// <inheritdoc />
		protected override void Up(MigrationBuilder migrationBuilder)
		{
			migrationBuilder.CreateTable(
				name: "AuthAttemptFacts",
				columns: table => new
				{
					Id = table.Column<long>(type: "INTEGER", nullable: false)
						.Annotation("Sqlite:Autoincrement", true),
					TimeUtc = table.Column<DateTime>(type: "TEXT", nullable: false),
					SourceIp = table.Column<string>(type: "TEXT", maxLength: 45, nullable: true),
					SourcePort = table.Column<int>(type: "INTEGER", nullable: true),
					TargetUser = table.Column<string>(type: "TEXT", maxLength: 256, nullable: true),
					TargetDomain = table.Column<string>(type: "TEXT", maxLength: 256, nullable: true),
					NormalizedUserName = table.Column<string>(type: "TEXT", maxLength: 256, nullable: true),
					WorkstationName = table.Column<string>(type: "TEXT", maxLength: 256, nullable: true),
					AuthPackage = table.Column<string>(type: "TEXT", maxLength: 64, nullable: true),
					LogonType = table.Column<int>(type: "INTEGER", nullable: true),
					LogonId = table.Column<string>(type: "TEXT", maxLength: 32, nullable: true),
					Outcome = table.Column<int>(type: "INTEGER", nullable: false),
					Status = table.Column<string>(type: "TEXT", maxLength: 64, nullable: true),
					SubStatus = table.Column<string>(type: "TEXT", maxLength: 64, nullable: true),
					SubStatusMeaning = table.Column<string>(type: "TEXT", maxLength: 128, nullable: true),
					EvidenceChannel = table.Column<string>(type: "TEXT", maxLength: 256, nullable: true),
					EvidenceEventId = table.Column<int>(type: "INTEGER", nullable: false),
					EvidenceRawEventId = table.Column<long>(type: "INTEGER", nullable: false),
					IpFromCorrelation = table.Column<bool>(type: "INTEGER", nullable: false, defaultValue: false),
					EnrichmentSource = table.Column<string>(type: "TEXT", maxLength: 64, nullable: true),
					EnrichmentConfidence = table.Column<string>(type: "TEXT", maxLength: 16, nullable: true),
					NeedsCorrelation = table.Column<bool>(type: "INTEGER", nullable: false, defaultValue: false),
					IngestedUtc = table.Column<DateTime>(type: "TEXT", nullable: false)
				},
				constraints: table =>
				{
					table.PrimaryKey("PK_AuthAttemptFacts", x => x.Id);
				});

			migrationBuilder.CreateIndex(
				name: "IX_AuthAttemptFacts_SourceIp_TimeUtc",
				table: "AuthAttemptFacts",
				columns: new[] { "SourceIp", "TimeUtc" });

			migrationBuilder.CreateIndex(
				name: "IX_AuthAttemptFacts_NormalizedUserName_TimeUtc",
				table: "AuthAttemptFacts",
				columns: new[] { "NormalizedUserName", "TimeUtc" });

			migrationBuilder.CreateIndex(
				name: "IX_AuthAttemptFacts_Outcome_TimeUtc",
				table: "AuthAttemptFacts",
				columns: new[] { "Outcome", "TimeUtc" });

			migrationBuilder.CreateIndex(
				name: "IX_AuthAttemptFacts_NeedsCorrelation_TimeUtc",
				table: "AuthAttemptFacts",
				columns: new[] { "NeedsCorrelation", "TimeUtc" });

			migrationBuilder.CreateIndex(
				name: "IX_AuthAttemptFacts_EvidenceRawEventId",
				table: "AuthAttemptFacts",
				column: "EvidenceRawEventId");
		}

		/// <inheritdoc />
		protected override void Down(MigrationBuilder migrationBuilder)
		{
			migrationBuilder.DropTable(
				name: "AuthAttemptFacts");
		}
	}
}
