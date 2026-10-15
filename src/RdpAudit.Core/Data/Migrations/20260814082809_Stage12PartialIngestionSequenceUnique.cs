/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 2.0.0
// File   : 20260814082809_Stage12PartialIngestionSequenceUnique.cs
// Project: RdpAudit.Core (RdpAudit.Core.Data.Migrations)
// Purpose: Recreates the RawEvents.IngestionSequence unique index as partial so it only enforces
//          uniqueness on ingestion-assigned sequences (> 0) and tolerates the legacy default 0.
// Depends: RawEvent, RawEventConfiguration
// Extends: If sequence semantics change, update RawEventConfiguration and add a new migration.

using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace RdpAudit.Core.Data.Migrations
{
	/// <inheritdoc />
	public partial class Stage12PartialIngestionSequenceUnique : Migration
	{
		/// <inheritdoc />
		protected override void Up(MigrationBuilder migrationBuilder)
		{
			migrationBuilder.DropIndex(
				name: "IX_RawEvents_IngestionSequence",
				table: "RawEvents");

			migrationBuilder.CreateIndex(
				name: "IX_RawEvents_IngestionSequence",
				table: "RawEvents",
				column: "IngestionSequence",
				unique: true,
				filter: "\"IngestionSequence\" > 0");
		}

		/// <inheritdoc />
		protected override void Down(MigrationBuilder migrationBuilder)
		{
			migrationBuilder.DropIndex(
				name: "IX_RawEvents_IngestionSequence",
				table: "RawEvents");

			migrationBuilder.CreateIndex(
				name: "IX_RawEvents_IngestionSequence",
				table: "RawEvents",
				column: "IngestionSequence",
				unique: true);
		}
	}
}
