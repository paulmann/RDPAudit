// File:    src/RdpAudit.Core/Data/Migrations/20261023204643_Stage20RawEventRecordId.cs
// Module:  RdpAudit.Core.Data.Migrations
// Purpose: Stage 20 - adds RawEvents.RecordId and the partial unique index
//          (Channel, RecordId, TimeUtc) so the live watcher and the backfill workers cannot persist
//          the same Windows record twice. All additive/nullable; Down drops the index and column.
// Extends: Microsoft.EntityFrameworkCore.Migrations.Migration
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace RdpAudit.Core.Data.Migrations
{
    /// <inheritdoc />
    public partial class Stage20RawEventRecordId : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<long>(
                name: "RecordId",
                table: "RawEvents",
                type: "INTEGER",
                nullable: true);

            migrationBuilder.CreateIndex(
                name: "IX_RawEvents_Channel_RecordId_TimeUtc",
                table: "RawEvents",
                columns: new[] { "Channel", "RecordId", "TimeUtc" },
                unique: true,
                filter: "\"RecordId\" IS NOT NULL");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropIndex(
                name: "IX_RawEvents_Channel_RecordId_TimeUtc",
                table: "RawEvents");

            migrationBuilder.DropColumn(
                name: "RecordId",
                table: "RawEvents");
        }
    }
}
