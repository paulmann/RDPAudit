// File:    src/RdpAudit.Core/Data/Migrations/20260814012527_Stage11ShardMetadataNullable.cs
// Module:  RdpAudit.Core.Data.Migrations
// Purpose: Stage 11 — makes the IpEventSummary shard metadata columns nullable and clears the
//          placeholder values written by Stage 10. No shard file has ever been created, so these
//          columns must read NULL rather than an empty path and zero counters, which an analyst
//          would otherwise mistake for a real but empty shard.
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace RdpAudit.Core.Data.Migrations
{
    /// <inheritdoc />
    public partial class Stage11ShardMetadataNullable : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AlterColumn<string>(
                name: "ShardRelativePath",
                table: "IpEventSummary",
                type: "TEXT",
                maxLength: 260,
                nullable: true,
                oldClrType: typeof(string),
                oldType: "TEXT",
                oldMaxLength: 260);

            migrationBuilder.AlterColumn<long>(
                name: "ShardRecordCount",
                table: "IpEventSummary",
                type: "INTEGER",
                nullable: true,
                oldClrType: typeof(long),
                oldType: "INTEGER",
                oldDefaultValue: 0L);

            migrationBuilder.AlterColumn<int>(
                name: "ShardFormatVersion",
                table: "IpEventSummary",
                type: "INTEGER",
                nullable: true,
                oldClrType: typeof(int),
                oldType: "INTEGER",
                oldDefaultValue: 1);

            migrationBuilder.AlterColumn<long>(
                name: "ShardEvictedCount",
                table: "IpEventSummary",
                type: "INTEGER",
                nullable: true,
                oldClrType: typeof(long),
                oldType: "INTEGER",
                oldDefaultValue: 0L);

            migrationBuilder.AlterColumn<long>(
                name: "ShardBytes",
                table: "IpEventSummary",
                type: "INTEGER",
                nullable: true,
                oldClrType: typeof(long),
                oldType: "INTEGER",
                oldDefaultValue: 0L);

            // Stage 10 populated these columns from the event payload rather than from a shard
            // header: ShardBytes held the size of the UTF-8 detail snapshot, ShardRecordCount
            // counted ingested events, and ShardRelativePath was always empty. ShardWriter is not
            // wired into the ingestion path, so not one shard file exists and every stored value is
            // fiction. Clear them unconditionally.
            migrationBuilder.Sql("""
                UPDATE IpEventSummary SET
                    ShardRelativePath = NULL,
                    ShardRecordCount = NULL,
                    ShardBytes = NULL,
                    ShardFormatVersion = NULL,
                    ShardEvictedCount = NULL,
                    ShardOldestRetainedUtc = NULL;
                """);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AlterColumn<string>(
                name: "ShardRelativePath",
                table: "IpEventSummary",
                type: "TEXT",
                maxLength: 260,
                nullable: false,
                defaultValue: "",
                oldClrType: typeof(string),
                oldType: "TEXT",
                oldMaxLength: 260,
                oldNullable: true);

            migrationBuilder.AlterColumn<long>(
                name: "ShardRecordCount",
                table: "IpEventSummary",
                type: "INTEGER",
                nullable: false,
                defaultValue: 0L,
                oldClrType: typeof(long),
                oldType: "INTEGER",
                oldNullable: true);

            migrationBuilder.AlterColumn<int>(
                name: "ShardFormatVersion",
                table: "IpEventSummary",
                type: "INTEGER",
                nullable: false,
                defaultValue: 1,
                oldClrType: typeof(int),
                oldType: "INTEGER",
                oldNullable: true);

            migrationBuilder.AlterColumn<long>(
                name: "ShardEvictedCount",
                table: "IpEventSummary",
                type: "INTEGER",
                nullable: false,
                defaultValue: 0L,
                oldClrType: typeof(long),
                oldType: "INTEGER",
                oldNullable: true);

            migrationBuilder.AlterColumn<long>(
                name: "ShardBytes",
                table: "IpEventSummary",
                type: "INTEGER",
                nullable: false,
                defaultValue: 0L,
                oldClrType: typeof(long),
                oldType: "INTEGER",
                oldNullable: true);
        }
    }
}
