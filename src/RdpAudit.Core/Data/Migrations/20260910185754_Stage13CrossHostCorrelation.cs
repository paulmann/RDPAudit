using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace RdpAudit.Core.Data.Migrations
{
    /// <inheritdoc />
    public partial class Stage13CrossHostCorrelation : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "CrossHostChains",
                columns: table => new
                {
                    Id = table.Column<long>(type: "INTEGER", nullable: false)
                        .Annotation("Sqlite:Autoincrement", true),
                    ChainKey = table.Column<string>(type: "TEXT", maxLength: 64, nullable: false),
                    RuleId = table.Column<string>(type: "TEXT", maxLength: 64, nullable: false),
                    NormalizedUserName = table.Column<string>(type: "TEXT", maxLength: 256, nullable: false),
                    FirstSeenUtc = table.Column<DateTime>(type: "TEXT", nullable: false),
                    LastSeenUtc = table.Column<DateTime>(type: "TEXT", nullable: false),
                    Score = table.Column<int>(type: "INTEGER", nullable: false),
                    FailedAttemptCount = table.Column<int>(type: "INTEGER", nullable: false),
                    DetectedUtc = table.Column<DateTime>(type: "TEXT", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_CrossHostChains", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "CrossHostFacts",
                columns: table => new
                {
                    Id = table.Column<long>(type: "INTEGER", nullable: false)
                        .Annotation("Sqlite:Autoincrement", true),
                    HostName = table.Column<string>(type: "TEXT", maxLength: 256, nullable: false),
                    TimeUtc = table.Column<DateTime>(type: "TEXT", nullable: false),
                    UserName = table.Column<string>(type: "TEXT", maxLength: 256, nullable: true),
                    NormalizedUserName = table.Column<string>(type: "TEXT", maxLength: 256, nullable: true),
                    SourceIp = table.Column<string>(type: "TEXT", maxLength: 45, nullable: true),
                    LogonType = table.Column<int>(type: "INTEGER", nullable: true),
                    Kind = table.Column<int>(type: "INTEGER", nullable: false),
                    EventId = table.Column<int>(type: "INTEGER", nullable: false),
                    DedupKey = table.Column<string>(type: "TEXT", maxLength: 64, nullable: true),
                    IngestedUtc = table.Column<DateTime>(type: "TEXT", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_CrossHostFacts", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "CrossHostHostStates",
                columns: table => new
                {
                    Id = table.Column<long>(type: "INTEGER", nullable: false)
                        .Annotation("Sqlite:Autoincrement", true),
                    HostName = table.Column<string>(type: "TEXT", maxLength: 256, nullable: false),
                    Availability = table.Column<int>(type: "INTEGER", nullable: false),
                    LastSeenUtc = table.Column<DateTime>(type: "TEXT", nullable: true),
                    LastError = table.Column<string>(type: "TEXT", maxLength: 1024, nullable: true),
                    LastPolledUtc = table.Column<DateTime>(type: "TEXT", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_CrossHostHostStates", x => x.Id);
                });

            migrationBuilder.CreateTable(
                name: "CrossHostLinks",
                columns: table => new
                {
                    Id = table.Column<long>(type: "INTEGER", nullable: false)
                        .Annotation("Sqlite:Autoincrement", true),
                    CrossHostChainId = table.Column<long>(type: "INTEGER", nullable: false),
                    Ordinal = table.Column<int>(type: "INTEGER", nullable: false),
                    HostName = table.Column<string>(type: "TEXT", maxLength: 256, nullable: false),
                    Kind = table.Column<int>(type: "INTEGER", nullable: false),
                    EventId = table.Column<int>(type: "INTEGER", nullable: false),
                    TimeUtc = table.Column<DateTime>(type: "TEXT", nullable: false),
                    SourceIp = table.Column<string>(type: "TEXT", maxLength: 45, nullable: true),
                    UserName = table.Column<string>(type: "TEXT", maxLength: 256, nullable: true)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_CrossHostLinks", x => x.Id);
                    table.ForeignKey(
                        name: "FK_CrossHostLinks_CrossHostChains_CrossHostChainId",
                        column: x => x.CrossHostChainId,
                        principalTable: "CrossHostChains",
                        principalColumn: "Id",
                        onDelete: ReferentialAction.Cascade);
                });

            migrationBuilder.CreateIndex(
                name: "IX_CrossHostChains_RuleId_ChainKey",
                table: "CrossHostChains",
                columns: new[] { "RuleId", "ChainKey" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_CrossHostChains_RuleId_LastSeenUtc",
                table: "CrossHostChains",
                columns: new[] { "RuleId", "LastSeenUtc" });

            migrationBuilder.CreateIndex(
                name: "IX_CrossHostFacts_DedupKey",
                table: "CrossHostFacts",
                column: "DedupKey",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_CrossHostFacts_HostName_TimeUtc",
                table: "CrossHostFacts",
                columns: new[] { "HostName", "TimeUtc" });

            migrationBuilder.CreateIndex(
                name: "IX_CrossHostFacts_Kind_HostName",
                table: "CrossHostFacts",
                columns: new[] { "Kind", "HostName" });

            migrationBuilder.CreateIndex(
                name: "IX_CrossHostFacts_NormalizedUserName_TimeUtc",
                table: "CrossHostFacts",
                columns: new[] { "NormalizedUserName", "TimeUtc" });

            migrationBuilder.CreateIndex(
                name: "IX_CrossHostHostStates_HostName",
                table: "CrossHostHostStates",
                column: "HostName",
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_CrossHostHostStates_LastPolledUtc",
                table: "CrossHostHostStates",
                column: "LastPolledUtc");

            migrationBuilder.CreateIndex(
                name: "IX_CrossHostLinks_CrossHostChainId_Ordinal",
                table: "CrossHostLinks",
                columns: new[] { "CrossHostChainId", "Ordinal" },
                unique: true);

            migrationBuilder.CreateIndex(
                name: "IX_CrossHostLinks_HostName_TimeUtc",
                table: "CrossHostLinks",
                columns: new[] { "HostName", "TimeUtc" });
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "CrossHostFacts");

            migrationBuilder.DropTable(
                name: "CrossHostHostStates");

            migrationBuilder.DropTable(
                name: "CrossHostLinks");

            migrationBuilder.DropTable(
                name: "CrossHostChains");
        }
    }
}
