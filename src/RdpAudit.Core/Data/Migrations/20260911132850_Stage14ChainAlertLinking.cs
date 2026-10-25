using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace RdpAudit.Core.Data.Migrations
{
    /// <inheritdoc />
    public partial class Stage14ChainAlertLinking : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<long>(
                name: "AlertId",
                table: "CrossHostChains",
                type: "INTEGER",
                nullable: true);

            migrationBuilder.AddColumn<bool>(
                name: "IsAcknowledged",
                table: "CrossHostChains",
                type: "INTEGER",
                nullable: false,
                defaultValue: false);

            migrationBuilder.CreateIndex(
                name: "IX_CrossHostChains_AlertId",
                table: "CrossHostChains",
                column: "AlertId");

            migrationBuilder.AddForeignKey(
                name: "FK_CrossHostChains_Alerts_AlertId",
                table: "CrossHostChains",
                column: "AlertId",
                principalTable: "Alerts",
                principalColumn: "Id",
                onDelete: ReferentialAction.SetNull);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropForeignKey(
                name: "FK_CrossHostChains_Alerts_AlertId",
                table: "CrossHostChains");

            migrationBuilder.DropIndex(
                name: "IX_CrossHostChains_AlertId",
                table: "CrossHostChains");

            migrationBuilder.DropColumn(
                name: "AlertId",
                table: "CrossHostChains");

            migrationBuilder.DropColumn(
                name: "IsAcknowledged",
                table: "CrossHostChains");
        }
    }
}
