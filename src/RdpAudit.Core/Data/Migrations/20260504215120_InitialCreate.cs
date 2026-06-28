using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace RdpAudit.Core.Data.Migrations
{
	/// <inheritdoc />
	public partial class InitialCreate : Migration
	{
		/// <inheritdoc />
		protected override void Up(MigrationBuilder migrationBuilder)
		{
			migrationBuilder.CreateTable(
				name: "Addresses",
				columns: table => new
				{
					Id = table.Column<long>(type: "INTEGER", nullable: false)
						.Annotation("Sqlite:Autoincrement", true),
					Ip = table.Column<string>(type: "TEXT", maxLength: 45, nullable: false),
					FailCount = table.Column<int>(type: "INTEGER", nullable: false),
					SuccessCount = table.Column<int>(type: "INTEGER", nullable: false),
					FirstSeen = table.Column<DateTime>(type: "TEXT", nullable: false),
					LastSeen = table.Column<DateTime>(type: "TEXT", nullable: false),
					ThreatScore = table.Column<double>(type: "REAL", nullable: false),
					IsBlocked = table.Column<bool>(type: "INTEGER", nullable: false),
					BlockReason = table.Column<string>(type: "TEXT", maxLength: 512, nullable: true),
					UserNames = table.Column<string>(type: "TEXT", maxLength: 8192, nullable: true),
					IsPublicIp = table.Column<bool>(type: "INTEGER", nullable: false)
				},
				constraints: table =>
				{
					table.PrimaryKey("PK_Addresses", x => x.Id);
				});

			migrationBuilder.CreateTable(
				name: "Alerts",
				columns: table => new
				{
					Id = table.Column<long>(type: "INTEGER", nullable: false)
						.Annotation("Sqlite:Autoincrement", true),
					RuleId = table.Column<string>(type: "TEXT", maxLength: 64, nullable: false),
					Severity = table.Column<int>(type: "INTEGER", nullable: false),
					TimeUtc = table.Column<DateTime>(type: "TEXT", nullable: false),
					SourceIp = table.Column<string>(type: "TEXT", maxLength: 45, nullable: true),
					UserName = table.Column<string>(type: "TEXT", maxLength: 256, nullable: true),
					Message = table.Column<string>(type: "TEXT", maxLength: 2048, nullable: false),
					Details = table.Column<string>(type: "TEXT", maxLength: 65536, nullable: true),
					Acknowledged = table.Column<bool>(type: "INTEGER", nullable: false),
					TriggerEventId = table.Column<long>(type: "INTEGER", nullable: false)
				},
				constraints: table =>
				{
					table.PrimaryKey("PK_Alerts", x => x.Id);
				});

			migrationBuilder.CreateTable(
				name: "Bookmarks",
				columns: table => new
				{
					Channel = table.Column<string>(type: "TEXT", maxLength: 256, nullable: false),
					BookmarkXml = table.Column<string>(type: "TEXT", maxLength: 8192, nullable: false),
					UpdatedUtc = table.Column<DateTime>(type: "TEXT", nullable: false)
				},
				constraints: table =>
				{
					table.PrimaryKey("PK_Bookmarks", x => x.Channel);
				});

			migrationBuilder.CreateTable(
				name: "DbProps",
				columns: table => new
				{
					Key = table.Column<string>(type: "TEXT", maxLength: 128, nullable: false),
					Value = table.Column<string>(type: "TEXT", maxLength: 8192, nullable: true),
					UpdatedUtc = table.Column<DateTime>(type: "TEXT", nullable: false)
				},
				constraints: table =>
				{
					table.PrimaryKey("PK_DbProps", x => x.Key);
				});

			migrationBuilder.CreateTable(
				name: "Sessions",
				columns: table => new
				{
					Id = table.Column<long>(type: "INTEGER", nullable: false)
						.Annotation("Sqlite:Autoincrement", true),
					WtsSessionId = table.Column<int>(type: "INTEGER", nullable: false),
					UserName = table.Column<string>(type: "TEXT", maxLength: 256, nullable: true),
					Domain = table.Column<string>(type: "TEXT", maxLength: 256, nullable: true),
					SourceIp = table.Column<string>(type: "TEXT", maxLength: 45, nullable: true),
					ConnectUtc = table.Column<DateTime>(type: "TEXT", nullable: false),
					DisconnectUtc = table.Column<DateTime>(type: "TEXT", nullable: true),
					LogoffUtc = table.Column<DateTime>(type: "TEXT", nullable: true),
					LogonType = table.Column<int>(type: "INTEGER", nullable: true),
					LogonId = table.Column<string>(type: "TEXT", maxLength: 32, nullable: true),
					Status = table.Column<int>(type: "INTEGER", nullable: false),
					Flags = table.Column<string>(type: "TEXT", maxLength: 256, nullable: true)
				},
				constraints: table =>
				{
					table.PrimaryKey("PK_Sessions", x => x.Id);
				});

			migrationBuilder.CreateTable(
				name: "RawEvents",
				columns: table => new
				{
					Id = table.Column<long>(type: "INTEGER", nullable: false)
						.Annotation("Sqlite:Autoincrement", true),
					EventId = table.Column<int>(type: "INTEGER", nullable: false),
					Channel = table.Column<string>(type: "TEXT", maxLength: 256, nullable: false),
					TimeUtc = table.Column<DateTime>(type: "TEXT", nullable: false),
					SourceIp = table.Column<string>(type: "TEXT", maxLength: 45, nullable: true),
					UserName = table.Column<string>(type: "TEXT", maxLength: 256, nullable: true),
					Domain = table.Column<string>(type: "TEXT", maxLength: 256, nullable: true),
					SessionId = table.Column<int>(type: "INTEGER", nullable: true),
					LogonType = table.Column<int>(type: "INTEGER", nullable: true),
					LogonId = table.Column<string>(type: "TEXT", maxLength: 32, nullable: true),
					AuthPackage = table.Column<string>(type: "TEXT", maxLength: 64, nullable: true),
					Status = table.Column<string>(type: "TEXT", maxLength: 64, nullable: true),
					ProcessName = table.Column<string>(type: "TEXT", maxLength: 1024, nullable: true),
					CommandLine = table.Column<string>(type: "TEXT", maxLength: 8192, nullable: true),
					ObjectName = table.Column<string>(type: "TEXT", maxLength: 1024, nullable: true),
					AccessMask = table.Column<string>(type: "TEXT", maxLength: 32, nullable: true),
					Details = table.Column<string>(type: "TEXT", maxLength: 65536, nullable: true),
					Processed = table.Column<bool>(type: "INTEGER", nullable: false),
					AddressId = table.Column<long>(type: "INTEGER", nullable: true),
					SessionRefId = table.Column<long>(type: "INTEGER", nullable: true)
				},
				constraints: table =>
				{
					table.PrimaryKey("PK_RawEvents", x => x.Id);
					table.ForeignKey(
						name: "FK_RawEvents_Addresses_AddressId",
						column: x => x.AddressId,
						principalTable: "Addresses",
						principalColumn: "Id",
						onDelete: ReferentialAction.SetNull);
					table.ForeignKey(
						name: "FK_RawEvents_Sessions_SessionRefId",
						column: x => x.SessionRefId,
						principalTable: "Sessions",
						principalColumn: "Id",
						onDelete: ReferentialAction.SetNull);
				});

			migrationBuilder.CreateIndex(
				name: "IX_Addresses_Ip",
				table: "Addresses",
				column: "Ip",
				unique: true);

			migrationBuilder.CreateIndex(
				name: "IX_Addresses_IsBlocked",
				table: "Addresses",
				column: "IsBlocked");

			migrationBuilder.CreateIndex(
				name: "IX_Addresses_LastSeen",
				table: "Addresses",
				column: "LastSeen");

			migrationBuilder.CreateIndex(
				name: "IX_Alerts_Acknowledged",
				table: "Alerts",
				column: "Acknowledged");

			migrationBuilder.CreateIndex(
				name: "IX_Alerts_RuleId_TimeUtc",
				table: "Alerts",
				columns: new[] { "RuleId", "TimeUtc" });

			migrationBuilder.CreateIndex(
				name: "IX_Alerts_TimeUtc_Severity",
				table: "Alerts",
				columns: new[] { "TimeUtc", "Severity" });

			migrationBuilder.CreateIndex(
				name: "IX_RawEvents_AddressId",
				table: "RawEvents",
				column: "AddressId");

			migrationBuilder.CreateIndex(
				name: "IX_RawEvents_EventId_TimeUtc",
				table: "RawEvents",
				columns: new[] { "EventId", "TimeUtc" });

			migrationBuilder.CreateIndex(
				name: "IX_RawEvents_LogonId_TimeUtc",
				table: "RawEvents",
				columns: new[] { "LogonId", "TimeUtc" });

			migrationBuilder.CreateIndex(
				name: "IX_RawEvents_ObjectName_EventId",
				table: "RawEvents",
				columns: new[] { "ObjectName", "EventId" });

			migrationBuilder.CreateIndex(
				name: "IX_RawEvents_Processed_TimeUtc",
				table: "RawEvents",
				columns: new[] { "Processed", "TimeUtc" });

			migrationBuilder.CreateIndex(
				name: "IX_RawEvents_SessionId_TimeUtc",
				table: "RawEvents",
				columns: new[] { "SessionId", "TimeUtc" });

			migrationBuilder.CreateIndex(
				name: "IX_RawEvents_SessionRefId",
				table: "RawEvents",
				column: "SessionRefId");

			migrationBuilder.CreateIndex(
				name: "IX_RawEvents_SourceIp_TimeUtc",
				table: "RawEvents",
				columns: new[] { "SourceIp", "TimeUtc" });

			migrationBuilder.CreateIndex(
				name: "IX_Sessions_Status",
				table: "Sessions",
				column: "Status");

			migrationBuilder.CreateIndex(
				name: "IX_Sessions_UserName_ConnectUtc",
				table: "Sessions",
				columns: new[] { "UserName", "ConnectUtc" });

			migrationBuilder.CreateIndex(
				name: "IX_Sessions_WtsSessionId_ConnectUtc",
				table: "Sessions",
				columns: new[] { "WtsSessionId", "ConnectUtc" });
		}

		/// <inheritdoc />
		protected override void Down(MigrationBuilder migrationBuilder)
		{
			migrationBuilder.DropTable(
				name: "Alerts");

			migrationBuilder.DropTable(
				name: "Bookmarks");

			migrationBuilder.DropTable(
				name: "DbProps");

			migrationBuilder.DropTable(
				name: "RawEvents");

			migrationBuilder.DropTable(
				name: "Addresses");

			migrationBuilder.DropTable(
				name: "Sessions");
		}
	}
}
