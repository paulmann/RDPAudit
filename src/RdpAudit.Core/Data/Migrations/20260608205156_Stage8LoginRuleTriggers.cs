// File:    src/RdpAudit.Core/Data/Migrations/20260608205156_Stage8LoginRuleTriggers.cs
// Module:  RdpAudit.Core.Data.Migrations
// Purpose: Stage 8 — adds login trip-wire telemetry columns (DisplayLogin, TriggerCount,
//          FirstTriggeredUtc, LastTriggeredUtc, LastSourceIp) to the LoginRules table so the
//          Firewall tab can show original-case logins and per-rule firing history. Append-only.
// Extends: Microsoft.EntityFrameworkCore.Migrations.Migration
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace RdpAudit.Core.Data.Migrations
{
	/// <inheritdoc />
	public partial class Stage8LoginRuleTriggers : Migration
	{
		/// <inheritdoc />
		protected override void Up(MigrationBuilder migrationBuilder)
		{
			migrationBuilder.AddColumn<string>(
				name: "DisplayLogin",
				table: "LoginRules",
				type: "TEXT",
				maxLength: 256,
				nullable: true);

			migrationBuilder.AddColumn<DateTime>(
				name: "FirstTriggeredUtc",
				table: "LoginRules",
				type: "TEXT",
				nullable: true);

			migrationBuilder.AddColumn<string>(
				name: "LastSourceIp",
				table: "LoginRules",
				type: "TEXT",
				maxLength: 45,
				nullable: true);

			migrationBuilder.AddColumn<DateTime>(
				name: "LastTriggeredUtc",
				table: "LoginRules",
				type: "TEXT",
				nullable: true);

			migrationBuilder.AddColumn<long>(
				name: "TriggerCount",
				table: "LoginRules",
				type: "INTEGER",
				nullable: false,
				defaultValue: 0L);
		}

		/// <inheritdoc />
		protected override void Down(MigrationBuilder migrationBuilder)
		{
			migrationBuilder.DropColumn(
				name: "DisplayLogin",
				table: "LoginRules");

			migrationBuilder.DropColumn(
				name: "FirstTriggeredUtc",
				table: "LoginRules");

			migrationBuilder.DropColumn(
				name: "LastSourceIp",
				table: "LoginRules");

			migrationBuilder.DropColumn(
				name: "LastTriggeredUtc",
				table: "LoginRules");

			migrationBuilder.DropColumn(
				name: "TriggerCount",
				table: "LoginRules");
		}
	}
}
