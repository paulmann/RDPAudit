/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 2.0.0
// File   : DatabaseGovernanceDtoTests.cs
// Project: RdpAudit.Core.Tests (RdpAudit.Core.Tests)
// Purpose: Locks the Stage 2a IPC contracts: the new DTOs must survive the JSON round trip the
//          named-pipe transport actually performs, with camelCase member names and enums as names,
//          and the nullable members that carry an honest "unknown" (the reclaimed-bytes estimate,
//          the failure-marker timestamp) must stay distinguishable from a real zero.
// Depends: RdpAudit.Core.Ipc.Contracts, RdpAudit.Core.Util.JsonOptions, xUnit
// Extends: Add an assertion here whenever a Stage 2a DTO gains a member clients depend on.

using System.Text.Json;
using RdpAudit.Core.Config;
using RdpAudit.Core.Ipc.Contracts;
using RdpAudit.Core.Models;
using RdpAudit.Core.Retention;
using RdpAudit.Core.Util;
using Xunit;

namespace RdpAudit.Core.Tests;

/// <summary>Locks the wire shape of the Database-tab DTOs.</summary>
public sealed class DatabaseGovernanceDtoTests
{
	// ── DatabaseOverviewDto ──────────────────────────────────────────────────────

	[Fact]
	public void DatabaseOverviewDto_JsonRoundTrip_PreservesEveryReportedField()
	{
		DateTime nowUtc = new(2026, 9, 14, 10, 30, 0, DateTimeKind.Utc);
		DatabaseOverviewDto source = new()
		{
			Status = IpcResultStatus.Success,
			QueriedUtc = nowUtc,
			DatabasePath = @"C:\ProgramData\RdpAudit\rdpaudit.db",
			DatabaseBytes = 1024,
			WalBytes = 2048,
			ShmBytes = 32,
			TotalDatabaseFamilyBytes = 3104,
			DatabaseVolumeRoot = @"C:\",
			DatabaseVolumeFreeBytes = 5_000_000,
			DatabaseVolumeTotalBytes = 100_000_000,
			ActionsRoot = @"C:\ProgramData\RdpAudit\actions",
			ActionsBytes = 4096,
			ActionsFileCount = 7,
			ShardCount = 3,
			MaxShardFiles = 4096,
			ShardingEnabled = true,
			RetentionPolicyEnabled = true,
			LegalHold = false,
			MaxDatabaseBytes = 1_000_000,
			MaxRawEventRows = 500,
			MinFreeDiskBytes = 100,
			GrowthBytesDay = 10,
			GrowthBytesWeek = 70,
			GrowthBytesMonth = 300,
			ProjectedDaysToCap = 3322,
			GrowthNote = "Projected from the month-over-month growth of 300 bytes over 30 days.",
			LedgerEntryCount = 12,
			LedgerRowsDeleted = 987,
			LedgerLastCreatedUtc = nowUtc.AddHours(-1),
			MigrationFailureMarkerPresent = true,
			MigrationFailureUtc = nowUtc.AddDays(-2),
			MigrationFailureMessage = "SqliteException",
			IsPartial = true,
		};
		source.TableRowCounts.Add(new DatabaseTableRowCountDto { Table = "RawEvents", RowCount = 42 });
		source.TableRowCounts.Add(new DatabaseTableRowCountDto { Table = "Alerts", RowCount = -1, Error = "unreadable" });
		source.AppliedMigrations.Add("20260914160902_Stage17EventDeletionLedger");
		source.PendingMigrations.Add("20260915000000_Stage18Example");
		source.MigrationFailurePendingMigrations.Add("20260915000000_Stage18Example");
		source.Sections.Add(new DatabaseOverviewSectionDto
		{
			Section = "DbCounts",
			DurationMs = 12,
			Status = "Failed",
			Error = "SqliteException - no such table",
		});
		source.Warnings.Add("Database overview section 'DbCounts' failed: SqliteException");

		string json = JsonSerializer.Serialize(source, JsonOptions.Default);
		Assert.Contains("\"databasePath\"", json, StringComparison.Ordinal);
		Assert.Contains("\"tableRowCounts\"", json, StringComparison.Ordinal);
		Assert.Contains("\"isPartial\":true", json, StringComparison.Ordinal);

		DatabaseOverviewDto? round = JsonSerializer.Deserialize<DatabaseOverviewDto>(json, JsonOptions.Default);
		Assert.NotNull(round);
		Assert.Equal(source.DatabasePath, round!.DatabasePath);
		Assert.Equal(source.TotalDatabaseFamilyBytes, round.TotalDatabaseFamilyBytes);
		Assert.Equal(source.ActionsBytes, round.ActionsBytes);
		Assert.Equal(source.ShardCount, round.ShardCount);
		Assert.Equal(source.ProjectedDaysToCap, round.ProjectedDaysToCap);
		Assert.Equal(source.LedgerRowsDeleted, round.LedgerRowsDeleted);
		Assert.True(round.MigrationFailureMarkerPresent);
		Assert.Equal(source.MigrationFailureUtc, round.MigrationFailureUtc);
		Assert.Equal(2, round.TableRowCounts.Count);
		Assert.Equal(-1, round.TableRowCounts[1].RowCount);
		Assert.Equal("unreadable", round.TableRowCounts[1].Error);
		Assert.Single(round.AppliedMigrations);
		Assert.True(round.IsPartial);
		Assert.Single(round.Warnings);
	}

	// ── RetentionPolicyDto ───────────────────────────────────────────────────────

	[Fact]
	public void RetentionPolicyDto_JsonRoundTrip_ReportsConfiguredAndEffectiveValues()
	{
		RetentionPolicyDto source = new()
		{
			Status = IpcResultStatus.Success,
			QueriedUtc = new DateTime(2026, 9, 14, 10, 30, 0, DateTimeKind.Utc),
			ConfigPath = @"C:\ProgramData\RdpAudit\appsettings.json",
			Policy = new RetentionPolicyValuesDto
			{
				Enabled = true,
				LegalHold = false,
				AnchorScope = RetentionAnchorScope.PerCodeAndIp,
				EffectiveAnchorScope = RetentionAnchorScope.PerCodeAndIp,
				ProtectedEventIds = [4720],
				EffectiveProtectedEventIds = [4672, 4720],
				TailKeepPerCode = 4,
				EffectiveTailKeepPerCode = 512,
				CandidateMinRows = 1,
				EffectiveCandidateMinRows = 10,
				MinAgeDays = 0,
				EffectiveMinAgeDays = 1,
				MaxRowsPerPass = 50_000,
				EffectiveMaxRowsPerPass = 50_000,
				MaxWriterLockMs = 250,
				EffectiveMaxWriterLockMs = 250,
				DeleteBatchRows = 2_000,
				EffectiveDeleteBatchRows = 2_000,
				MaxDatabaseBytes = -5,
				EffectiveMaxDatabaseBytes = 0,
				MaxRawEventRows = 100,
				EffectiveMaxRawEventRows = 100,
				MinFreeDiskBytes = 0,
				EffectiveMinFreeDiskBytes = 0,
				HasAnyPressureTrigger = true,
				PressureDeletionAllowed = true,
			},
		};
		source.GlobalWindows = new RetentionWindowsDto { EventRetentionDays = 365, LogRetentionDays = 90 };
		source.EventWindows.Add(new EventRetentionWindowDto
		{
			EventId = 4625,
			Channel = "Security",
			DisplayName = "Failed logon",
			RetentionDays = 30,
			DefaultRetentionDays = 180,
			UpdatedUtc = new DateTime(2026, 9, 1, 0, 0, 0, DateTimeKind.Utc),
		});

		string json = JsonSerializer.Serialize(source, JsonOptions.Default);
		Assert.Contains("\"effectiveTailKeepPerCode\":512", json, StringComparison.Ordinal);
		Assert.Contains("\"anchorScope\":\"PerCodeAndIp\"", json, StringComparison.Ordinal);

		RetentionPolicyDto? round = JsonSerializer.Deserialize<RetentionPolicyDto>(json, JsonOptions.Default);
		Assert.NotNull(round);
		Assert.Equal(4, round!.Policy.TailKeepPerCode);
		Assert.Equal(512, round.Policy.EffectiveTailKeepPerCode);
		Assert.Equal(1, round.Policy.CandidateMinRows);
		Assert.Equal(10, round.Policy.EffectiveCandidateMinRows);
		Assert.Equal(-5, round.Policy.MaxDatabaseBytes);
		Assert.Equal(0, round.Policy.EffectiveMaxDatabaseBytes);
		Assert.Equal(RetentionAnchorScope.PerCodeAndIp, round.Policy.EffectiveAnchorScope);
		Assert.Equal(2, round.Policy.EffectiveProtectedEventIds.Count);
		Assert.Equal(365, round.GlobalWindows.EventRetentionDays);
		Assert.Single(round.EventWindows);
		Assert.Equal(180, round.EventWindows[0].DefaultRetentionDays);
		Assert.Equal(RetentionPolicyOptions.MinTailKeepPerCode, round.Policy.Bounds.MinTailKeepPerCode);
		Assert.Equal(RetentionPolicyOptions.MaxMinAgeDays, round.Policy.Bounds.MaxMinAgeDays);
	}

	[Fact]
	public void RetentionPolicyMutationRequest_JsonRoundTrip_AllowsPartialSections()
	{
		string json = """
			{ "policy": { "enabled": true }, "eventWindows": [ { "eventId": 4625, "retentionDays": 14 } ], "eventWindowsReplaceAll": true }
			""";

		RetentionPolicyMutationRequest? request =
			JsonSerializer.Deserialize<RetentionPolicyMutationRequest>(json, JsonOptions.Default);

		Assert.NotNull(request);
		Assert.NotNull(request!.Policy);
		Assert.True(request.Policy!.Enabled);
		Assert.Null(request.GlobalWindows);
		Assert.True(request.EventWindowsReplaceAll);
		Assert.Single(request.EventWindows);
		Assert.Equal(4625, request.EventWindows[0].EventId);
		Assert.Equal(14, request.EventWindows[0].RetentionDays);
	}

	// ── RetentionPreviewDto ──────────────────────────────────────────────────────

	[Fact]
	public void RetentionPreviewDto_JsonRoundTrip_KeepsTheReclaimedBytesEstimateNull()
	{
		DateTime windowStart = new(2026, 8, 1, 0, 0, 0, DateTimeKind.Utc);
		RetentionPreviewDto source = new()
		{
			Status = IpcResultStatus.Success,
			PolicyEnabled = true,
			LegalHold = false,
			Trigger = EventDeletionTrigger.RawEventRows,
			TriggerWouldFire = true,
			WouldDeleteRows = 294,
			EstimatedReclaimedBytes = null,
			ReclaimedBytesNote = "Not estimated.",
			RuleVersion = RetentionRuleVersion.Current,
			MinAgeCutoffUtc = new DateTime(2026, 9, 7, 0, 0, 0, DateTimeKind.Utc),
			TailKeepPerCode = 5,
			MaxRowsPerPass = 1000,
			SkippedCodeCount = 1,
			QueriedUtc = new DateTime(2026, 9, 14, 0, 0, 0, DateTimeKind.Utc),
		};
		source.Codes.Add(new RetentionPreviewCodeDto
		{
			EventId = 4625,
			Channel = "Security",
			Count = 300,
			EligibleInteriorRows = 294,
			PlannedRows = 294,
			Explanation = "Would be compressed.",
			OldestRetainedUtc = windowStart,
			OldestDeletedUtc = windowStart.AddMinutes(1),
			NewestDeletedUtc = windowStart.AddMinutes(294),
		});
		source.Codes.Add(new RetentionPreviewCodeDto
		{
			EventId = 4720,
			Channel = "Security",
			SkipReason = RetentionSkipReason.ProtectedEventCode,
			Explanation = "Protected.",
		});
		source.Steps.Add(new RetentionPreviewStepDto
		{
			Order = 0,
			EventId = 4625,
			Channel = "Security",
			Rows = 294,
			AnchorRowId = 1,
			AnchorTimeUtc = windowStart,
			TailBoundaryRowId = 296,
			TailBoundaryTimeUtc = windowStart.AddMinutes(295),
			WindowStartUtc = windowStart.AddMinutes(1),
			WindowEndUtc = windowStart.AddMinutes(294),
		});

		string json = JsonSerializer.Serialize(source, JsonOptions.Default);
		// An honest null must stay absent rather than becoming a literal zero the UI could render.
		Assert.DoesNotContain("estimatedReclaimedBytes", json, StringComparison.Ordinal);
		Assert.Contains("\"trigger\":\"RawEventRows\"", json, StringComparison.Ordinal);
		Assert.Contains("\"skipReason\":\"ProtectedEventCode\"", json, StringComparison.Ordinal);

		RetentionPreviewDto? round = JsonSerializer.Deserialize<RetentionPreviewDto>(json, JsonOptions.Default);
		Assert.NotNull(round);
		Assert.Null(round!.EstimatedReclaimedBytes);
		Assert.Equal(EventDeletionTrigger.RawEventRows, round.Trigger);
		Assert.True(round.TriggerWouldFire);
		Assert.Equal(294, round.WouldDeleteRows);
		Assert.Equal(2, round.Codes.Count);
		Assert.Null(round.Codes[0].SkipReason);
		Assert.Equal(RetentionSkipReason.ProtectedEventCode, round.Codes[1].SkipReason);
		Assert.Single(round.Steps);
		Assert.Equal(294, round.Steps[0].Rows);
		Assert.Equal(windowStart.AddMinutes(1), round.Steps[0].WindowStartUtc);
	}

	// ── DeletionLedger DTOs ──────────────────────────────────────────────────────

	[Fact]
	public void DeletionLedgerPageDto_JsonRoundTrip_PreservesTheLedgerEvidence()
	{
		DateTime createdUtc = new(2026, 9, 14, 9, 0, 0, DateTimeKind.Utc);
		DeletionLedgerPageDto source = new()
		{
			Status = IpcResultStatus.Success,
			TotalMatching = 1,
			Page = 0,
			PageSize = 100,
			HasMore = false,
			QueriedUtc = createdUtc,
		};
		source.Items.Add(new DeletionLedgerEntryDto
		{
			Id = 7,
			EventCode = 4625,
			Scope = EventDeletionScope.PerIp,
			IpHex = "0A00002A",
			WindowStartUtc = createdUtc.AddDays(-30),
			WindowEndUtc = createdUtc.AddDays(-29),
			RowsDeleted = 412,
			Trigger = EventDeletionTrigger.DatabaseBytes,
			RuleVersion = 1,
			Reason = "IDR-1 information-density retention; trigger=DatabaseBytes; code=Security/4625",
			InitiatedBy = "Service",
			CreatedUtc = createdUtc,
		});

		string json = JsonSerializer.Serialize(source, JsonOptions.Default);
		Assert.Contains("\"ipHex\":\"0A00002A\"", json, StringComparison.Ordinal);
		Assert.Contains("\"scope\":\"PerIp\"", json, StringComparison.Ordinal);

		DeletionLedgerPageDto? round = JsonSerializer.Deserialize<DeletionLedgerPageDto>(json, JsonOptions.Default);
		Assert.NotNull(round);
		Assert.Single(round!.Items);
		Assert.Equal(EventDeletionScope.PerIp, round.Items[0].Scope);
		Assert.Equal("0A00002A", round.Items[0].IpHex);
		Assert.Equal(412, round.Items[0].RowsDeleted);
		Assert.Equal(EventDeletionTrigger.DatabaseBytes, round.Items[0].Trigger);
		Assert.Equal("Service", round.Items[0].InitiatedBy);
	}

	[Fact]
	public void DeletionLedgerQueryRequest_JsonRoundTrip_LeavesOmittedFiltersNull()
	{
		string json = """{ "eventCode": 4625, "page": 2, "pageSize": 50 }""";

		DeletionLedgerQueryRequest? request =
			JsonSerializer.Deserialize<DeletionLedgerQueryRequest>(json, JsonOptions.Default);

		Assert.NotNull(request);
		Assert.Equal(4625, request!.EventCode);
		Assert.Null(request.FromUtc);
		Assert.Null(request.ToUtc);
		Assert.Null(request.Scope);
		Assert.Null(request.IpHex);
		Assert.Equal(2, request.Page);
		Assert.Equal(50, request.PageSize);
	}
}
