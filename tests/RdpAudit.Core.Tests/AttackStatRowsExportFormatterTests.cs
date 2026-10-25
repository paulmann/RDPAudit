// File:    tests/RdpAudit.Core.Tests/AttackStatRowsExportFormatterTests.cs
// Module:  RdpAudit.Core.Tests
// Purpose: Locks the RDP Activity "Export" submenu contracts. The load-bearing rules are the scope
//          classification (Selected / Red / Yellow / All), the deliberate but never silent exclusion
//          of the unresolved-IP sentinel row from the Red / Yellow scopes, and the projection of
//          AttackStatEntryDto onto the shared column set. The byte-level encoders (CSV quoting,
//          Markdown escaping, CR/LF neutralisation, extension mapping) are covered by
//          TableExportWriterTests, because they now live in one shared writer.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System.Text.Json;
using RdpAudit.Core.Ipc.Contracts;
using RdpAudit.Core.Models;
using Xunit;

namespace RdpAudit.Core.Tests;

/// <summary>RDP Activity row-export scope and projection coverage.</summary>
public class AttackStatRowsExportFormatterTests
{
	private static readonly DateTime Now = new(2026, 10, 12, 9, 30, 0, DateTimeKind.Utc);

	private static AttackStatEntryDto Row(
		string ip,
		AttackThreatLevel level,
		double score = 50d,
		bool isUnresolved = false) => new()
		{
			Ip = ip,
			ThreatLevel = level,
			ThreatScore = score,
			IsUnresolved = isUnresolved,
			Classification = "Public",
			TotalAttempts = 120,
			Failed = 118,
			Successful = 2,
			FirstSeenUtc = new DateTime(2026, 10, 11, 6, 0, 0, DateTimeKind.Utc),
			LastSeenUtc = new DateTime(2026, 10, 12, 6, 30, 0, DateTimeKind.Utc),
			DurationSeconds = 88_200,
			Top10AttemptedLogins = "[\"administrator\",\"root\"]",
			LastLoginType = 3,
			IsBlocked = true,
			LastUpdatedUtc = new DateTime(2026, 10, 12, 6, 31, 0, DateTimeKind.Utc),
			FactFailedLogons = 118,
			FactSuccessfulLogons = 2,
			HasActiveConnectionFact = true,
			IsHighRisk = true,
			ThreatIntelConfidenceScore = 95,
		};

	private static AttackStatEntryDto SentinelRow() => new()
	{
		Ip = AttackStatsAggregator.SentinelUnresolvedIp,
		ThreatLevel = AttackThreatLevel.Red,
		ThreatScore = 100d,
		IsUnresolved = true,
		Classification = "Unresolved",
		TotalAttempts = 9,
		Failed = 9,
		FirstSeenUtc = new DateTime(2026, 10, 11, 6, 0, 0, DateTimeKind.Utc),
		LastSeenUtc = new DateTime(2026, 10, 12, 6, 0, 0, DateTimeKind.Utc),
		LastUpdatedUtc = new DateTime(2026, 10, 12, 6, 1, 0, DateTimeKind.Utc),
	};

	private static AttackStatRowsExportContext Context() => new()
	{
		NowUtc = Now,
		FilterSummary = "IP contains \"203.\"; min threat score 50; only blocked",
		VisibleRowCount = 4,
	};

	private static AttackStatRowsExportSelection Select(
		IReadOnlyList<AttackStatEntryDto> rows,
		AttackStatRowScope scope) =>
		AttackStatRowsExportFormatter.Select(rows, scope);

	private static TabularExportDocument Document(
		IReadOnlyList<AttackStatEntryDto> rows,
		AttackStatRowScope scope) =>
		AttackStatRowsExportFormatter.BuildDocument(Select(rows, scope), Context());

	private static string Format(
		AttackStatRowsExportSelection selection,
		TableExportFormat format) =>
		AttackStatRowsExportFormatter.Format(selection, Context(), format);

	[Fact]
	public void RedScope_KeepsOnlyRedAttackerRows()
	{
		List<AttackStatEntryDto> rows =
		[
			Row("203.0.113.7", AttackThreatLevel.Red, 80d),
			Row("203.0.113.8", AttackThreatLevel.Yellow, 40d),
			Row("203.0.113.9", AttackThreatLevel.Green, 5d),
		];

		AttackStatRowsExportSelection selection = Select(rows, AttackStatRowScope.RedRows);

		Assert.Equal("203.0.113.7", Assert.Single(selection.Rows).Ip);
		Assert.Equal(0, selection.ExcludedSentinels);
	}

	[Fact]
	public void YellowScope_KeepsOnlyYellowRows()
	{
		List<AttackStatEntryDto> rows =
		[
			Row("203.0.113.7", AttackThreatLevel.Red, 80d),
			Row("203.0.113.8", AttackThreatLevel.Yellow, 40d),
			Row("203.0.113.9", AttackThreatLevel.Yellow, 35d),
		];

		AttackStatRowsExportSelection selection = Select(rows, AttackStatRowScope.YellowRows);

		Assert.Equal(new[] { "203.0.113.8", "203.0.113.9" }, selection.Rows.Select(r => r.Ip));
	}

	[Fact]
	public void RedScope_ExcludesTheUnresolvedSentinel_AndCountsIt()
	{
		List<AttackStatEntryDto> rows =
		[
			Row("203.0.113.7", AttackThreatLevel.Red, 80d),
			SentinelRow(),
		];

		AttackStatRowsExportSelection selection = Select(rows, AttackStatRowScope.RedRows);

		Assert.Equal("203.0.113.7", Assert.Single(selection.Rows).Ip);
		Assert.Equal(1, selection.ExcludedSentinels);
		// The exclusion must be visible to the operator, not silent.
		Assert.Contains("excluded", selection.Describe(), StringComparison.OrdinalIgnoreCase);
	}

	[Fact]
	public void AllScope_KeepsTheSentinelAndEveryBand()
	{
		List<AttackStatEntryDto> rows =
		[
			Row("203.0.113.7", AttackThreatLevel.Red, 80d),
			SentinelRow(),
			Row("203.0.113.9", AttackThreatLevel.Green, 5d),
		];

		AttackStatRowsExportSelection selection = Select(rows, AttackStatRowScope.AllRows);

		Assert.Equal(3, selection.Rows.Count);
		Assert.Equal(0, selection.ExcludedSentinels);
	}

	[Fact]
	public void SelectedScope_KeepsExactlyWhatWasPassed_EvenTheSentinel()
	{
		List<AttackStatEntryDto> selected = [SentinelRow(), Row("203.0.113.8", AttackThreatLevel.Yellow, 40d)];

		AttackStatRowsExportSelection selection = Select(selected, AttackStatRowScope.Selected);

		Assert.Equal(2, selection.Rows.Count);
		Assert.Equal(0, selection.ExcludedSentinels);
	}

	[Fact]
	public void SentinelDetection_FollowsEitherTheFlagOrTheAddress()
	{
		// A row whose IsUnresolved flag was not set but whose address is the sentinel must still be
		// recognised, so the Red scope cannot leak it through a DTO that only carries the address.
		AttackStatEntryDto byAddress = Row(AttackStatsAggregator.SentinelUnresolvedIp, AttackThreatLevel.Red);

		Assert.True(AttackStatRowsExportFormatter.IsUnresolvedSentinel(byAddress));
		Assert.True(AttackStatRowsExportFormatter.IsUnresolvedSentinel(SentinelRow()));
		Assert.False(AttackStatRowsExportFormatter.IsUnresolvedSentinel(Row("203.0.113.7", AttackThreatLevel.Red)));
	}

	[Fact]
	public void EmptyScope_StillProducesAValidDocument()
	{
		List<AttackStatEntryDto> rows = [Row("203.0.113.9", AttackThreatLevel.Green, 5d)];
		AttackStatRowsExportSelection selection = Select(rows, AttackStatRowScope.RedRows);

		Assert.Empty(selection.Rows);

		using JsonDocument parsed = JsonDocument.Parse(Format(selection, TableExportFormat.Json));
		Assert.Equal(0, parsed.RootElement.GetProperty("rowCount").GetInt32());

		string csv = Format(selection, TableExportFormat.Csv);
		Assert.Contains("Ip,ThreatScore,ThreatLevel", csv, StringComparison.Ordinal);
	}

	[Fact]
	public void Document_DeclaresTheSourceScopeAndColumnSet()
	{
		TabularExportDocument document = Document(
			[Row("203.0.113.7", AttackThreatLevel.Red, 80d)],
			AttackStatRowScope.RedRows);

		Assert.Equal("RDP Activity", document.Source);
		Assert.Equal("Red rows", document.Scope);
		Assert.Equal(20, document.Columns.Count);
		Assert.Single(document.Rows);
		Assert.Equal(20, document.Rows[0].Count);
		Assert.Equal(4, document.VisibleRowCount);
		Assert.Contains("min threat score 50", document.FilterSummary!, StringComparison.Ordinal);
	}

	/// <summary>
	/// A file that lists fewer red rows than the grid showed must explain itself, so the sentinel
	/// exclusion is recorded in the provenance that every format writes.
	/// </summary>
	[Fact]
	public void Document_RecordsTheSentinelExclusionInTheProvenance()
	{
		TabularExportDocument document = Document(
			[Row("203.0.113.7", AttackThreatLevel.Red, 80d), SentinelRow()],
			AttackStatRowScope.RedRows);

		Assert.Contains("unresolved-IP rows excluded: 1", document.FilterSummary!, StringComparison.Ordinal);
	}

	[Fact]
	public void Json_DeclaresTheSchemaScopeAndRowValues()
	{
		using JsonDocument parsed = JsonDocument.Parse(Format(
			Select([Row("203.0.113.7", AttackThreatLevel.Red, 80d)], AttackStatRowScope.RedRows),
			TableExportFormat.Json));
		JsonElement root = parsed.RootElement;

		Assert.Equal(TabularExportWriter.JsonSchema, root.GetProperty("schema").GetString());
		Assert.Equal("RDP Activity", root.GetProperty("source").GetString());
		Assert.Equal("Red rows", root.GetProperty("scope").GetString());
		Assert.Equal("2026-10-12 09:30:00", root.GetProperty("generatedUtc").GetString());
		Assert.Equal(1, root.GetProperty("rowCount").GetInt32());
		Assert.Equal(20, root.GetProperty("columns").GetArrayLength());

		// Values are emitted as arrays in column order, so duplicate header text cannot drop a column.
		JsonElement firstRow = root.GetProperty("rows")[0];
		Assert.Equal(20, firstRow.GetArrayLength());
		Assert.Equal("203.0.113.7", firstRow[0].GetString());
		Assert.Equal("80.0", firstRow[1].GetString());
		Assert.Equal("Red", firstRow[2].GetString());
	}

	[Fact]
	public void Txt_And_Csv_ShareTheSameColumnOrder()
	{
		AttackStatRowsExportSelection selection = Select(
			[Row("203.0.113.7", AttackThreatLevel.Red, 80d)],
			AttackStatRowScope.RedRows);

		string txt = Format(selection, TableExportFormat.Txt);
		string[] txtLines = txt.Split('\n', StringSplitOptions.RemoveEmptyEntries);
		string csv = Format(selection, TableExportFormat.Csv);
		string[] csvLines = csv.Split('\n', StringSplitOptions.RemoveEmptyEntries);

		// The first cell of both tabular bodies is the same column, whatever the surrounding preamble.
		Assert.StartsWith("Ip\t", txtLines.First(l => l.StartsWith("Ip\t", StringComparison.Ordinal)), StringComparison.Ordinal);
		Assert.StartsWith("Ip,", csvLines.First(l => l.StartsWith("Ip,", StringComparison.Ordinal)), StringComparison.Ordinal);
	}

	[Fact]
	public void Format_RejectsAnUnknownFormat_AndANullSelection()
	{
		AttackStatRowsExportSelection selection = Select([Row("203.0.113.7", AttackThreatLevel.Red)], AttackStatRowScope.RedRows);

		Assert.Throws<ArgumentOutOfRangeException>(
			() => AttackStatRowsExportFormatter.Format(selection, Context(), (TableExportFormat)99));
		Assert.Throws<ArgumentNullException>(
			() => AttackStatRowsExportFormatter.Format(null!, Context(), TableExportFormat.Json));
		Assert.Throws<ArgumentNullException>(
			() => AttackStatRowsExportFormatter.Format(selection, null!, TableExportFormat.Json));
		Assert.Throws<ArgumentOutOfRangeException>(
			() => AttackStatRowsExportFormatter.Select([], (AttackStatRowScope)99));
	}
}
