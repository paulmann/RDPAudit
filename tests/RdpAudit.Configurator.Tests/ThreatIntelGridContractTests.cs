// File:    tests/RdpAudit.Configurator.Tests/ThreatIntelGridContractTests.cs
// Module:  RdpAudit.Configurator.Tests
// Purpose: Targeted contract tests for the Stage 15 High-risk grid binding introduced in
//          Backlog #5. AttackStatisticsPage.AttackStatRow must map the append-only DTO keys
//          (IsHighRisk / ThreatIntelConfidenceScore) onto the display text the new "High risk"
//          column renders, and LiveEventsPage.LiveEventRow must round-trip the camelCase wire
//          fields (isHighRisk / threatIntelConfidenceScore) while the computed HighRiskDisplay
//          stays a UI-only property excluded from serialization.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System.Text.Json;
using RdpAudit.Configurator.Forms;
using RdpAudit.Core.Ipc.Contracts;
using Xunit;

namespace RdpAudit.Configurator.Tests;

public sealed class ThreatIntelGridContractTests
{
	private static AttackStatEntryDto MakeEntry(bool isHighRisk, int score) => new()
	{
		Ip = "203.0.113.7",
		IsHighRisk = isHighRisk,
		ThreatIntelConfidenceScore = score,
	};

	[Fact]
	public void AttackStatRow_From_HighRiskEntry_MapsFlagScoreAndDisplayText()
	{
		AttackStatisticsPage.AttackStatRow row =
			AttackStatisticsPage.AttackStatRow.From(MakeEntry(isHighRisk: true, score: 95));

		Assert.True(row.IsHighRisk);
		Assert.Equal(95, row.ThreatIntelConfidenceScore);
		Assert.Equal("yes (95)", row.HighRiskDisplay);
	}

	[Fact]
	public void AttackStatRow_From_FailClosedEntry_RendersNo()
	{
		AttackStatisticsPage.AttackStatRow row =
			AttackStatisticsPage.AttackStatRow.From(MakeEntry(isHighRisk: false, score: 0));

		Assert.False(row.IsHighRisk);
		Assert.Equal(0, row.ThreatIntelConfidenceScore);
		Assert.Equal("no", row.HighRiskDisplay);
	}

	[Fact]
	public void LiveEventRow_JsonRoundTrip_BindsThreatFields_AndExcludesDisplayProperty()
	{
		string json = """
			{
				"id": 42,
				"eventId": 4625,
				"sourceIp": "203.0.113.7",
				"isHighRisk": true,
				"threatIntelConfidenceScore": 95
			}
			""";

		LiveEventsPage.LiveEventRow? row =
			JsonSerializer.Deserialize<LiveEventsPage.LiveEventRow>(json, Core.Util.JsonOptions.Default);

		Assert.NotNull(row);
		Assert.True(row!.IsHighRisk);
		Assert.Equal(95, row.ThreatIntelConfidenceScore);
		Assert.Equal("yes (95)", row.HighRiskDisplay);

		string serialized = JsonSerializer.Serialize(row, Core.Util.JsonOptions.Default);
		Assert.Contains("\"isHighRisk\":true", serialized);
		Assert.Contains("\"threatIntelConfidenceScore\":95", serialized);
		Assert.DoesNotContain("highRiskDisplay", serialized);
	}

	[Fact]
	public void LiveEventRow_DefaultInstance_IsFailClosed()
	{
		LiveEventsPage.LiveEventRow row = new();

		Assert.False(row.IsHighRisk);
		Assert.Equal(0, row.ThreatIntelConfidenceScore);
		Assert.Equal("no", row.HighRiskDisplay);
	}
}
