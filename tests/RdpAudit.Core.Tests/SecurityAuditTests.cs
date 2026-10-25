// File:    tests/RdpAudit.Core.Tests/SecurityAuditTests.cs
// Module:  RdpAudit.Core.Tests
// Purpose: Locks the RouterOS security audit: the catalogue is complete and its weights are fixed,
//          every rule family fires on a fabricated snapshot, an unreadable menu becomes S-00 instead
//          of silence, an absent package is reported as unavailable rather than compliant, secrets
//          (SNMP community, script password, note text) never reach the evidence, and the report
//          renders to Markdown without leaking them.
//          The rules are proven here, without a router, because a security rule that is only
//          exercised against a live device is a rule nobody regression-tests.
// Extends: xunit
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System;
using System.Collections.Generic;
using System.Linq;
using RdpAudit.Core.MikroTik.SecurityAudit;
using Xunit;

namespace RdpAudit.Core.Tests;

public sealed class SecurityAuditTests
{
	private static readonly DateTime Captured = new(2026, 10, 23, 6, 0, 0, DateTimeKind.Utc);

	private static MikroTikSecuritySnapshot Snapshot()
		=> MikroTikSecuritySnapshot.CreatePasport(true, "rb-test", "7.23.1", "RB2011UiAS", "1d2h", Captured);

	private static Dictionary<string, string> Row(params (string Key, string Value)[] pairs)
	{
		Dictionary<string, string> row = new(StringComparer.Ordinal);
		foreach ((string key, string value) in pairs)
		{
			row[key] = value;
		}
		return row;
	}

	private static List<IReadOnlyDictionary<string, string>> Rows(params Dictionary<string, string>[] rows)
		=> rows.Cast<IReadOnlyDictionary<string, string>>().ToList();

	private static SecurityAuditFinding? Find(SecurityAuditReport report, string ruleId)
		=> report.Findings.FirstOrDefault(f => f.RuleId == ruleId);

	// ── catalogue ───────────────────────────────────────────────────────────────

	[Fact]
	public void Catalogue_HasEveryRuleExactlyOnce_AndReferenceWeights()
	{
		Assert.Equal(37, SecurityAuditCatalog.All.Count);

		string[] ids = SecurityAuditCatalog.All.Select(r => r.Id).ToArray();
		Assert.Equal(ids.Length, ids.Distinct(StringComparer.Ordinal).Count());

		for (int i = 0; i <= 35; i++)
		{
			string id = "S-" + i.ToString("00", System.Globalization.CultureInfo.InvariantCulture);
			Assert.NotNull(SecurityAuditCatalog.Find(id));
		}
		Assert.NotNull(SecurityAuditCatalog.Find("S-27b"));

		// Weights are part of the contract, not a presentation choice.
		Assert.Equal(40, SecurityAuditReport.WeightOf(SecurityAuditSeverity.Critical));
		Assert.Equal(15, SecurityAuditReport.WeightOf(SecurityAuditSeverity.High));
		Assert.Equal(5, SecurityAuditReport.WeightOf(SecurityAuditSeverity.Medium));
		Assert.Equal(1, SecurityAuditReport.WeightOf(SecurityAuditSeverity.Low));
		Assert.Equal(0, SecurityAuditReport.WeightOf(SecurityAuditSeverity.Info));
	}

	[Fact]
	public void Catalogue_EveryRuleStatesWhyAndWhatToDo()
	{
		foreach (SecurityAuditRule rule in SecurityAuditCatalog.All)
		{
			Assert.False(string.IsNullOrWhiteSpace(rule.Title));
			Assert.False(string.IsNullOrWhiteSpace(rule.Why));
			Assert.False(string.IsNullOrWhiteSpace(rule.Recommendation));
			Assert.False(string.IsNullOrWhiteSpace(rule.Menu));
		}
	}

	// ── S-00 and absent packages ────────────────────────────────────────────────

	[Fact]
	public void UnreadableMenu_BecomesS00_AndSilencesItsOwnRules()
	{
		MikroTikSecuritySnapshot snapshot = Snapshot();
		snapshot.AddError("services", "HTTP 401 Unauthorized");

		SecurityAuditReport report = SecurityAuditEvaluator.Evaluate(snapshot);

		SecurityAuditFinding finding = Assert.IsType<SecurityAuditFinding>(Find(report, "S-00"));
		Assert.Equal(SecurityAuditSeverity.High, finding.Severity);
		Assert.Contains("services", finding.Evidence, StringComparison.Ordinal);
		Assert.Contains("401", finding.Evidence, StringComparison.Ordinal);
		Assert.Null(Find(report, "S-04"));
	}

	[Fact]
	public void AbsentPackage_IsUnavailable_NotAFindingAndNotSilence()
	{
		MikroTikSecuritySnapshot snapshot = Snapshot();
		snapshot.AddUnavailable("containers");
		snapshot.AddRows("containers", Rows());

		SecurityAuditReport report = SecurityAuditEvaluator.Evaluate(snapshot);

		Assert.Contains("containers", report.UnavailableMenus);
		Assert.Null(Find(report, "S-34"));
		Assert.Null(Find(report, "S-00"));
	}

	// ── services ────────────────────────────────────────────────────────────────

	[Fact]
	public void OpenManagementServices_AreReportedWithTheirOwnIds()
	{
		MikroTikSecuritySnapshot snapshot = Snapshot();
		snapshot.AddRows("services", Rows(
			Row(("name", "ftp"), ("disabled", "false"), ("port", "21")),
			Row(("name", "telnet"), ("disabled", "false"), ("port", "23")),
			Row(("name", "www"), ("disabled", "false"), ("port", "80")),
			Row(("name", "api"), ("disabled", "false"), ("port", "8728")),
			Row(("name", "api-ssl"), ("disabled", "false"), ("port", "8729"), ("address", "")),
			Row(("name", "ssh"), ("disabled", "false"), ("port", "22"), ("address", "")),
			Row(("name", "winbox"), ("disabled", "false"), ("port", "8291"), ("address", "192.168.31.0/24")),
			Row(("name", "reverse-proxy"), ("disabled", "false"), ("port", "443"))));

		SecurityAuditReport report = SecurityAuditEvaluator.Evaluate(snapshot);

		Assert.Equal(SecurityAuditSeverity.Critical, Find(report, "S-04")!.Severity);
		Assert.Equal(SecurityAuditSeverity.Critical, Find(report, "S-05")!.Severity);
		Assert.Equal(SecurityAuditSeverity.High, Find(report, "S-06")!.Severity);
		Assert.Equal(SecurityAuditSeverity.Medium, Find(report, "S-09")!.Severity);

		// api without TLS is risky: disabling it can cut the channel the tool uses.
		SecurityAuditFinding api = Assert.IsType<SecurityAuditFinding>(Find(report, "S-07"));
		Assert.Equal(SecurityAuditAutofix.Risky, api.Autofix);

		// ssh and api-ssl have no address restriction; winbox does, so it must not be reported.
		Assert.Contains(report.Findings, f => f.RuleId == "S-08" && f.Title.Contains("ssh", StringComparison.Ordinal));
		Assert.Contains(report.Findings, f => f.RuleId == "S-08" && f.Title.Contains("api-ssl", StringComparison.Ordinal));
		Assert.DoesNotContain(report.Findings, f => f.RuleId == "S-08" && f.Title.Contains("winbox", StringComparison.Ordinal));
	}

	[Fact]
	public void DisabledService_IsNotAFinding()
	{
		MikroTikSecuritySnapshot snapshot = Snapshot();
		snapshot.AddRows("services", Rows(
			Row(("name", "ftp"), ("disabled", "true"), ("port", "21"))));

		SecurityAuditReport report = SecurityAuditEvaluator.Evaluate(snapshot);

		Assert.Null(Find(report, "S-04"));
	}

	// ── accounts ────────────────────────────────────────────────────────────────

	[Fact]
	public void FullAccountWithoutAddress_IsCritical_AndAdminIsFlagged()
	{
		MikroTikSecuritySnapshot snapshot = Snapshot();
		snapshot.AddRows("users", Rows(
			Row(("name", "admin"), ("group", "full"), ("address", ""), ("disabled", "false")),
			Row(("name", "backup"), ("group", "full"), ("address", ""), ("disabled", "false"))));

		SecurityAuditReport report = SecurityAuditEvaluator.Evaluate(snapshot, new SecurityAuditProfile { BackupUser = "backup" });

		Assert.NotNull(Find(report, "S-01"));
		Assert.NotNull(Find(report, "S-02"));
		// Two full accounts exist, so S-03 must stay silent.
		Assert.Null(Find(report, "S-03"));
		// The emergency account is excluded from S-01 by the profile.
		Assert.DoesNotContain(report.Findings, f => f.RuleId == "S-01" && f.Title.Contains("backup", StringComparison.Ordinal));
	}

	[Fact]
	public void SingleFullAccount_IsMediumS03()
	{
		MikroTikSecuritySnapshot snapshot = Snapshot();
		snapshot.AddRows("users", Rows(
			Row(("name", "rdpaudit"), ("group", "full"), ("address", "192.168.31.0/24"), ("disabled", "false"))));

		SecurityAuditReport report = SecurityAuditEvaluator.Evaluate(snapshot);

		Assert.Equal(SecurityAuditSeverity.Medium, Find(report, "S-03")!.Severity);
		Assert.Null(Find(report, "S-01"));
	}

	// ── firewall ────────────────────────────────────────────────────────────────

	[Fact]
	public void InputWithoutDrop_IsCritical_AndForwardIsCheckedSeparately()
	{
		MikroTikSecuritySnapshot snapshot = Snapshot();
		snapshot.AddRows("fw_filter", Rows(
			Row(("chain", "input"), ("action", "accept"), ("disabled", "false"), ("connection-state", "established,related"))));

		SecurityAuditReport report = SecurityAuditEvaluator.Evaluate(snapshot);

		Assert.Equal(SecurityAuditSeverity.Critical, Find(report, "S-20")!.Severity);
		Assert.NotNull(Find(report, "S-21"));
		Assert.NotNull(Find(report, "S-22"));
	}

	[Fact]
	public void BruteForceListRule_SatisfiesS22()
	{
		MikroTikSecuritySnapshot snapshot = Snapshot();
		snapshot.AddRows("fw_filter", Rows(
			Row(("chain", "input"), ("action", "drop"), ("disabled", "false")),
			Row(("chain", "forward"), ("action", "accept"), ("disabled", "false"), ("connection-state", "established,related")),
			Row(("chain", "forward"), ("action", "drop"), ("disabled", "false")),
			Row(("chain", "input"), ("action", "drop"), ("disabled", "false"), ("src-address-list", "rdpaudit_rdp_blocklist"))));

		SecurityAuditReport report = SecurityAuditEvaluator.Evaluate(snapshot);

		Assert.Null(Find(report, "S-20"));
		Assert.Null(Find(report, "S-21"));
		Assert.Null(Find(report, "S-22"));
	}

	// ── unneeded services ───────────────────────────────────────────────────────

	[Fact]
	public void UnneededServicesAndCloud_AreReported()
	{
		MikroTikSecuritySnapshot snapshot = Snapshot();
		snapshot.AddRows("socks", Rows(Row(("enabled", "true"))));
		snapshot.AddRows("upnp", Rows(Row(("enabled", "true"))));
		snapshot.AddRows("romon", Rows(Row(("enabled", "true"))));
		snapshot.AddRows("smb", Rows(Row(("enabled", "auto"), ("status", "running"))));
		snapshot.AddRows("cloud", Rows(Row(("ddns-enabled", "auto"))));

		SecurityAuditReport report = SecurityAuditEvaluator.Evaluate(snapshot);

		Assert.NotNull(Find(report, "S-13"));
		Assert.NotNull(Find(report, "S-14"));
		Assert.NotNull(Find(report, "S-15"));
		Assert.NotNull(Find(report, "S-16"));
		// "auto" is informational; a hard "yes" is medium.
		Assert.Equal(SecurityAuditSeverity.Info, Find(report, "S-17")!.Severity);
	}

	// ── secrets ─────────────────────────────────────────────────────────────────

	[Fact]
	public void SnmpCommunity_IsReportedWithoutPrintingTheCommunityString()
	{
		MikroTikSecuritySnapshot snapshot = Snapshot();
		snapshot.AddRows("snmp", Rows(Row(("enabled", "true"))));
		snapshot.AddRows("snmp_community", Rows(Row(("name", "public"), ("addresses", "0.0.0.0/0"), ("security", "none"))));

		SecurityAuditReport report = SecurityAuditEvaluator.Evaluate(snapshot);
		string rendered = SecurityAuditMarkdown.Render(report);

		SecurityAuditFinding finding = Assert.IsType<SecurityAuditFinding>(Find(report, "S-18"));
		Assert.DoesNotContain("public", finding.Evidence, StringComparison.OrdinalIgnoreCase);
		Assert.DoesNotContain("public", rendered, StringComparison.OrdinalIgnoreCase);
	}

	[Fact]
	public void ScriptCredential_IsReportedByNameAndKind_NeverByValue()
	{
		MikroTikSecuritySnapshot snapshot = Snapshot();
		snapshot.AddRows("scripts", Rows(
			Row(("name", "backup-upload"), ("source", ":local password=Sup3rSecret /tool fetch url=ftp://x"))));

		SecurityAuditReport report = SecurityAuditEvaluator.Evaluate(snapshot);
		string rendered = SecurityAuditMarkdown.Render(report);

		SecurityAuditFinding finding = Assert.IsType<SecurityAuditFinding>(Find(report, "S-29"));
		Assert.Equal(SecurityAuditSeverity.Critical, finding.Severity);
		Assert.Contains("backup-upload", finding.Evidence, StringComparison.Ordinal);
		Assert.Contains("password", finding.Evidence, StringComparison.OrdinalIgnoreCase);
		Assert.DoesNotContain("Sup3rSecret", finding.Evidence, StringComparison.Ordinal);
		Assert.DoesNotContain("Sup3rSecret", rendered, StringComparison.Ordinal);
	}

	[Fact]
	public void FlashBackupsAndNote_AreReported_WithoutNoteText()
	{
		MikroTikSecuritySnapshot snapshot = Snapshot();
		snapshot.AddRows("files", Rows(
			Row(("name", "rdpaudit_pre_bootstrap_20261020.backup")),
			Row(("name", "export.rsc")),
			Row(("name", "log.txt"))));
		snapshot.AddRows("note", Rows(Row(("note", "wifi password here"))));

		SecurityAuditReport report = SecurityAuditEvaluator.Evaluate(snapshot);

		Assert.Contains("2 files", Find(report, "S-30")!.Evidence, StringComparison.Ordinal);
		SecurityAuditFinding note = Assert.IsType<SecurityAuditFinding>(Find(report, "S-31"));
		Assert.Contains("18 characters", note.Evidence, StringComparison.Ordinal);
		Assert.DoesNotContain("wifi", note.Evidence, StringComparison.OrdinalIgnoreCase);
	}

	// ── platform ────────────────────────────────────────────────────────────────

	[Fact]
	public void RouterBootOlderThanRouterOs_IsReported()
	{
		MikroTikSecuritySnapshot snapshot = Snapshot();
		snapshot.AddRows("routerboard", Rows(Row(("current-firmware", "3.33"), ("upgrade-firmware", "7.23.1"))));

		SecurityAuditReport report = SecurityAuditEvaluator.Evaluate(snapshot);

		Assert.NotNull(Find(report, "S-26"));
		Assert.True(SecurityAuditEvaluator.CompareVersions("3.33", "7.23.1") < 0);
		Assert.Equal(0, SecurityAuditEvaluator.CompareVersions("7.23.1", "7.23.1"));
	}

	[Fact]
	public void ClockSkew_IsReportedOnlyWhenNtpIsOn()
	{
		MikroTikSecuritySnapshot snapshot = Snapshot();
		snapshot.AddRows("ntp", Rows(Row(("enabled", "true"))));
		snapshot.AddRows("clock", Rows(Row(
			("date", "2026-10-23"),
			("time", "09:00:00"),
			("time-zone-name", "Europe/Moscow"),
			("gmt-offset", "+03:00"))));

		// Device says 09:00 local; the evaluator is told it is 10:00 local two hours later.
		SecurityAuditReport drifting = SecurityAuditEvaluator.Evaluate(snapshot, new SecurityAuditProfile(), new DateTime(2026, 10, 23, 11, 30, 0));
		Assert.NotNull(Find(drifting, "S-27b"));
		Assert.Null(Find(drifting, "S-27"));

		SecurityAuditReport aligned = SecurityAuditEvaluator.Evaluate(snapshot, new SecurityAuditProfile(), new DateTime(2026, 10, 23, 9, 2, 0));
		Assert.Null(Find(aligned, "S-27b"));
	}

	[Fact]
	public void ParseRouterOsTime_HandlesBothWireFormats_AndRefusesJunk()
	{
		Assert.Equal(new DateTime(2026, 10, 20, 12, 34, 56), SecurityAuditEvaluator.ParseRouterOsTime("2026-10-20", "12:34:56"));
		Assert.Equal(new DateTime(2026, 10, 20, 12, 34, 0), SecurityAuditEvaluator.ParseRouterOsTime("oct/20/2026", "12:34"));
		Assert.Null(SecurityAuditEvaluator.ParseRouterOsTime(string.Empty, "12:34:56"));
		Assert.Null(SecurityAuditEvaluator.ParseRouterOsTime("2026-10-20", "junk"));
	}

	// ── report ──────────────────────────────────────────────────────────────────

	[Fact]
	public void Report_SortsWorstFirst_AndCapsTheRiskIndex()
	{
		MikroTikSecuritySnapshot snapshot = Snapshot();
		snapshot.AddRows("services", Rows(
			Row(("name", "ftp"), ("disabled", "false"), ("port", "21")),
			Row(("name", "telnet"), ("disabled", "false"), ("port", "23")),
			Row(("name", "www"), ("disabled", "false"), ("port", "80"))));
		snapshot.AddRows("users", Rows(Row(("name", "admin"), ("group", "full"), ("address", ""), ("disabled", "false"))));
		snapshot.AddRows("fw_filter", Rows(Row(("chain", "input"), ("action", "accept"), ("disabled", "false"))));

		SecurityAuditReport report = SecurityAuditEvaluator.Evaluate(snapshot);

		// S-01 + S-02 + S-04 + S-05 + S-06 + S-03 + S-20 = 40+15+40+40+15+5+40 = 195, capped at 100.
		Assert.Equal(100, report.RiskIndex);
		Assert.Equal("critical risk", report.Verdict);
		Assert.Equal(SecurityAuditSeverity.Critical, report.Findings[0].Severity);
		Assert.True(report.Findings.Count >= 6);
	}

	[Fact]
	public void Markdown_RendersSummaryTableAndDetails()
	{
		MikroTikSecuritySnapshot snapshot = Snapshot();
		snapshot.AddRows("services", Rows(Row(("name", "ftp"), ("disabled", "false"), ("port", "21"))));

		string markdown = SecurityAuditMarkdown.Render(SecurityAuditEvaluator.Evaluate(snapshot));

		Assert.Contains("# RouterOS security audit", markdown, StringComparison.Ordinal);
		Assert.Contains("| ID | Severity | Finding | Evidence | Autofix |", markdown, StringComparison.Ordinal);
		Assert.Contains("S-04", markdown, StringComparison.Ordinal);
		Assert.Contains("/ip/service disable [find name=ftp]", markdown, StringComparison.Ordinal);
		Assert.Contains("Risk index:", markdown, StringComparison.Ordinal);
	}

	[Fact]
	public void Markdown_DeviceSuppliedTextCannotReshapeTheDocument()
	{
		// Device name, board name and firmware strings come from the router over REST. A line break
		// used to start a new Markdown block in the rendered report (a heading, a link or an image the
		// operator's viewer would then fetch), and a backtick closed the inline code span an evidence
		// line was quoted in.
		MikroTikSecuritySnapshot snapshot = MikroTikSecuritySnapshot.CreatePasport(
			true, "rb\n# Injected heading", "7.23.1", "RB`2011", "1d2h", Captured);
		snapshot.AddRows("services", Rows(Row(("name", "ftp"), ("disabled", "false"), ("port", "21"))));

		string markdown = SecurityAuditMarkdown.Render(SecurityAuditEvaluator.Evaluate(snapshot));

		// The text is kept - only the structure is neutralised - so the operator still sees what the
		// device calls itself.
		Assert.Contains("rb # Injected heading", markdown, StringComparison.Ordinal);
		Assert.DoesNotContain("RB`2011", markdown, StringComparison.Ordinal);

		foreach (string line in markdown.Split('\n'))
		{
			Assert.False(
				line.TrimStart().StartsWith("# Injected heading", StringComparison.Ordinal),
				"a device-controlled line break became a Markdown block: " + line);
		}
	}

	[Fact]
	public void FirmwareComparison_DoesNotThrowOnAnOverlongDigitRun()
	{
		// The firmware strings come from the device over REST. A digit run longer than an int can
		// hold used to throw from int.Parse and abort the whole audit, so S-01..S-35 were never
		// reported for that router at all.
		int compare = SecurityAuditEvaluator.CompareVersions("7.23.1-99999999999", "7.24");

		Assert.Equal(-1, compare);
	}

	[Fact]
	public void FirmwareComparison_StillOrdersOrdinaryVersions()
	{
		Assert.True(SecurityAuditEvaluator.CompareVersions("7.22.1", "7.23") < 0);
		Assert.True(SecurityAuditEvaluator.CompareVersions("7.23", "7.22.1") > 0);
		Assert.Equal(0, SecurityAuditEvaluator.CompareVersions("7.23.1", "7.23.1"));
	}
}
