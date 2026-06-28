// File:    tests/RdpAudit.Core.Tests/FirewallDiagnosticsScannerBackendTests.cs
// Module:  RdpAudit.Core.Tests
// Purpose: Verifies the diagnostics report surfaces (a) which firewall-scanner backend was used plus
//          the manual-equivalent PowerShell command, (b) a locale-risk warning when the fragile
//          netsh text backend was used, (c) honest third-party (Kaspersky) wording that never claims
//          "no interference" when a third-party firewall is detected and never blames it when the
//          scanner itself was the failing path, and (d) clearly-labeled enforcement count buckets so
//          an enabled-blocklist vs per-IP mismatch is explained rather than alarming.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using RdpAudit.Core.Firewall;
using Xunit;

namespace RdpAudit.Core.Tests;

public class FirewallDiagnosticsScannerBackendTests
{
	private static FirewallDiagnosticsInput BaseInput(string scannerBackend, bool thirdParty) => new(
		ConfiguredProviderKind: "Windows",
		ConfiguredEnforcementBackend: "WindowsFirewall",
		ConfiguredBlockScope: "RdpPortOnly",
		ResolvedRdpPort: 55554,
		RdpPortFromRegistry: true,
		Providers: System.Array.Empty<FirewallProviderDiagnostic>(),
		RdpAuditGroupBlockRuleCount: 0,
		EnabledAllowInboundTcpPorts: System.Array.Empty<int>(),
		RdpAuditAllowRuleForResolvedPort: false,
		RouteBackendState: "n/a",
		IPsecBackendState: "n/a",
		ThirdPartyFirewallSuspected: thirdParty,
		ThirdPartyFirewallNote: null,
		BlocklistRowCount: 4,
		ActiveBlockRowCount: 5,
		VerifiedEnforcedCount: 0)
	{
		ScannerBackend = scannerBackend,
	};

	[Fact]
	public void Report_IncludesScannerBackendSection_AndManualPowerShellCommand()
	{
		string report = FirewallDiagnosticsReportBuilder.Build(BaseInput("PowerShellJson", thirdParty: false));

		Assert.Contains("[Firewall scanner backend used]", report);
		Assert.Contains("PowerShell Get-NetFirewallRule JSON", report);
		Assert.Contains("Get-NetFirewallRule -Group 'RdpAudit'", report);
	}

	[Fact]
	public void Report_WarnsAboutLocaleRisk_OnlyForNetshBackend()
	{
		string netsh = FirewallDiagnosticsReportBuilder.Build(BaseInput("NetshText", thirdParty: false));
		string ps = FirewallDiagnosticsReportBuilder.Build(BaseInput("PowerShellJson", thirdParty: false));

		Assert.Contains("localized netsh text", netsh);
		Assert.DoesNotContain("localized netsh text", ps);
	}

	[Fact]
	public void Report_ThirdPartyDetected_NeverSaysNo_AndMarksInterferenceUnknown()
	{
		string report = FirewallDiagnosticsReportBuilder.Build(BaseInput("PowerShellJson", thirdParty: true));

		Assert.Contains("Detected: YES", report);
		Assert.Contains("Interference: UNKNOWN", report);
		// Must not emit the old "Suspected interference: no" phrasing.
		Assert.DoesNotContain("Suspected interference: no", report);
	}

	[Fact]
	public void Report_ThirdPartyDetected_WithFragileScanner_DoesNotBlameThirdParty()
	{
		string report = FirewallDiagnosticsReportBuilder.Build(BaseInput("NetshText", thirdParty: true));

		Assert.Contains("Do not attribute missing rules to the third-party firewall", report);
	}

	[Fact]
	public void Report_ExplainsCountBuckets_SoEnabledVsPerIpMismatchIsNotAlarming()
	{
		string report = FirewallDiagnosticsReportBuilder.Build(BaseInput("PowerShellJson", thirdParty: false));

		Assert.Contains("NOT expected to be equal", report);
		Assert.Contains("Blocklist rows (enabled, intent in DB): 4", report);
		Assert.Contains("Active-block rows (active/pending, attempted enforcement): 5", report);
		// Unenforced warning must point operators to the Blocklist repair actions, not Active Blocks.
		Assert.Contains("Repair Selected", report);
		Assert.Contains("Repair All Enabled", report);
	}
}
