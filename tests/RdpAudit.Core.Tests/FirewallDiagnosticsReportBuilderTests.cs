// File:    tests/RdpAudit.Core.Tests/FirewallDiagnosticsReportBuilderTests.cs
// Module:  RdpAudit.Core.Tests
// Purpose: Unit tests for FirewallDiagnosticsReportBuilder — pinning the sections an operator relies
//          on to confirm RdpAudit's IP blocking is actually enforced (resolved RDP port, RdpAudit
//          group rules, per-provider availability, alternate backends, third-party interference) and
//          the reconciliation warning that fires when active-block rows exceed verified enforcement.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using RdpAudit.Core.Firewall;
using Xunit;

namespace RdpAudit.Core.Tests;

public class FirewallDiagnosticsReportBuilderTests
{
	private static FirewallDiagnosticsInput Sample(
		int activeRows = 0,
		int verified = 0,
		bool thirdParty = false,
		bool allowForPort = true) =>
		new(
			ConfiguredProviderKind: "Windows",
			ConfiguredEnforcementBackend: "WindowsFirewall",
			ConfiguredBlockScope: "RdpPortOnly",
			ResolvedRdpPort: 55554,
			RdpPortFromRegistry: true,
			Providers: new[]
			{
				new FirewallProviderDiagnostic("Windows", true, 3, "ok"),
				new FirewallProviderDiagnostic("MikroTik", false, 0, "not configured"),
			},
			RdpAuditGroupBlockRuleCount: 3,
			EnabledAllowInboundTcpPorts: new[] { 55554 },
			RdpAuditAllowRuleForResolvedPort: allowForPort,
			RouteBackendState: "Available",
			IPsecBackendState: "NotImplemented",
			ThirdPartyFirewallSuspected: thirdParty,
			ThirdPartyFirewallNote: thirdParty ? "Kaspersky detected" : null,
			BlocklistRowCount: 5,
			ActiveBlockRowCount: activeRows,
			VerifiedEnforcedCount: verified);

	[Fact]
	public void Report_IncludesResolvedPortAndSource()
	{
		string text = FirewallDiagnosticsReportBuilder.Build(Sample());
		Assert.Contains("Resolved RDP port: 55554 (from registry)", text, StringComparison.Ordinal);
	}

	[Fact]
	public void Report_ListsProvidersWithAvailability()
	{
		string text = FirewallDiagnosticsReportBuilder.Build(Sample());
		Assert.Contains("Windows: available, activeBlocks=3", text, StringComparison.Ordinal);
		Assert.Contains("MikroTik: unavailable", text, StringComparison.Ordinal);
	}

	[Fact]
	public void Report_ShowsRdpAuditGroupRuleCountAndBackends()
	{
		string text = FirewallDiagnosticsReportBuilder.Build(Sample());
		Assert.Contains("RdpAudit-group inbound block rules: 3", text, StringComparison.Ordinal);
		Assert.Contains("Route blackhole: Available", text, StringComparison.Ordinal);
		Assert.Contains("IPsec policy: NotImplemented", text, StringComparison.Ordinal);
	}

	[Fact]
	public void Report_FlagsMissingAllowRuleForResolvedPort()
	{
		string text = FirewallDiagnosticsReportBuilder.Build(Sample(allowForPort: false));
		Assert.Contains("Allow-inbound rule for resolved RDP port (55554): ABSENT", text, StringComparison.Ordinal);
	}

	[Fact]
	public void Report_WarnsWhenActiveRowsExceedVerifiedEnforcement()
	{
		string text = FirewallDiagnosticsReportBuilder.Build(Sample(activeRows: 4, verified: 1));
		Assert.Contains("WARNING: 3 active-block row(s) have NO confirmed firewall enforcement", text, StringComparison.Ordinal);
	}

	[Fact]
	public void Report_NoWarningWhenAllEnforced()
	{
		string text = FirewallDiagnosticsReportBuilder.Build(Sample(activeRows: 3, verified: 3));
		Assert.DoesNotContain("WARNING:", text, StringComparison.Ordinal);
	}

	[Fact]
	public void Report_SurfacesThirdPartyNote()
	{
		string text = FirewallDiagnosticsReportBuilder.Build(Sample(thirdParty: true));
		Assert.Contains("Detected: YES", text, StringComparison.Ordinal);
		Assert.Contains("Interference: UNKNOWN", text, StringComparison.Ordinal);
		Assert.Contains("Kaspersky detected", text, StringComparison.Ordinal);
	}

	[Fact]
	public void Report_HandlesEmptyProvidersAndPorts()
	{
		FirewallDiagnosticsInput input = Sample() with
		{
			Providers = Array.Empty<FirewallProviderDiagnostic>(),
			EnabledAllowInboundTcpPorts = Array.Empty<int>(),
		};
		string text = FirewallDiagnosticsReportBuilder.Build(input);
		Assert.Contains("(no providers registered)", text, StringComparison.Ordinal);
		Assert.Contains("Enabled allow-inbound TCP ports: (none)", text, StringComparison.Ordinal);
	}

	[Fact]
	public void Report_RdpPortOnly_ShowsExpectedRuleShapeWithResolvedPort()
	{
		// Configured RdpPortOnly with resolved port 55554: the expected-shape line must pin TCP 55554,
		// proving the report drives off the dynamically resolved port and never a hardcoded 3389.
		string text = FirewallDiagnosticsReportBuilder.Build(Sample());
		Assert.Contains("[Block scope]", text, StringComparison.Ordinal);
		Assert.Contains("Configured scope: RdpPortOnly", text, StringComparison.Ordinal);
		Assert.Contains("Expected rule shape: inbound block, TCP, LocalPort=55554", text, StringComparison.Ordinal);
	}

	[Fact]
	public void Report_AllInbound_ExplainsLocalPortAnyIsExpected()
	{
		FirewallDiagnosticsInput input = Sample() with { ConfiguredBlockScope = "AllInbound" };
		string text = FirewallDiagnosticsReportBuilder.Build(input);
		Assert.Contains("Configured scope: AllInbound", text, StringComparison.Ordinal);
		Assert.Contains("LocalPort=Any is EXPECTED because BlockScope=AllInbound", text, StringComparison.Ordinal);
	}

	[Fact]
	public void Report_DetectsMismatch_WhenConfiguredRdpOnlyButRuleIsAllInbound()
	{
		// Live rule pins no port (AllInbound shape) while config says RdpPortOnly — the report must
		// name the rule and warn, instead of silently claiming RdpPortOnly.
		FirewallDiagnosticsInput input = Sample() with
		{
			DiscoveredRuleShapes = new[]
			{
				new FirewallRuleShape("RdpAudit-Block-203.0.113.10", null, Array.Empty<int>()),
			},
		};
		string text = FirewallDiagnosticsReportBuilder.Build(input);
		Assert.Contains("RdpAudit rule(s) do NOT match the configured scope", text, StringComparison.Ordinal);
		Assert.Contains("RdpAudit-Block-203.0.113.10", text, StringComparison.Ordinal);
		Assert.Contains("still blocks all inbound", text, StringComparison.Ordinal);
	}

	[Fact]
	public void Report_NoMismatch_WhenRuleMatchesConfiguredRdpOnlyScope()
	{
		FirewallDiagnosticsInput input = Sample() with
		{
			DiscoveredRuleShapes = new[]
			{
				new FirewallRuleShape("RdpAudit-Block-203.0.113.10", "TCP", new[] { 55554 }),
			},
		};
		string text = FirewallDiagnosticsReportBuilder.Build(input);
		Assert.Contains("Existing rule mismatches: none", text, StringComparison.Ordinal);
	}
}
