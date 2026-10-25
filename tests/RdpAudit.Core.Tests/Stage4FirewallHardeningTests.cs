// File:    tests/RdpAudit.Core.Tests/Stage4FirewallHardeningTests.cs
// Module:  RdpAudit.Core.Tests
// Purpose: Stage 4 regression coverage for the firewall / Kaspersky diagnostics hardening:
//          * NetshRuleScanner now requires Enabled=Yes + Protocol=TCP and exposes diagnostic
//            helpers (ExplainPortMatches, EnumerateEnabledAllowInboundTcpPorts) so the
//            Prerequisites tab can explain stale-port / disabled-rule failures.
//          * LocalRulePolicyParser surfaces the `LocalFirewallRules N/A (GPO-store only)` row
//            from `netsh advfirewall show allprofiles`.
//          * FirewallProviderDiagnostics.BuildDiagnosticsText emits the per-profile
//            LocalFirewallRules rows + a clear GPO-store-only note.
//          * FirewallProviderClassifier still detects the user's reported `AVP21.24` Kaspersky
//            service through the `AVP` fragment, so service / CLI detection holds even when
//            SecurityCenter2 is absent (Windows Server SKUs).
//          User scenario (Windows 10 Pro 19045 ru-RU, resolved RDP port 55554, Kaspersky as
//          FirewallProduct / AntiVirusProduct) is reproduced verbatim in the integration-style
//          tests at the bottom.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using RdpAudit.Core.Firewall;
using Xunit;

namespace RdpAudit.Core.Tests;

public class Stage4FirewallHardeningTests
{
	/// <summary>One rule block helper — produces the exact column layout netsh emits for verbose
	/// `show rule name=all verbose`.</summary>
	private static string RuleBlock(
		string ruleName,
		string enabled,
		string direction,
		string protocol,
		string localPort,
		string action)
		=> "Rule Name:                            " + ruleName + "\n"
			+ "----------------------------------------------------------------------\n"
			+ "Enabled:                              " + enabled + "\n"
			+ "Direction:                            " + direction + "\n"
			+ "Profiles:                             Domain,Private,Public\n"
			+ "Grouping:                             \n"
			+ "LocalIP:                              Any\n"
			+ "RemoteIP:                             Any\n"
			+ "Protocol:                             " + protocol + "\n"
			+ "LocalPort:                            " + localPort + "\n"
			+ "RemotePort:                           Any\n"
			+ "Edge traversal:                       No\n"
			+ "Action:                               " + action + "\n"
			+ "\n";

	[Fact]
	public void Scanner_DisabledRule_IsNotConsideredAllow()
	{
		// Stage 4: disabled rules must no longer satisfy the probe.
		string output = RuleBlock("Allow RDP 55554 TCP",
			enabled: "No", direction: "In", protocol: "TCP", localPort: "55554", action: "Allow");

		Assert.False(NetshRuleScanner.ContainsAllowInboundForPort(output, 55554));

		var matches = NetshRuleScanner.ExplainPortMatches(output, 55554);
		Assert.Single(matches);
		Assert.True(matches[0].MatchesPort);
		Assert.False(matches[0].EnabledOk);
		Assert.True(matches[0].DirectionInOk);
		Assert.True(matches[0].ActionAllowOk);
		Assert.True(matches[0].ProtocolTcpOk);
	}

	[Fact]
	public void Scanner_UdpProtocol_IsNotConsideredAllow()
	{
		// Stage 4: UDP rules must no longer satisfy the TCP-only probe.
		string output = RuleBlock("Allow RDP 55554 UDP",
			enabled: "Yes", direction: "In", protocol: "UDP", localPort: "55554", action: "Allow");

		Assert.False(NetshRuleScanner.ContainsAllowInboundForPort(output, 55554));

		var matches = NetshRuleScanner.ExplainPortMatches(output, 55554);
		Assert.Single(matches);
		Assert.False(matches[0].ProtocolTcpOk);
	}

	[Fact]
	public void Scanner_PortRangeCoveringTarget_Matches()
	{
		// Stage 4: range-form LocalPort (e.g. 55550-55559) must be expanded so the scanner
		// recognises a rule that covers the resolved listener port.
		string output = RuleBlock("Range",
			enabled: "Yes", direction: "In", protocol: "TCP", localPort: "55550-55559", action: "Allow");

		Assert.True(NetshRuleScanner.ContainsAllowInboundForPort(output, 55554));
		Assert.False(NetshRuleScanner.ContainsAllowInboundForPort(output, 55560));
	}

	[Fact]
	public void Scanner_EnumerateEnabledAllowInboundTcpPorts_ReturnsDistinctSortedPorts()
	{
		string output =
			RuleBlock("First", "Yes", "In", "TCP", "3389", "Allow")
			+ RuleBlock("Second", "Yes", "In", "TCP", "55554", "Allow")
			+ RuleBlock("Disabled", "No", "In", "TCP", "9999", "Allow");

		var ports = NetshRuleScanner.EnumerateEnabledAllowInboundTcpPorts(output);

		Assert.Equal(new[] { 3389, 55554 }, ports);
	}

	[Fact]
	public void Scanner_UserScenario_ResolvedPort55554WithAllowRulePasses()
	{
		// User diagnostic: resolved RDP listener port is 55554 and an explicit allow rule for
		// TCP/55554 exists. The probe must Pass after Stage 4 fixes.
		string output =
			RuleBlock("Allow RDP 55554 TCP", "Yes", "In", "TCP", "55554", "Allow")
			+ RuleBlock("New RDP Port 55554", "Yes", "In", "TCP", "55554", "Allow")
			+ RuleBlock("Stale Default", "Yes", "In", "TCP", "3389", "Allow");

		Assert.True(NetshRuleScanner.ContainsAllowInboundForPort(output, 55554));
		Assert.True(NetshRuleScanner.ContainsAllowInboundForPort(output, 3389));
	}

	[Fact]
	public void Scanner_StaleDefaultRule_DoesNotSatisfyResolvedCustomPort()
	{
		// User scenario reversed: only a 3389 rule exists while the listener moved to 55554.
		// The probe MUST fail, and the diagnostic helper must enumerate 3389 so the operator
		// recognises the stale rule.
		string output = RuleBlock("Stale Default", "Yes", "In", "TCP", "3389", "Allow");

		Assert.False(NetshRuleScanner.ContainsAllowInboundForPort(output, 55554));

		var enabledPorts = NetshRuleScanner.EnumerateEnabledAllowInboundTcpPorts(output);
		Assert.Equal(new[] { 3389 }, enabledPorts);

		var explanations = NetshRuleScanner.ExplainPortMatches(output, 55554);
		Assert.Empty(explanations); // no rule mentions 55554 at all
	}

	[Fact]
	public void Parser_ParsesEnabledNoYesAndPorts()
	{
		string output =
			RuleBlock("R1", "Yes", "In", "TCP", "55554", "Allow")
			+ RuleBlock("R2", "No", "In", "TCP", "80,443", "Allow");

		var parsed = System.Linq.Enumerable.ToList(NetshRuleScanner.ParseRules(output));
		Assert.Equal(2, parsed.Count);

		Assert.Equal("R1", parsed[0].RuleName);
		Assert.True(parsed[0].Enabled);
		Assert.Equal(new[] { 55554 }, parsed[0].LocalPorts);

		Assert.Equal("R2", parsed[1].RuleName);
		Assert.False(parsed[1].Enabled);
		Assert.Equal(new[] { 80, 443 }, parsed[1].LocalPorts);
	}

	// ----- LocalRulePolicyParser ------------------------------------------------------------------

	[Fact]
	public void PolicyParser_DetectsGpoStoreOnly()
	{
		// User diagnostic: `netsh show allprofiles` in English on a host where GPO controls the
		// firewall reports the row `LocalFirewallRules                     N/A (GPO-store only)`.
		string output =
			"Domain Profile Settings:\n"
			+ "----------------------------------------------------------------------\n"
			+ "State                                 ON\n"
			+ "Firewall Policy                       BlockInbound,AllowOutbound\n"
			+ "LocalFirewallRules                    N/A (GPO-store only)\n"
			+ "LocalConSecRules                      N/A (GPO-store only)\n"
			+ "InboundUserNotification               Disable\n"
			+ "\n"
			+ "Private Profile Settings:\n"
			+ "----------------------------------------------------------------------\n"
			+ "State                                 ON\n"
			+ "LocalFirewallRules                    Enable\n"
			+ "\n";

		var rows = LocalRulePolicyParser.ParseAllProfiles(output);
		Assert.Equal(2, rows.Count);

		Assert.Equal("Domain", rows[0].ProfileLabel);
		Assert.Equal(LocalRulePolicyHint.GpoStoreOnly, rows[0].Hint);

		Assert.Equal("Private", rows[1].ProfileLabel);
		Assert.Equal(LocalRulePolicyHint.Allowed, rows[1].Hint);

		Assert.True(LocalRulePolicyParser.AnyProfileIsGpoStoreOnly(output));
	}

	[Fact]
	public void PolicyParser_NoLocalRulesRow_ReturnsEmpty()
	{
		string output =
			"Domain Profile Settings:\n"
			+ "State                                 ON\n"
			+ "\n";

		var rows = LocalRulePolicyParser.ParseAllProfiles(output);
		Assert.Empty(rows);
		Assert.False(LocalRulePolicyParser.AnyProfileIsGpoStoreOnly(output));
	}

	[Fact]
	public void PolicyParser_DisableValue_ReportsDisabled()
	{
		string output =
			"Public Profile Settings:\n"
			+ "LocalFirewallRules                    Disable\n"
			+ "\n";

		var rows = LocalRulePolicyParser.ParseAllProfiles(output);
		Assert.Single(rows);
		Assert.Equal(LocalRulePolicyHint.Disabled, rows[0].Hint);
	}

	[Fact]
	public void PolicyParser_Classify_AcceptsDocumentedTokens()
	{
		Assert.Equal(LocalRulePolicyHint.GpoStoreOnly, LocalRulePolicyParser.Classify("N/A (GPO-store only)"));
		Assert.Equal(LocalRulePolicyHint.GpoStoreOnly, LocalRulePolicyParser.Classify("N/A"));
		Assert.Equal(LocalRulePolicyHint.Allowed, LocalRulePolicyParser.Classify("Enable"));
		Assert.Equal(LocalRulePolicyHint.Allowed, LocalRulePolicyParser.Classify("Yes"));
		Assert.Equal(LocalRulePolicyHint.Disabled, LocalRulePolicyParser.Classify("Disable"));
		Assert.Equal(LocalRulePolicyHint.Disabled, LocalRulePolicyParser.Classify("No"));
		Assert.Equal(LocalRulePolicyHint.Unknown, LocalRulePolicyParser.Classify(""));
		Assert.Equal(LocalRulePolicyHint.Unknown, LocalRulePolicyParser.Classify(null));
		Assert.Equal(LocalRulePolicyHint.Unknown, LocalRulePolicyParser.Classify("?"));
	}

	// ----- FirewallProviderDiagnostics.BuildDiagnosticsText surfaces policy rows ----------------

	[Fact]
	public void Diagnostics_BuildText_SurfacesGpoStoreOnlyAndPort()
	{
		FirewallProviderDiagnostics diag = new()
		{
			ProviderKind = FirewallProviderDetectedKind.KasperskyDetected,
			ProviderName = "Kaspersky Endpoint Security for Windows",
			ConfiguredRdpPort = 55554,
			LocalRuleManagementAllowed = false,
			LocalRulePolicyRows = new[]
			{
				new LocalRulePolicyRow("Domain", LocalRulePolicyHint.GpoStoreOnly, "N/A (GPO-store only)"),
				new LocalRulePolicyRow("Private", LocalRulePolicyHint.Allowed, "Enable"),
				new LocalRulePolicyRow("Public", LocalRulePolicyHint.GpoStoreOnly, "N/A (GPO-store only)"),
			},
		};

		string text = diag.BuildDiagnosticsText();

		Assert.Contains("Configured RDP port: 55554", text);
		Assert.Contains("Kaspersky Endpoint Security for Windows", text);
		Assert.Contains("LocalFirewallRules policy (per profile)", text);
		Assert.Contains("Domain: GpoStoreOnly", text);
		Assert.Contains("Private: Allowed", text);
		Assert.Contains("Public: GpoStoreOnly", text);
		Assert.Contains("GPO-store only", text);
		Assert.Contains("blocked by Group Policy", text);
		Assert.True(diag.LocalRulesAreGpoStoreOnly);
	}

	[Fact]
	public void Diagnostics_LocalRulesAreGpoStoreOnly_FalseWhenAllProfilesAllowed()
	{
		FirewallProviderDiagnostics diag = new()
		{
			LocalRulePolicyRows = new[]
			{
				new LocalRulePolicyRow("Domain", LocalRulePolicyHint.Allowed, "Enable"),
				new LocalRulePolicyRow("Private", LocalRulePolicyHint.Allowed, "Enable"),
			},
		};

		Assert.False(diag.LocalRulesAreGpoStoreOnly);
	}

	// ----- Kaspersky detection: user's AVP21.24 service signal --------------------------------

	[Fact]
	public void Classifier_UserScenario_Avp21_24_ClassifiesAsKaspersky()
	{
		// User diagnostic: SecurityCenter2 reports Kaspersky as FirewallProduct + AntiVirusProduct,
		// service "AVP21.24" is running. Service / CLI detection alone (no SecurityCenter2 input)
		// must still classify as KasperskyDetected via the "AVP" fragment.
		FirewallServiceState[] services = new[]
		{
			new FirewallServiceState("AVP21.24", "Kaspersky Security Service", "Running", IsRunning: true),
			new FirewallServiceState("MpsSvc", "Windows Defender Firewall", "Running", IsRunning: true),
			new FirewallServiceState("BFE", "Base Filtering Engine", "Running", IsRunning: true),
		};

		FirewallCliToolPresence[] cli = new[]
		{
			new FirewallCliToolPresence("avp.exe", @"C:\Program Files (x86)\Kaspersky Lab\KES\avp.exe", Present: true),
			new FirewallCliToolPresence("kescli.exe", null, Present: false),
		};

		(FirewallProviderDetectedKind kind, string name) = FirewallProviderClassifier.Classify(
			services, cli, kasperskyManagesWindowsFirewall: false);

		Assert.Equal(FirewallProviderDetectedKind.KasperskyDetected, kind);
		Assert.Equal("Kaspersky Endpoint Security for Windows", name);
	}

	[Fact]
	public void Classifier_UserScenario_KasperskyServiceFragmentsList_IncludesAvp()
	{
		// Defensive: the "AVP" fragment is the load-bearing one for the user's reported
		// AVP21.24 service. Stage 4 must not accidentally drop it.
		Assert.Contains("AVP", FirewallProviderClassifier.KasperskyServiceFragments);
	}

	// ----- NetshDiagnosticsFormatter Stage-4 fail-case still includes port + rule name ----------

	[Fact]
	public void Formatter_Short_UserScenario55554_IncludesPortAndProposedRule()
	{
		NetshProbeOutcome outcome = new(
			Command: "netsh",
			Arguments: new[] { "advfirewall", "firewall", "show", "rule", "name=all", "verbose" },
			ExitCode: 0,
			StdOut: "Rule Name:    Stale Default\nEnabled:      Yes\nDirection:    In\nProtocol:     TCP\nLocalPort:    3389\nAction:       Allow\n\n",
			StdErr: string.Empty,
			ConfiguredRdpPort: 55554,
			RuleNameAttempted: "RdpAudit-RDP-Allow-55554",
			TimedOut: false);

		string s = NetshDiagnosticsFormatter.FormatShort(outcome);
		Assert.Contains("port=55554", s);
		Assert.Contains("rule=RdpAudit-RDP-Allow-55554", s);
	}
}
