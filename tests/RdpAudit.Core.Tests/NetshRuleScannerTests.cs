// File:    tests/RdpAudit.Core.Tests/NetshRuleScannerTests.cs
// Module:  RdpAudit.Core.Tests
// Purpose: Verifies the rule-by-port scanner so the "Windows Firewall RDP rule present" probe
//          stays localisation-tolerant and uses the configured RDP port rather than the
//          well-known 3389 — matching the new contract laid out in feedback (no localized
//          Windows Firewall group name lookups).
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using RdpAudit.Core.Firewall;
using Xunit;

namespace RdpAudit.Core.Tests;

public class NetshRuleScannerTests
{
	private const string AllowInbound3389 =
		"Rule Name:                            My RDP Rule\n" +
		"----------------------------------------------------------------------\n" +
		"Enabled:                              Yes\n" +
		"Direction:                            In\n" +
		"Profiles:                             Domain,Private,Public\n" +
		"Grouping:                             Remote Desktop\n" +
		"LocalIP:                              Any\n" +
		"RemoteIP:                             Any\n" +
		"Protocol:                             TCP\n" +
		"LocalPort:                            3389\n" +
		"RemotePort:                           Any\n" +
		"Edge traversal:                       No\n" +
		"Action:                               Allow\n" +
		"\n";

	[Fact]
	public void ContainsAllowInboundForPort_FindsMatchingRule()
	{
		Assert.True(NetshRuleScanner.ContainsAllowInboundForPort(AllowInbound3389, 3389));
	}

	[Fact]
	public void ContainsAllowInboundForPort_DefaultPortDoesNotMatchCustomPort()
	{
		// Critical: previous implementation hard-coded 3389. The scanner must accept the
		// configured port. We assert the inverse: feeding 3389 output but asking for 33890
		// returns false so the prerequisite Fail with actionable diagnostic.
		Assert.False(NetshRuleScanner.ContainsAllowInboundForPort(AllowInbound3389, 33890));
	}

	[Fact]
	public void ContainsAllowInboundForPort_CustomPortInOutput_MatchesCustomPort()
	{
		string output = AllowInbound3389.Replace("LocalPort:                            3389", "LocalPort:                            33890", StringComparison.Ordinal);
		Assert.True(NetshRuleScanner.ContainsAllowInboundForPort(output, 33890));
		Assert.False(NetshRuleScanner.ContainsAllowInboundForPort(output, 3389));
	}

	[Fact]
	public void ContainsAllowInboundForPort_PortListWithMatch_Matches()
	{
		string output =
			"Rule Name:                            Bulk\n" +
			"Enabled:                              Yes\n" +
			"Direction:                            In\n" +
			"Protocol:                             TCP\n" +
			"LocalPort:                            80,443,3389\n" +
			"Action:                               Allow\n" +
			"\n";
		Assert.True(NetshRuleScanner.ContainsAllowInboundForPort(output, 3389));
		Assert.True(NetshRuleScanner.ContainsAllowInboundForPort(output, 443));
		Assert.False(NetshRuleScanner.ContainsAllowInboundForPort(output, 4443));
	}

	[Fact]
	public void ContainsAllowInboundForPort_BlockActionIgnored()
	{
		string output = AllowInbound3389.Replace("Action:                               Allow", "Action:                               Block", StringComparison.Ordinal);
		Assert.False(NetshRuleScanner.ContainsAllowInboundForPort(output, 3389));
	}

	[Fact]
	public void ContainsAllowInboundForPort_OutboundIgnored()
	{
		string output = AllowInbound3389.Replace("Direction:                            In", "Direction:                            Out", StringComparison.Ordinal);
		Assert.False(NetshRuleScanner.ContainsAllowInboundForPort(output, 3389));
	}

	[Fact]
	public void ContainsAllowInboundForPort_EmptyInput_ReturnsFalse()
	{
		Assert.False(NetshRuleScanner.ContainsAllowInboundForPort(string.Empty, 3389));
		Assert.False(NetshRuleScanner.ContainsAllowInboundForPort(null!, 3389));
	}

	[Fact]
	public void ContainsAllowInboundForPort_NoRulesMatchOutput_ReturnsFalse()
	{
		Assert.False(NetshRuleScanner.ContainsAllowInboundForPort("No rules match the specified criteria.\n", 3389));
	}

	private const string BlockInboundRule =
		"Rule Name:                            RdpAudit-Block-203.0.113.10\n" +
		"----------------------------------------------------------------------\n" +
		"Enabled:                              Yes\n" +
		"Direction:                            In\n" +
		"Profiles:                             Domain,Private,Public\n" +
		"Grouping:                             RdpAudit\n" +
		"RemoteIP:                             203.0.113.10/32\n" +
		"Protocol:                             Any\n" +
		"Action:                               Block\n" +
		"\n";

	[Fact]
	public void ContainsEnabledInboundBlockRule_FindsEnabledInboundBlock()
	{
		Assert.True(NetshRuleScanner.ContainsEnabledInboundBlockRule(BlockInboundRule));
	}

	[Fact]
	public void ContainsEnabledInboundBlockRule_DisabledRuleRejected()
	{
		string output = BlockInboundRule.Replace(
			"Enabled:                              Yes",
			"Enabled:                              No",
			StringComparison.Ordinal);
		Assert.False(NetshRuleScanner.ContainsEnabledInboundBlockRule(output));
	}

	[Fact]
	public void ContainsEnabledInboundBlockRule_OutboundRuleRejected()
	{
		string output = BlockInboundRule.Replace(
			"Direction:                            In",
			"Direction:                            Out",
			StringComparison.Ordinal);
		Assert.False(NetshRuleScanner.ContainsEnabledInboundBlockRule(output));
	}

	[Fact]
	public void ContainsEnabledInboundBlockRule_AllowActionRejected()
	{
		string output = BlockInboundRule.Replace(
			"Action:                               Block",
			"Action:                               Allow",
			StringComparison.Ordinal);
		Assert.False(NetshRuleScanner.ContainsEnabledInboundBlockRule(output));
	}

	[Fact]
	public void ContainsEnabledInboundBlockRule_NoRulesMatchOutput_ReturnsFalse()
	{
		Assert.False(NetshRuleScanner.ContainsEnabledInboundBlockRule("No rules match the specified criteria.\n"));
		Assert.False(NetshRuleScanner.ContainsEnabledInboundBlockRule(string.Empty));
	}

	private const string MixedRulesDump =
		"Rule Name:                            RdpAudit-Block-203.0.113.10\n" +
		"----------------------------------------------------------------------\n" +
		"Enabled:                              Yes\n" +
		"Direction:                            In\n" +
		"Profiles:                             Domain,Private,Public\n" +
		"Grouping:                             RdpAudit\n" +
		"RemoteIP:                             203.0.113.10/32\n" +
		"Protocol:                             TCP\n" +
		"LocalPort:                            3389\n" +
		"Action:                               Block\n" +
		"\n" +
		"Rule Name:                            Some Unrelated Admin Rule\n" +
		"----------------------------------------------------------------------\n" +
		"Enabled:                              Yes\n" +
		"Direction:                            In\n" +
		"RemoteIP:                             198.51.100.5/32\n" +
		"Protocol:                             TCP\n" +
		"Action:                               Block\n" +
		"\n" +
		"Rule Name:                            RdpAudit-Block-198.51.100.7\n" +
		"----------------------------------------------------------------------\n" +
		"Enabled:                              No\n" +
		"Direction:                            In\n" +
		"Grouping:                             RdpAudit\n" +
		"RemoteIP:                             198.51.100.7/32\n" +
		"Protocol:                             Any\n" +
		"Action:                               Block\n" +
		"\n";

	[Fact]
	public void DiscoverRdpAuditBlockRules_ReturnsOnlyPrefixedRules()
	{
		IReadOnlyList<DiscoveredBlockRule> rules =
			NetshRuleScanner.DiscoverRdpAuditBlockRules(MixedRulesDump, "RdpAudit-Block");

		Assert.Equal(2, rules.Count);
		Assert.All(rules, r => Assert.StartsWith("RdpAudit-Block", r.RuleName, StringComparison.Ordinal));
		Assert.DoesNotContain(rules, r => r.RuleName.Contains("Unrelated", StringComparison.Ordinal));
	}

	[Fact]
	public void DiscoverRdpAuditBlockRules_CapturesRemoteIpAndDirectionAndAction()
	{
		IReadOnlyList<DiscoveredBlockRule> rules =
			NetshRuleScanner.DiscoverRdpAuditBlockRules(MixedRulesDump, "RdpAudit-Block");

		DiscoveredBlockRule enabled = Assert.Single(rules, r => r.Enabled);
		Assert.True(enabled.DirectionInbound);
		Assert.True(enabled.ActionBlock);
		// netsh renders 203.0.113.10/32; the parser strips the /prefix to the canonical IP token.
		Assert.Contains("203.0.113.10", enabled.RemoteIps);
	}

	[Fact]
	public void DiscoverRdpAuditBlockRules_PreservesDisabledRule()
	{
		IReadOnlyList<DiscoveredBlockRule> rules =
			NetshRuleScanner.DiscoverRdpAuditBlockRules(MixedRulesDump, "RdpAudit-Block");

		Assert.Contains(rules, r => !r.Enabled && r.RuleName.EndsWith("198.51.100.7", StringComparison.Ordinal));
	}

	[Fact]
	public void DiscoverRdpAuditBlockRules_EmptyOutput_ReturnsEmpty()
	{
		Assert.Empty(NetshRuleScanner.DiscoverRdpAuditBlockRules(string.Empty, "RdpAudit-Block"));
	}
}
