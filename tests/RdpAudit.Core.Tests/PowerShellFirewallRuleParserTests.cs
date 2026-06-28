// File:    tests/RdpAudit.Core.Tests/PowerShellFirewallRuleParserTests.cs
// Module:  RdpAudit.Core.Tests
// Purpose: Verifies the locale-independent PowerShell JSON firewall-rule parser. The whole point of
//          this path is that ConvertTo-Json property names are English-stable on every host UI
//          culture (unlike netsh text labels), and that rules are recognised by group=RdpAudit as
//          well as by rule-name prefix. These tests pin: array vs single-object JSON shapes,
//          group / display-group matching, name-prefix matching, RemoteAddress /32 + range + array
//          equivalence, and enum-as-string vs enum-as-integer tolerance.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using RdpAudit.Core.Firewall;
using Xunit;

namespace RdpAudit.Core.Tests;

public class PowerShellFirewallRuleParserTests
{
	private const string Prefix = "RdpAudit-Block";
	private const string Group = "RdpAudit";

	[Fact]
	public void DiscoverRdpAuditBlockRules_MatchesByGroup_EvenWhenNamePrefixDiffers()
	{
		// The netsh path missed this: a rule tagged group=RdpAudit but with a name that does NOT carry
		// the prefix must still be discovered.
		const string json = """
		[{"Name":"some-unrelated-name","DisplayName":"x","Group":"RdpAudit","DisplayGroup":"RdpAudit",
		"Direction":"Inbound","Action":"Block","Enabled":"True","Protocol":"TCP",
		"LocalPort":["55554"],"RemoteAddress":["80.244.40.164/32"]}]
		""";

		IReadOnlyList<DiscoveredBlockRule> rules =
			PowerShellFirewallRuleParser.DiscoverRdpAuditBlockRules(json, Prefix, Group);

		DiscoveredBlockRule rule = Assert.Single(rules);
		Assert.True(rule.Enabled);
		Assert.True(rule.DirectionInbound);
		Assert.True(rule.ActionBlock);
		Assert.Contains("80.244.40.164", rule.RemoteIps);
		Assert.Contains(55554, rule.LocalPorts);
	}

	[Fact]
	public void DiscoverRdpAuditBlockRules_MatchesByNamePrefix()
	{
		const string json = """
		[{"Name":"RdpAudit-Block-80.244.40.164","Group":null,"DisplayGroup":null,
		"Direction":"Inbound","Action":"Block","Enabled":"True","Protocol":"Any",
		"LocalPort":"Any","RemoteAddress":"80.244.40.164"}]
		""";

		IReadOnlyList<DiscoveredBlockRule> rules =
			PowerShellFirewallRuleParser.DiscoverRdpAuditBlockRules(json, Prefix, Group);

		DiscoveredBlockRule rule = Assert.Single(rules);
		Assert.Equal("RdpAudit-Block-80.244.40.164", rule.RuleName);
		Assert.Contains("80.244.40.164", rule.RemoteIps);
	}

	[Fact]
	public void DiscoverRdpAuditBlockRules_HandlesSingleObject_NotArray()
	{
		// ConvertTo-Json collapses a single match to a lone object rather than a one-element array.
		const string json = """
		{"Name":"RdpAudit-Block-1.2.3.4","Group":"RdpAudit","Direction":"Inbound","Action":"Block",
		"Enabled":"True","Protocol":"TCP","LocalPort":["3389"],"RemoteAddress":"1.2.3.4/32"}
		""";

		IReadOnlyList<DiscoveredBlockRule> rules =
			PowerShellFirewallRuleParser.DiscoverRdpAuditBlockRules(json, Prefix, Group);

		DiscoveredBlockRule rule = Assert.Single(rules);
		Assert.Contains("1.2.3.4", rule.RemoteIps);
		Assert.Contains(3389, rule.LocalPorts);
	}

	[Fact]
	public void DiscoverRdpAuditBlockRules_RemoteAddressEquivalence_Slash32_Range_Bare()
	{
		// /32, an x-x single-address range, and a bare address must all normalise to the same token.
		const string json = """
		[
		 {"Name":"RdpAudit-Block-a","Group":"RdpAudit","Direction":"Inbound","Action":"Block","Enabled":"True","RemoteAddress":"80.244.40.164/32"},
		 {"Name":"RdpAudit-Block-b","Group":"RdpAudit","Direction":"Inbound","Action":"Block","Enabled":"True","RemoteAddress":"80.244.40.164-80.244.40.164"},
		 {"Name":"RdpAudit-Block-c","Group":"RdpAudit","Direction":"Inbound","Action":"Block","Enabled":"True","RemoteAddress":["80.244.40.164"]}
		]
		""";

		IReadOnlyList<DiscoveredBlockRule> rules =
			PowerShellFirewallRuleParser.DiscoverRdpAuditBlockRules(json, Prefix, Group);

		Assert.Equal(3, rules.Count);
		foreach (DiscoveredBlockRule rule in rules)
		{
			Assert.Contains("80.244.40.164", rule.RemoteIps);
		}
	}

	[Fact]
	public void DiscoverRdpAuditBlockRules_ToleratesEnumIntegers()
	{
		// PowerShard may emit Direction/Action/Enabled as the underlying CIM enum integers
		// (Inbound=1, Block=4, Enabled=1) rather than the English word.
		const string json = """
		[{"Name":"RdpAudit-Block-x","Group":"RdpAudit","Direction":1,"Action":4,"Enabled":1,
		"Protocol":"TCP","LocalPort":[3389],"RemoteAddress":["9.9.9.9/32"]}]
		""";

		IReadOnlyList<DiscoveredBlockRule> rules =
			PowerShellFirewallRuleParser.DiscoverRdpAuditBlockRules(json, Prefix, Group);

		DiscoveredBlockRule rule = Assert.Single(rules);
		Assert.True(rule.Enabled);
		Assert.True(rule.DirectionInbound);
		Assert.True(rule.ActionBlock);
		Assert.Contains(3389, rule.LocalPorts);
	}

	[Fact]
	public void DiscoverRdpAuditBlockRules_IgnoresUnrelatedRules()
	{
		const string json = """
		[{"Name":"SomeAdminRule","Group":"Remote Desktop","Direction":"Inbound","Action":"Allow",
		"Enabled":"True","RemoteAddress":"Any"}]
		""";

		IReadOnlyList<DiscoveredBlockRule> rules =
			PowerShellFirewallRuleParser.DiscoverRdpAuditBlockRules(json, Prefix, Group);

		Assert.Empty(rules);
	}

	[Theory]
	[InlineData(null)]
	[InlineData("")]
	[InlineData("   ")]
	[InlineData("not json at all")]
	[InlineData("[]")]
	public void DiscoverRdpAuditBlockRules_EmptyOrInvalidJson_ReturnsEmpty(string? json)
	{
		IReadOnlyList<DiscoveredBlockRule> rules =
			PowerShellFirewallRuleParser.DiscoverRdpAuditBlockRules(json, Prefix, Group);

		Assert.Empty(rules);
	}

	[Fact]
	public void DiscoverRdpAuditBlockRules_ManualRule_GuidName_ManualDisplayName_MatchedByGroup_SingleObject()
	{
		// Live shape of a manually-created RdpAudit rule: Name is an auto-assigned GUID, DisplayName is
		// operator text, identity is carried solely by Group=RdpAudit. ConvertTo-Json emits a lone object
		// for a single match. This MUST NOT return 0 — the regression that prompted the fix.
		const string json = """
		{"Name":"{7d48c3ed-1b2c-4f5a-9c0d-0123456789ab}","DisplayName":"RdpAudit Manual Keep 80.244.40.164",
		"Group":"RdpAudit","DisplayGroup":"RdpAudit","Direction":"Inbound","Action":"Block","Enabled":"True",
		"Protocol":"Any","LocalPort":"Any","RemoteAddress":"80.244.40.164/32"}
		""";

		IReadOnlyList<DiscoveredBlockRule> rules =
			PowerShellFirewallRuleParser.DiscoverRdpAuditBlockRules(json, Prefix, Group);

		DiscoveredBlockRule rule = Assert.Single(rules);
		Assert.Equal("{7d48c3ed-1b2c-4f5a-9c0d-0123456789ab}", rule.RuleName);
		Assert.True(rule.Enabled);
		Assert.True(rule.DirectionInbound);
		Assert.True(rule.ActionBlock);
		Assert.Contains("80.244.40.164", rule.RemoteIps);
	}

	[Fact]
	public void DiscoverRdpAuditBlockRules_ManualRule_GuidName_ManualDisplayName_MatchedByGroup_Array()
	{
		// Same live shape, but as a multi-element array (ConvertTo-Json's form when >1 rule matches).
		const string json = """
		[
		 {"Name":"{7d48c3ed-1b2c-4f5a-9c0d-0123456789ab}","DisplayName":"RdpAudit Manual Keep 80.244.40.164",
		  "Group":"RdpAudit","DisplayGroup":"RdpAudit","Direction":"Inbound","Action":"Block","Enabled":"True",
		  "Protocol":"Any","LocalPort":"Any","RemoteAddress":"80.244.40.164/32"},
		 {"Name":"{0a1b2c3d-4e5f-6071-8293-a4b5c6d7e8f9}","DisplayName":"RdpAudit Manual Keep 5.5.5.5",
		  "Group":"RdpAudit","DisplayGroup":"RdpAudit","Direction":"Inbound","Action":"Block","Enabled":"True",
		  "Protocol":"Any","LocalPort":"Any","RemoteAddress":"5.5.5.5/32"}
		]
		""";

		IReadOnlyList<DiscoveredBlockRule> rules =
			PowerShellFirewallRuleParser.DiscoverRdpAuditBlockRules(json, Prefix, Group);

		Assert.Equal(2, rules.Count);
		Assert.Contains(rules, r => r.RemoteIps.Contains("80.244.40.164"));
		Assert.Contains(rules, r => r.RemoteIps.Contains("5.5.5.5"));
	}

	[Fact]
	public void DiscoverRdpAuditBlockRules_TempProbeRule_NameEqualsDisplayName_MatchedByGroup()
	{
		// The Tools Diag temporary-probe rule: Name == DisplayName == the deterministic per-IP name, with
		// Group=RdpAudit. The provider verify/list path relies on this matching by group so the temp probe
		// reports verify PASS. This MUST NOT return 0.
		const string json = """
		{"Name":"RdpAudit-ToolsDiag-TempProbe-78.37.40.185","DisplayName":"RdpAudit-ToolsDiag-TempProbe-78.37.40.185",
		"Group":"RdpAudit","DisplayGroup":"RdpAudit","Direction":"Inbound","Action":"Block","Enabled":"True",
		"Protocol":"Any","LocalPort":"Any","RemoteAddress":"78.37.40.185"}
		""";

		IReadOnlyList<DiscoveredBlockRule> rules =
			PowerShellFirewallRuleParser.DiscoverRdpAuditBlockRules(json, Prefix, Group);

		DiscoveredBlockRule rule = Assert.Single(rules);
		Assert.Equal("RdpAudit-ToolsDiag-TempProbe-78.37.40.185", rule.RuleName);
		Assert.Contains("78.37.40.185", rule.RemoteIps);
	}

	[Fact]
	public void DiscoverRdpAuditBlockRules_DisplayGroupMatch_IsRecognised()
	{
		// Some hosts surface the localized DisplayGroup but keep Group null; an exact match on either
		// must count.
		const string json = """
		[{"Name":"x","Group":null,"DisplayGroup":"RdpAudit","Direction":"Inbound","Action":"Block",
		"Enabled":"False","RemoteAddress":"5.5.5.5/32"}]
		""";

		IReadOnlyList<DiscoveredBlockRule> rules =
			PowerShellFirewallRuleParser.DiscoverRdpAuditBlockRules(json, Prefix, Group);

		DiscoveredBlockRule rule = Assert.Single(rules);
		Assert.False(rule.Enabled);
		Assert.Contains("5.5.5.5", rule.RemoteIps);
	}
}
