// File:    tests/RdpAudit.Core.Tests/RdpAuditFirewallRuleMatcherTests.cs
// Module:  RdpAudit.Core.Tests
// Purpose: v1.3.8 — pin the firewall rule reconciliation semantics so verification recognises
//          BOTH identity forms Windows Firewall presents for an RdpAudit block, and reports
//          duplicate / canonicalization status. Fixtures mirror the affected-host evidence: the
//          blocked IP 62.176.5.200 surfaced as a canonical rule (Name == RdpAudit-Block-<ip>,
//          Group RdpAudit) AND a GUID-named rule (Name == {GUID}, DisplayName == RdpAudit-Block-<ip>,
//          empty Group). Both must verify enforcement; both must be reported as a duplicate pair.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using RdpAudit.Core.Firewall;
using Xunit;

namespace RdpAudit.Core.Tests;

public class RdpAuditFirewallRuleMatcherTests
{
	private const string Prefix = "RdpAudit-Block";
	private const string Group = "RdpAudit";
	private const string Ip = "62.176.5.200";
	private const string Canonical = "RdpAudit-Block-62.176.5.200";

	private static RawFirewallRule CanonicalRule() => new(
		Name: Canonical,
		DisplayName: Canonical,
		Group: Group,
		DisplayGroup: Group,
		Enabled: true,
		RemoteIps: new[] { Ip });

	private static RawFirewallRule GuidNamedRule() => new(
		Name: "{ED78943D-1FB7-45D3-B02A-31F1B4B232E8}",
		DisplayName: Canonical,
		Group: null,
		DisplayGroup: null,
		Enabled: true,
		RemoteIps: new[] { Ip });

	[Fact]
	public void Match_CanonicalNameRule_IsRecognised()
	{
		FirewallRuleMatchResult result = RdpAuditFirewallRuleMatcher.Match(
			new[] { CanonicalRule() }, Ip, Prefix, Group);

		Assert.True(result.RuleExists);
		Assert.True(result.VerifiedEnforced);
		Assert.True(result.HasCanonicalRule);
		Assert.False(result.HasDuplicates);
		Assert.Equal(Canonical, result.CanonicalRuleName);
		Assert.Equal(RdpAuditRuleIdentity.CanonicalName, result.Matches.Single().Identity);
	}

	[Fact]
	public void Match_GuidNamedRuleWithCanonicalDisplayName_IsRecognised()
	{
		// This is the form the prior verifier MISSED: Name is a GUID, Group is empty, but the
		// DisplayName carries the canonical RdpAudit-Block-<ip> token.
		FirewallRuleMatchResult result = RdpAuditFirewallRuleMatcher.Match(
			new[] { GuidNamedRule() }, Ip, Prefix, Group);

		Assert.True(result.RuleExists);
		Assert.True(result.VerifiedEnforced);
		Assert.False(result.HasCanonicalRule);
		Assert.Equal(RdpAuditRuleIdentity.DisplayName, result.Matches.Single().Identity);
	}

	[Fact]
	public void Match_DuplicateRulesForSameIp_AreReported()
	{
		FirewallRuleMatchResult result = RdpAuditFirewallRuleMatcher.Match(
			new[] { CanonicalRule(), GuidNamedRule() }, Ip, Prefix, Group);

		Assert.True(result.HasDuplicates);
		Assert.Equal(2, result.Matches.Count);
		Assert.True(result.HasCanonicalRule);
		Assert.True(result.VerifiedEnforced);
		// The canonical rule is the repair target.
		Assert.Contains(result.Matches, m => m.Identity == RdpAuditRuleIdentity.CanonicalName);
		Assert.Contains(result.Matches, m => m.Identity == RdpAuditRuleIdentity.DisplayName);
	}

	[Fact]
	public void Match_NoRuleForIp_ReportsMissing()
	{
		RawFirewallRule otherIp = new(
			Name: "RdpAudit-Block-203.0.113.9",
			DisplayName: "RdpAudit-Block-203.0.113.9",
			Group: Group,
			DisplayGroup: Group,
			Enabled: true,
			RemoteIps: new[] { "203.0.113.9" });

		FirewallRuleMatchResult result = RdpAuditFirewallRuleMatcher.Match(
			new[] { otherIp }, Ip, Prefix, Group);

		Assert.False(result.RuleExists);
		Assert.False(result.VerifiedEnforced);
		Assert.Contains("no RdpAudit rule found", result.Describe(), StringComparison.Ordinal);
	}

	[Fact]
	public void Match_DisabledRule_ExistsButNotEnforced()
	{
		RawFirewallRule disabled = CanonicalRule() with { Enabled = false };

		FirewallRuleMatchResult result = RdpAuditFirewallRuleMatcher.Match(
			new[] { disabled }, Ip, Prefix, Group);

		Assert.True(result.RuleExists);
		Assert.False(result.VerifiedEnforced);
	}

	[Fact]
	public void Match_GroupOwnedRuleBoundToIp_WithoutCanonicalToken_IsRecognised()
	{
		// A rule owned by the RdpAudit group, bound to the IP via RemoteAddress, but whose name
		// does not carry the canonical token (e.g. a legacy naming scheme). It must still verify.
		RawFirewallRule groupOnly = new(
			Name: "RdpAudit-Legacy-1",
			DisplayName: "RdpAudit legacy block",
			Group: Group,
			DisplayGroup: Group,
			Enabled: true,
			RemoteIps: new[] { Ip });

		FirewallRuleMatchResult result = RdpAuditFirewallRuleMatcher.Match(
			new[] { groupOnly }, Ip, Prefix, Group);

		Assert.True(result.RuleExists);
		Assert.True(result.VerifiedEnforced);
		Assert.Equal(RdpAuditRuleIdentity.GroupOnly, result.Matches.Single().Identity);
		Assert.False(result.HasCanonicalRule);
	}

	[Fact]
	public void Match_GroupOwnedRuleForDifferentIp_IsNotAttributed()
	{
		// Group-owned but RemoteAddress is a different IP and no canonical token — must not be
		// attributed to our target IP.
		RawFirewallRule groupOther = new(
			Name: "RdpAudit-Legacy-2",
			DisplayName: "RdpAudit legacy block",
			Group: Group,
			DisplayGroup: Group,
			Enabled: true,
			RemoteIps: new[] { "198.51.100.7" });

		FirewallRuleMatchResult result = RdpAuditFirewallRuleMatcher.Match(
			new[] { groupOther }, Ip, Prefix, Group);

		Assert.False(result.RuleExists);
	}

	[Fact]
	public void BuildCanonicalRuleName_ComposesPrefixAndIp()
	{
		Assert.Equal(Canonical, RdpAuditFirewallRuleMatcher.BuildCanonicalRuleName(Prefix, Ip));
	}
}
