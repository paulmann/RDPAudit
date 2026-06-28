// File:    src/RdpAudit.Core/Firewall/RdpAuditFirewallRuleMatcher.cs
// Module:  RdpAudit.Core.Firewall
// Purpose: v1.3.8 — recognise RdpAudit block rules for a given IP across BOTH identity forms that
//          Windows Firewall can present, and report duplicate / canonicalization status so the
//          Firewall tab can reconcile desired vs. actual enforcement honestly. On the affected host
//          a single blocked IP surfaced as TWO firewall rules:
//              1. canonical  — Name == "RdpAudit-Block-<ip>", Group == "RdpAudit";
//              2. GUID-named — Name == "{GUID}", DisplayName == "RdpAudit-Block-<ip>", Group empty.
//          The prior verifier matched only on Name-prefix OR Group, so the GUID-named rule (Name is
//          a GUID, Group empty) was MISSED — enforcement showed "MISSING RULE" even though a valid
//          block rule existed, and a manual "Repair Selected" was needed. This pure matcher closes
//          that gap: it matches the canonical Name, the DisplayName form, and the Group, dedupes by
//          IP, flags duplicates, and recommends the canonical rule for repair. Pure / no I/O — fully
//          testable from canned rule tuples cross-platform.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System.Globalization;

namespace RdpAudit.Core.Firewall;

/// <summary>How a firewall rule matched (or was identified as) an RdpAudit block rule for an IP.</summary>
public enum RdpAuditRuleIdentity
{
	/// <summary>Did not match the target IP / RdpAudit ownership at all.</summary>
	None = 0,

	/// <summary>Canonical: Name == "RdpAudit-Block-&lt;ip&gt;" (optionally Group == RdpAudit).</summary>
	CanonicalName = 1,

	/// <summary>GUID-named (or otherwise non-canonical Name) whose DisplayName == "RdpAudit-Block-&lt;ip&gt;".</summary>
	DisplayName = 2,

	/// <summary>Owned by the RdpAudit Group and bound to the target IP, but neither Name nor
	/// DisplayName carries the canonical "RdpAudit-Block-&lt;ip&gt;" token.</summary>
	GroupOnly = 3,
}

/// <summary>A raw firewall rule as read back from the provider, independent of the heavier
/// <see cref="DiscoveredBlockRule"/> shape. <paramref name="RemoteIps"/> is the rule's RemoteAddress
/// set (already normalized by the scanner). Only the fields needed for identity reconciliation are
/// carried.</summary>
public sealed record RawFirewallRule(
	string? Name,
	string? DisplayName,
	string? Group,
	string? DisplayGroup,
	bool Enabled,
	IReadOnlyList<string> RemoteIps);

/// <summary>A single rule that matched the target IP, tagged with how it was identified.</summary>
public sealed record MatchedFirewallRule(
	string RuleName,
	string? DisplayName,
	RdpAuditRuleIdentity Identity,
	bool Enabled);

/// <summary>Outcome of matching the live rule set against one desired blocked IP.</summary>
public sealed record FirewallRuleMatchResult(
	string Ip,
	string CanonicalRuleName,
	IReadOnlyList<MatchedFirewallRule> Matches)
{
	/// <summary>True when at least one matching rule exists (in any identity form).</summary>
	public bool RuleExists => Matches.Count > 0;

	/// <summary>True when at least one matching rule is enabled — i.e. the block is actually
	/// enforced regardless of which identity form the rule takes.</summary>
	public bool VerifiedEnforced
	{
		get
		{
			foreach (MatchedFirewallRule match in Matches)
			{
				if (match.Enabled)
				{
					return true;
				}
			}

			return false;
		}
	}

	/// <summary>True when more than one rule matches the same IP — the operator (or auto-repair)
	/// should canonicalize/de-duplicate.</summary>
	public bool HasDuplicates => Matches.Count > 1;

	/// <summary>True when a rule with the exact canonical Name already exists.</summary>
	public bool HasCanonicalRule
	{
		get
		{
			foreach (MatchedFirewallRule match in Matches)
			{
				if (match.Identity == RdpAuditRuleIdentity.CanonicalName)
				{
					return true;
				}
			}

			return false;
		}
	}

	/// <summary>One-line diagnostics summary for the Firewall tab / DEBUG OperationLog.</summary>
	public string Describe()
	{
		if (!RuleExists)
		{
			return string.Format(
				CultureInfo.InvariantCulture,
				"{0}: no RdpAudit rule found (canonical expected: {1}).",
				Ip,
				CanonicalRuleName);
		}

		return string.Format(
			CultureInfo.InvariantCulture,
			"{0}: {1} matching rule(s); enforced={2}; canonicalPresent={3}; duplicates={4}; canonical={5}.",
			Ip,
			Matches.Count,
			VerifiedEnforced ? "yes" : "no",
			HasCanonicalRule ? "yes" : "no",
			HasDuplicates ? "yes" : "no",
			CanonicalRuleName);
	}
}

/// <summary>Pure matcher recognising RdpAudit block rules for an IP across both identity forms.</summary>
public static class RdpAuditFirewallRuleMatcher
{
	/// <summary>Build the canonical rule name for <paramref name="ip"/> under
	/// <paramref name="rulePrefix"/> (e.g. "RdpAudit-Block" + "62.176.5.200"
	/// → "RdpAudit-Block-62.176.5.200"). The IP is used verbatim — callers that need IP
	/// normalization should normalize before calling.</summary>
	public static string BuildCanonicalRuleName(string rulePrefix, string ip)
	{
		ArgumentException.ThrowIfNullOrWhiteSpace(rulePrefix);
		ArgumentException.ThrowIfNullOrWhiteSpace(ip);
		return rulePrefix + "-" + ip.Trim();
	}

	/// <summary>Match every rule in <paramref name="rules"/> against the desired blocked
	/// <paramref name="ip"/>. A rule matches when it targets the IP (RemoteAddress contains it, or
	/// the canonical name/displayname for the IP is present) AND is RdpAudit-owned by one of:
	/// canonical Name, DisplayName == canonical, or Group/DisplayGroup == <paramref name="groupName"/>.
	/// Returns the per-IP reconciliation result with duplicate/canonicalization status.</summary>
	public static FirewallRuleMatchResult Match(
		IReadOnlyList<RawFirewallRule> rules,
		string ip,
		string rulePrefix,
		string groupName)
	{
		ArgumentNullException.ThrowIfNull(rules);
		ArgumentException.ThrowIfNullOrWhiteSpace(ip);
		ArgumentException.ThrowIfNullOrWhiteSpace(rulePrefix);
		ArgumentException.ThrowIfNullOrWhiteSpace(groupName);

		string trimmedIp = ip.Trim();
		string canonicalName = BuildCanonicalRuleName(rulePrefix, trimmedIp);

		List<MatchedFirewallRule> matches = new();
		foreach (RawFirewallRule rule in rules)
		{
			RdpAuditRuleIdentity identity = Classify(rule, trimmedIp, canonicalName, groupName);
			if (identity == RdpAuditRuleIdentity.None)
			{
				continue;
			}

			string ruleName = rule.Name
				?? rule.DisplayName
				?? canonicalName;
			matches.Add(new MatchedFirewallRule(ruleName, rule.DisplayName, identity, rule.Enabled));
		}

		return new FirewallRuleMatchResult(trimmedIp, canonicalName, matches);
	}

	/// <summary>Projects a live <see cref="DiscoveredBlockRule"/> (the heavier shape the scanners
	/// produce) into the lightweight <see cref="RawFirewallRule"/> this matcher consumes. The scanners
	/// fold a GUID-named rule's DisplayName / Group into the discovered rule (v1.3.9) so the matcher can
	/// attribute it; when the backend could not read DisplayName separately from Name (netsh text
	/// parse) the rule's <see cref="DiscoveredBlockRule.RuleName"/> stands in for both.</summary>
	public static RawFirewallRule ToRawRule(DiscoveredBlockRule rule)
	{
		ArgumentNullException.ThrowIfNull(rule);
		return new RawFirewallRule(
			Name: rule.RuleName,
			DisplayName: rule.DisplayName ?? rule.RuleName,
			Group: rule.Group,
			DisplayGroup: rule.DisplayGroup,
			Enabled: rule.Enabled,
			RemoteIps: rule.RemoteIps);
	}

	/// <summary>Matches the live <paramref name="rules"/> (discovered by a scanner) against the desired
	/// blocked <paramref name="ip"/> using the same identity logic as
	/// <see cref="Match(IReadOnlyList{RawFirewallRule}, string, string, string)"/>. Convenience overload
	/// so the Service reconciler can feed its <see cref="DiscoveredBlockRule"/> list without converting
	/// at the call site.</summary>
	public static FirewallRuleMatchResult MatchDiscovered(
		IReadOnlyList<DiscoveredBlockRule> rules,
		string ip,
		string rulePrefix,
		string groupName)
	{
		ArgumentNullException.ThrowIfNull(rules);
		List<RawFirewallRule> raw = new(rules.Count);
		foreach (DiscoveredBlockRule rule in rules)
		{
			raw.Add(ToRawRule(rule));
		}

		return Match(raw, ip, rulePrefix, groupName);
	}

	private static RdpAuditRuleIdentity Classify(
		RawFirewallRule rule,
		string ip,
		string canonicalName,
		string groupName)
	{
		bool nameIsCanonical = rule.Name is not null
			&& string.Equals(rule.Name, canonicalName, StringComparison.OrdinalIgnoreCase);
		bool displayNameIsCanonical = rule.DisplayName is not null
			&& string.Equals(rule.DisplayName, canonicalName, StringComparison.OrdinalIgnoreCase);
		bool groupOwned =
			(rule.Group is not null && string.Equals(rule.Group, groupName, StringComparison.OrdinalIgnoreCase))
			|| (rule.DisplayGroup is not null && string.Equals(rule.DisplayGroup, groupName, StringComparison.OrdinalIgnoreCase));

		// The canonical/displayname forms encode the IP in the rule identity itself, so they are
		// authoritative even when the scanner could not read RemoteAddress back. The group-only form
		// must additionally bind to the IP via RemoteAddress to be attributed to this IP.
		if (nameIsCanonical)
		{
			return RdpAuditRuleIdentity.CanonicalName;
		}

		if (displayNameIsCanonical)
		{
			return RdpAuditRuleIdentity.DisplayName;
		}

		if (groupOwned && TargetsIp(rule, ip))
		{
			return RdpAuditRuleIdentity.GroupOnly;
		}

		return RdpAuditRuleIdentity.None;
	}

	private static bool TargetsIp(RawFirewallRule rule, string ip)
	{
		foreach (string remote in rule.RemoteIps)
		{
			if (string.Equals(remote?.Trim(), ip, StringComparison.OrdinalIgnoreCase))
			{
				return true;
			}
		}

		return false;
	}
}
