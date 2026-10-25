// File:    src/RdpAudit.Core/Firewall/NetshRuleScanner.cs
// Module:  RdpAudit.Core.Firewall
// Purpose: Pure parser that scans the textual output of `netsh advfirewall firewall show rule
//          name=all verbose` for an inbound-allow rule whose LocalPort matches a configured RDP
//          port. The parser relies on the stable English keys netsh emits regardless of the
//          operator's UI culture (when the producer pinned the console to chcp 437):
//          `Rule Name`, `Enabled`, `Direction`, `Action`, `Protocol`, `LocalPort`.
//
//          Stage 4 hardening:
//            * `Enabled: Yes` is now required — disabled rules no longer satisfy the probe.
//            * `Protocol: TCP` is now required — UDP / Any rules no longer satisfy the probe.
//            * A diagnostic helper enumerates every rule block that matches the requested port
//              but failed one of the other gates, so the operator sees "you have a rule for
//              3389 while the listener is on 55554" or "the rule is disabled" instead of a
//              generic 'no match'.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System.Globalization;

namespace RdpAudit.Core.Firewall;

/// <summary>One parsed rule block extracted from netsh `show rule name=all verbose` output.
/// Only the fields the scanner needs are exposed; everything else is dropped.</summary>
public sealed record NetshParsedRule(
	string? RuleName,
	bool? Enabled,
	string? Direction,
	string? Action,
	string? Protocol,
	IReadOnlyList<int> LocalPorts,
	IReadOnlyList<string> RemoteIps);

/// <summary>A discovered RdpAudit inbound block rule, projected from netsh `show rule` output for
/// live enforcement reconciliation. Carries the concrete parameters the reconciler must compare
/// against the desired block (direction / action / enabled / protocol / port / remote IP).</summary>
public sealed record DiscoveredBlockRule(
	string RuleName,
	bool Enabled,
	bool DirectionInbound,
	bool ActionBlock,
	string? Protocol,
	IReadOnlyList<int> LocalPorts,
	IReadOnlyList<string> RemoteIps)
{
	/// <summary>The rule's DisplayName when the backend can read it back (PowerShell JSON scan). On the
	/// affected host a blocked IP can surface as a GUID-named rule whose Name is a "{GUID}" but whose
	/// DisplayName is the canonical "RdpAudit-Block-&lt;ip&gt;" — carrying DisplayName lets
	/// <see cref="RdpAuditFirewallRuleMatcher"/> attribute that rule to RdpAudit even though its Name
	/// carries no prefix and its Group is empty. Null when the backend (netsh text parse) cannot read
	/// it separately from Name.</summary>
	public string? DisplayName { get; init; }

	/// <summary>The rule's Group (e.g. "RdpAudit") when the backend can read it back. Null when unknown.</summary>
	public string? Group { get; init; }

	/// <summary>The rule's DisplayGroup when the backend can read it back. Null when unknown.</summary>
	public string? DisplayGroup { get; init; }
}

/// <summary>Why a rule that mentions the requested port was nonetheless rejected by the scanner.</summary>
public sealed record NetshRulePortMatchExplanation(
	string? RuleName,
	bool MatchesPort,
	bool EnabledOk,
	bool DirectionInOk,
	bool ActionAllowOk,
	bool ProtocolTcpOk);

/// <summary>Pure parser for netsh `show rule` output.</summary>
public static class NetshRuleScanner
{
	private const string EnabledKey = "Enabled:";
	private const string DirectionKey = "Direction:";
	private const string ActionKey = "Action:";
	private const string ProtocolKey = "Protocol:";
	private const string LocalPortKey = "LocalPort:";
	private const string RemoteIpKey = "RemoteIP:";
	private const string RuleNameKey = "Rule Name:";

	/// <summary>True when <paramref name="netshOutput"/> contains at least one rule block
	/// describing an <em>enabled, inbound, allow, TCP</em> rule whose LocalPort matches
	/// <paramref name="port"/>. The parser only depends on the ASCII keys (Rule Name / Enabled /
	/// Direction / Action / Protocol / LocalPort) which netsh emits in English even on
	/// localised hosts when the spawning console is pinned to chcp 437.</summary>
	public static bool ContainsAllowInboundForPort(string netshOutput, int port)
	{
		foreach (NetshParsedRule rule in ParseRules(netshOutput))
		{
			if (Matches(rule, port))
			{
				return true;
			}
		}
		return false;
	}

	/// <summary>For each rule block in <paramref name="netshOutput"/> whose LocalPort mentions
	/// <paramref name="port"/>, returns an explanation listing which gates passed/failed. Useful
	/// when the probe fails: callers can surface "rule found but disabled" or "rule found but
	/// for port 3389" instead of an opaque negative.</summary>
	public static IReadOnlyList<NetshRulePortMatchExplanation> ExplainPortMatches(string netshOutput, int port)
	{
		List<NetshRulePortMatchExplanation> results = new();
		foreach (NetshParsedRule rule in ParseRules(netshOutput))
		{
			bool matchesPort = ContainsPort(rule.LocalPorts, port);
			if (!matchesPort)
			{
				continue;
			}

			results.Add(new NetshRulePortMatchExplanation(
				RuleName: rule.RuleName,
				MatchesPort: true,
				EnabledOk: rule.Enabled == true,
				DirectionInOk: IsInboundDirection(rule.Direction),
				ActionAllowOk: IsAllowAction(rule.Action),
				ProtocolTcpOk: IsTcpProtocol(rule.Protocol)));
		}
		return results;
	}

	/// <summary>Returns every distinct local TCP port for which an enabled, inbound, allow rule
	/// exists. Useful when the resolved RDP port has no matching rule — operator sees which
	/// ports DO have allow rules so a stale 3389 rule is recognisable.</summary>
	public static IReadOnlyList<int> EnumerateEnabledAllowInboundTcpPorts(string netshOutput)
	{
		HashSet<int> ports = new();
		foreach (NetshParsedRule rule in ParseRules(netshOutput))
		{
			if (rule.Enabled != true
				|| !IsInboundDirection(rule.Direction)
				|| !IsAllowAction(rule.Action)
				|| !IsTcpProtocol(rule.Protocol))
			{
				continue;
			}

			foreach (int p in rule.LocalPorts)
			{
				ports.Add(p);
			}
		}

		List<int> sorted = new(ports);
		sorted.Sort();
		return sorted;
	}

	/// <summary>Iterator over parsed rule blocks in <paramref name="netshOutput"/>. Blocks are
	/// separated by blank lines in the verbose format.</summary>
	public static IEnumerable<NetshParsedRule> ParseRules(string netshOutput)
	{
		if (string.IsNullOrEmpty(netshOutput))
		{
			yield break;
		}

		string[] lines = netshOutput.Replace("\r\n", "\n", StringComparison.Ordinal).Split('\n');

		string? ruleName = null;
		bool? enabled = null;
		string? direction = null;
		string? action = null;
		string? protocol = null;
		List<int> ports = new();
		List<string> remoteIps = new();
		bool hasAnyField = false;

		foreach (string raw in lines)
		{
			string line = raw.Trim();
			if (line.Length == 0)
			{
				if (hasAnyField)
				{
					yield return new NetshParsedRule(ruleName, enabled, direction, action, protocol, ports, remoteIps);
				}
				ruleName = null;
				enabled = null;
				direction = null;
				action = null;
				protocol = null;
				ports = new List<int>();
				remoteIps = new List<string>();
				hasAnyField = false;
				continue;
			}

			if (TryReadField(line, RuleNameKey, out string? rn))
			{
				ruleName = rn;
				hasAnyField = true;
			}
			else if (TryReadField(line, EnabledKey, out string? en))
			{
				enabled = string.Equals(en, "Yes", StringComparison.OrdinalIgnoreCase);
				hasAnyField = true;
			}
			else if (TryReadField(line, DirectionKey, out string? dir))
			{
				direction = dir;
				hasAnyField = true;
			}
			else if (TryReadField(line, ActionKey, out string? ac))
			{
				action = ac;
				hasAnyField = true;
			}
			else if (TryReadField(line, ProtocolKey, out string? pr))
			{
				protocol = pr;
				hasAnyField = true;
			}
			else if (TryReadField(line, LocalPortKey, out string? lp))
			{
				ParsePortList(lp!, ports);
				hasAnyField = true;
			}
			else if (TryReadField(line, RemoteIpKey, out string? rip))
			{
				ParseRemoteIpList(rip!, remoteIps);
				hasAnyField = true;
			}
		}

		if (hasAnyField)
		{
			yield return new NetshParsedRule(ruleName, enabled, direction, action, protocol, ports, remoteIps);
		}
	}

	/// <summary>Projects every rule block in <paramref name="netshOutput"/> whose name carries the
	/// supplied RdpAudit rule-name prefix into a <see cref="DiscoveredBlockRule"/>. This is the
	/// live-scan primitive used by enforcement reconciliation: callers compare the discovered
	/// parameters against each desired block to derive a status (Active / ParameterMismatch /
	/// MissingRule) and detect orphaned RdpAudit rules with no backing database row. The match is a
	/// case-insensitive prefix test on the rule name so only RdpAudit-created rules are returned —
	/// unrelated admin rules are never touched.</summary>
	public static IReadOnlyList<DiscoveredBlockRule> DiscoverRdpAuditBlockRules(string netshOutput, string ruleNamePrefix)
	{
		ArgumentException.ThrowIfNullOrWhiteSpace(ruleNamePrefix);

		List<DiscoveredBlockRule> discovered = new();
		foreach (NetshParsedRule rule in ParseRules(netshOutput))
		{
			if (rule.RuleName is null)
			{
				continue;
			}

			if (!rule.RuleName.StartsWith(ruleNamePrefix, StringComparison.OrdinalIgnoreCase))
			{
				continue;
			}

			discovered.Add(new DiscoveredBlockRule(
				RuleName: rule.RuleName,
				Enabled: rule.Enabled == true,
				DirectionInbound: IsInboundDirection(rule.Direction),
				ActionBlock: IsBlockAction(rule.Action),
				Protocol: rule.Protocol,
				LocalPorts: rule.LocalPorts,
				RemoteIps: rule.RemoteIps));
		}

		return discovered;
	}

	/// <summary>True when <paramref name="netshOutput"/> (the verbose dump for a single named rule)
	/// contains at least one <em>enabled, inbound, block</em> rule. Used to verify that a block rule
	/// RdpAudit just installed actually exists in the firewall store — turning a silent netsh
	/// success into a confirmed enforcement, or an actionable failure when no block rule is present
	/// (e.g. a third-party firewall such as Kaspersky silently swallowed the write).</summary>
	public static bool ContainsEnabledInboundBlockRule(string netshOutput)
	{
		foreach (NetshParsedRule rule in ParseRules(netshOutput))
		{
			if (rule.Enabled == true
				&& IsInboundDirection(rule.Direction)
				&& IsBlockAction(rule.Action))
			{
				return true;
			}
		}
		return false;
	}

	private static bool IsBlockAction(string? value)
		=> value is not null && value.Contains("Block", StringComparison.OrdinalIgnoreCase);

	private static bool Matches(NetshParsedRule rule, int port)
	{
		return rule.Enabled == true
			&& IsInboundDirection(rule.Direction)
			&& IsAllowAction(rule.Action)
			&& IsTcpProtocol(rule.Protocol)
			&& ContainsPort(rule.LocalPorts, port);
	}

	private static bool ContainsPort(IReadOnlyList<int> ports, int port)
	{
		foreach (int p in ports)
		{
			if (p == port)
			{
				return true;
			}
		}
		return false;
	}

	private static bool IsInboundDirection(string? value)
		=> value is not null && value.StartsWith("In", StringComparison.OrdinalIgnoreCase);

	private static bool IsAllowAction(string? value)
		=> value is not null && value.Contains("Allow", StringComparison.OrdinalIgnoreCase);

	private static bool IsTcpProtocol(string? value)
		=> value is not null && value.Contains("TCP", StringComparison.OrdinalIgnoreCase);

	private static bool TryReadField(string line, string key, out string? value)
	{
		if (line.StartsWith(key, StringComparison.OrdinalIgnoreCase))
		{
			value = line[key.Length..].Trim();
			return true;
		}
		value = null;
		return false;
	}

	/// <summary>Parses a netsh RemoteIP field into bare address tokens. netsh renders remote IPs as
	/// <c>1.2.3.4/32</c>, <c>1.2.3.4-1.2.3.4</c>, a comma list, or the literal <c>Any</c>. We strip
	/// the <c>/prefix</c> and collapse single-address ranges so the token matches the canonical IP
	/// stored on the desired block; <c>Any</c> is preserved verbatim so the reconciler can flag a
	/// rule that blocks everything (a parameter mismatch for a per-IP block).</summary>
	internal static void ParseRemoteIpList(string raw, List<string> remoteIps)
	{
		foreach (string part in raw.Split(','))
		{
			string token = part.Trim();
			if (token.Length == 0)
			{
				continue;
			}

			int slash = token.IndexOf('/', StringComparison.Ordinal);
			if (slash > 0)
			{
				token = token[..slash].Trim();
			}

			int dash = token.IndexOf('-', StringComparison.Ordinal);
			if (dash > 0)
			{
				string from = token[..dash].Trim();
				string to = token[(dash + 1)..].Trim();
				token = string.Equals(from, to, StringComparison.OrdinalIgnoreCase) ? from : token;
			}

			if (token.Length > 0)
			{
				remoteIps.Add(token);
			}
		}
	}

	private static void ParsePortList(string raw, List<int> ports)
	{
		foreach (string part in raw.Split(','))
		{
			ParsePortToken(part, ports);
		}
	}

	/// <summary>Parses a single port token (a bare number or an inclusive range such as
	/// <c>5000-5050</c>) into <paramref name="ports"/>. Tolerates surrounding whitespace and ignores
	/// non-numeric tokens (e.g. the literal <c>Any</c>). Shared by the netsh text scanner and the
	/// locale-independent <see cref="PowerShellFirewallRuleParser"/> so both expand ranges the same
	/// way.</summary>
	internal static void ParsePortToken(string? rawToken, List<int> ports)
	{
		if (rawToken is null)
		{
			return;
		}

		string token = rawToken.Trim();
		if (token.Length == 0)
		{
			return;
		}

		if (int.TryParse(token, NumberStyles.Integer, CultureInfo.InvariantCulture, out int single))
		{
			ports.Add(single);
			return;
		}

		// Range form: "5000-5050".
		int dash = token.IndexOf('-');
		if (dash > 0
			&& int.TryParse(token[..dash], NumberStyles.Integer, CultureInfo.InvariantCulture, out int from)
			&& int.TryParse(token[(dash + 1)..], NumberStyles.Integer, CultureInfo.InvariantCulture, out int to)
			&& from > 0 && to >= from && to <= 65535)
		{
			for (int p = from; p <= to; p++)
			{
				ports.Add(p);
			}
		}
	}
}
