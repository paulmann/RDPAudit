// File:    src/RdpAudit.Core/Firewall/PowerShellFirewallRuleParser.cs
// Module:  RdpAudit.Core.Firewall
// Purpose: Pure parser for the JSON produced by `Get-NetFirewallRule | … | ConvertTo-Json`. Unlike
//          the verbose `netsh` text dump (whose field labels are translated into the operator's UI
//          language — "Имя правила:" on a Russian host instead of "Rule Name:"), the JSON property
//          names emitted by ConvertTo-Json are English-stable on every locale. This parser is the
//          locale-independent primitive behind PowerShellFirewallRuleScanner; the netsh text scanner
//          is retained only as a clearly-labeled fallback. Pure: no I/O, no Win32, fully testable
//          cross-platform from canned JSON.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System.Text.Json;

namespace RdpAudit.Core.Firewall;

/// <summary>Pure parser for `Get-NetFirewallRule … | ConvertTo-Json` output.</summary>
/// <remarks>
/// The producing PowerShell pipeline emits, per inbound rule, an object with the properties
/// <c>Name</c>, <c>DisplayName</c>, <c>Group</c>, <c>DisplayGroup</c>, <c>Direction</c>,
/// <c>Action</c>, <c>Enabled</c>, <c>Protocol</c>, <c>LocalPort</c> and <c>RemoteAddress</c>.
/// ConvertTo-Json collapses a single match to a lone object (not an array) and renders array-valued
/// properties (<c>LocalPort</c>, <c>RemoteAddress</c>) either as a JSON array or, for a single value,
/// as a bare scalar — this parser tolerates all of those shapes. Enum-valued properties
/// (<c>Direction</c>, <c>Action</c>, <c>Enabled</c>) may arrive as the English word ("Inbound",
/// "Block", "True") or as the underlying integer; both are recognised.
/// </remarks>
public static class PowerShellFirewallRuleParser
{
	/// <summary>Direction enum value PowerShell uses for inbound rules (Microsoft.Management.Infrastructure).</summary>
	private const int DirectionInboundValue = 1;

	/// <summary>Action enum value PowerShell uses for a Block rule.</summary>
	private const int ActionBlockValue = 4;

	/// <summary>Enabled enum value PowerShell uses for an enabled rule.</summary>
	private const int EnabledTrueValue = 1;

	/// <summary>Projects every rule in <paramref name="json"/> whose name carries
	/// <paramref name="ruleNamePrefix"/> OR whose Group / DisplayGroup equals
	/// <paramref name="groupName"/> into a <see cref="DiscoveredBlockRule"/>. Matching on Group as
	/// well as the name prefix is the key fix over the netsh path: rules tagged
	/// <c>group=RdpAudit</c> are recognised even if a future rule-name scheme drifts from the prefix.
	/// The match is case-insensitive. Returns an empty list for null / empty / unparseable JSON.</summary>
	public static IReadOnlyList<DiscoveredBlockRule> DiscoverRdpAuditBlockRules(
		string? json,
		string ruleNamePrefix,
		string groupName)
	{
		ArgumentException.ThrowIfNullOrWhiteSpace(ruleNamePrefix);
		ArgumentException.ThrowIfNullOrWhiteSpace(groupName);

		List<DiscoveredBlockRule> discovered = new();
		if (string.IsNullOrWhiteSpace(json))
		{
			return discovered;
		}

		JsonDocument doc;
		try
		{
			doc = JsonDocument.Parse(json);
		}
		catch (JsonException)
		{
			return discovered;
		}

		using (doc)
		{
			JsonElement root = doc.RootElement;
			if (root.ValueKind == JsonValueKind.Array)
			{
				foreach (JsonElement element in root.EnumerateArray())
				{
					TryAdd(element, ruleNamePrefix, groupName, discovered);
				}
			}
			else if (root.ValueKind == JsonValueKind.Object)
			{
				TryAdd(root, ruleNamePrefix, groupName, discovered);
			}
		}

		return discovered;
	}

	private static void TryAdd(
		JsonElement element,
		string ruleNamePrefix,
		string groupName,
		List<DiscoveredBlockRule> discovered)
	{
		if (element.ValueKind != JsonValueKind.Object)
		{
			return;
		}

		string? name = ReadString(element, "Name");
		string? displayName = ReadString(element, "DisplayName");
		string? group = ReadString(element, "Group");
		string? displayGroup = ReadString(element, "DisplayGroup");

		// Ownership is recognised on ANY of the three RdpAudit identity forms (see
		// RdpAuditFirewallRuleMatcher): canonical Name prefix, canonical DisplayName prefix (the
		// GUID-named rule whose Name is a "{GUID}" but whose DisplayName is "RdpAudit-Block-<ip>"), or
		// Group/DisplayGroup == RdpAudit. The earlier parser keyed only on Name-prefix OR Group, so the
		// GUID-named rule (Name a GUID, Group empty) was dropped here before the matcher could see it.
		bool nameMatch = name is not null
			&& name.StartsWith(ruleNamePrefix, StringComparison.OrdinalIgnoreCase);
		bool displayNameMatch = displayName is not null
			&& displayName.StartsWith(ruleNamePrefix, StringComparison.OrdinalIgnoreCase);
		bool groupMatch =
			(group is not null && string.Equals(group, groupName, StringComparison.OrdinalIgnoreCase))
			|| (displayGroup is not null && string.Equals(displayGroup, groupName, StringComparison.OrdinalIgnoreCase));

		if (!nameMatch && !displayNameMatch && !groupMatch)
		{
			return;
		}

		string ruleName = name ?? displayName ?? group ?? displayGroup ?? ruleNamePrefix;
		discovered.Add(new DiscoveredBlockRule(
			RuleName: ruleName,
			Enabled: ReadEnabled(element),
			DirectionInbound: ReadDirectionInbound(element),
			ActionBlock: ReadActionBlock(element),
			Protocol: ReadString(element, "Protocol"),
			LocalPorts: ReadPorts(element),
			RemoteIps: ReadRemoteIps(element))
		{
			DisplayName = displayName,
			Group = group,
			DisplayGroup = displayGroup,
		});
	}

	private static string? ReadString(JsonElement obj, string property)
	{
		if (!obj.TryGetProperty(property, out JsonElement value))
		{
			return null;
		}

		return value.ValueKind switch
		{
			JsonValueKind.String => value.GetString(),
			JsonValueKind.Number => value.ToString(),
			_ => null,
		};
	}

	private static bool ReadEnabled(JsonElement obj)
	{
		if (!obj.TryGetProperty("Enabled", out JsonElement value))
		{
			return false;
		}

		return value.ValueKind switch
		{
			JsonValueKind.True => true,
			JsonValueKind.False => false,
			JsonValueKind.String => string.Equals(value.GetString(), "True", StringComparison.OrdinalIgnoreCase),
			JsonValueKind.Number => value.TryGetInt32(out int n) && n == EnabledTrueValue,
			_ => false,
		};
	}

	private static bool ReadDirectionInbound(JsonElement obj)
	{
		if (!obj.TryGetProperty("Direction", out JsonElement value))
		{
			return false;
		}

		return value.ValueKind switch
		{
			JsonValueKind.String => value.GetString() is { } s
				&& s.StartsWith("In", StringComparison.OrdinalIgnoreCase),
			JsonValueKind.Number => value.TryGetInt32(out int n) && n == DirectionInboundValue,
			_ => false,
		};
	}

	private static bool ReadActionBlock(JsonElement obj)
	{
		if (!obj.TryGetProperty("Action", out JsonElement value))
		{
			return false;
		}

		return value.ValueKind switch
		{
			JsonValueKind.String => value.GetString() is { } s
				&& s.Contains("Block", StringComparison.OrdinalIgnoreCase),
			JsonValueKind.Number => value.TryGetInt32(out int n) && n == ActionBlockValue,
			_ => false,
		};
	}

	private static List<int> ReadPorts(JsonElement obj)
	{
		List<int> ports = new();
		if (!obj.TryGetProperty("LocalPort", out JsonElement value))
		{
			return ports;
		}

		if (value.ValueKind == JsonValueKind.Array)
		{
			foreach (JsonElement item in value.EnumerateArray())
			{
				AddPortToken(item, ports);
			}
		}
		else
		{
			AddPortToken(value, ports);
		}

		return ports;
	}

	private static void AddPortToken(JsonElement item, List<int> ports)
	{
		switch (item.ValueKind)
		{
			case JsonValueKind.Number when item.TryGetInt32(out int n):
				ports.Add(n);
				break;
			case JsonValueKind.String:
				NetshRuleScanner.ParsePortToken(item.GetString(), ports);
				break;
		}
	}

	private static List<string> ReadRemoteIps(JsonElement obj)
	{
		List<string> ips = new();
		if (!obj.TryGetProperty("RemoteAddress", out JsonElement value))
		{
			return ips;
		}

		if (value.ValueKind == JsonValueKind.Array)
		{
			foreach (JsonElement item in value.EnumerateArray())
			{
				if (item.ValueKind == JsonValueKind.String)
				{
					NetshRuleScanner.ParseRemoteIpList(item.GetString() ?? string.Empty, ips);
				}
			}
		}
		else if (value.ValueKind == JsonValueKind.String)
		{
			NetshRuleScanner.ParseRemoteIpList(value.GetString() ?? string.Empty, ips);
		}

		return ips;
	}
}
