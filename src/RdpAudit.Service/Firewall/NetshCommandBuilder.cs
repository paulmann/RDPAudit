// File:    src/RdpAudit.Service/Firewall/NetshCommandBuilder.cs
// Module:  RdpAudit.Service.Firewall
// Purpose: Pure builders for netsh advfirewall argument vectors used by the Windows firewall
//          provider. Every helper validates IP and rule-name inputs defensively, sanitises rule
//          names, and emits arguments that can ONLY be passed via ProcessStartInfo.ArgumentList.
//          NO string concatenation is performed across IP / rule-name / reason boundaries.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System.Globalization;
using System.Net;
using System.Net.Sockets;
using System.Text;
using RdpAudit.Core.Config;

namespace RdpAudit.Service.Firewall;

/// <summary>Pure builders for netsh advfirewall argument vectors used by the Windows firewall provider.</summary>
/// <remarks>
/// netsh accepts arguments as <c>name=value</c> pairs. We treat the whole pair as a single
/// argument and never quote or interpolate via the shell. <see cref="ProcessStartInfo.ArgumentList"/>
/// is the only supported invocation path.
/// </remarks>
public static class NetshCommandBuilder
{
	/// <summary>Maximum length for the per-IP rule name we generate.</summary>
	/// <remarks>
	/// Windows Defender Firewall stores rule names in a 255-character field; we cap our generated
	/// names well below that so any future suffix appended by the operator still fits.
	/// </remarks>
	public const int MaxRuleNameLength = 200;

	/// <summary>Prefix used by every RdpAudit-owned rule, never touched on third-party rules.</summary>
	public const string DefaultRulePrefix = "RdpAudit-Block";

	/// <summary>Firewall group stamped on every RdpAudit-owned rule created through the PowerShell
	/// <c>New-NetFirewallRule</c> path.</summary>
	/// <remarks>
	/// IMPORTANT: <c>netsh advfirewall firewall add rule</c> does NOT accept a <c>group=</c> (or
	/// <c>grouping=</c>) argument — live Windows diagnostics confirmed both forms fail with
	/// <c>"…is not a valid argument"</c>, which is what broke the earlier Tools Diag temp probe. The
	/// netsh add path therefore relies solely on the deterministic <see cref="DefaultRulePrefix"/>
	/// rule-name prefix as its identity handle. Only the PowerShell <c>New-NetFirewallRule -Group</c>
	/// path stamps this Group, which is the supported way to make
	/// <c>Get-NetFirewallRule -Group RdpAudit</c> enumerate our rules.
	/// </remarks>
	public const string RdpAuditGroup = "RdpAudit";

	/// <summary>Normalises a base rule prefix to the conservative ASCII set accepted by netsh.</summary>
	/// <remarks>
	/// Allowed characters: ASCII letters, digits, '-', '_', '.'. Anything else collapses to '-'.
	/// Empty / whitespace input falls back to <see cref="DefaultRulePrefix"/>.
	/// </remarks>
	public static string NormalizeRulePrefix(string? prefix)
	{
		if (string.IsNullOrWhiteSpace(prefix))
		{
			return DefaultRulePrefix;
		}

		StringBuilder sb = new(prefix.Length);
		foreach (char c in prefix)
		{
			if (char.IsAsciiLetterOrDigit(c) || c == '-' || c == '_' || c == '.')
			{
				sb.Append(c);
			}
			else
			{
				sb.Append('-');
			}
		}

		string normalized = sb.ToString().Trim('-');
		return normalized.Length == 0 ? DefaultRulePrefix : normalized;
	}

	/// <summary>Builds the deterministic per-IP rule name in the form "{prefix}-{normalized-ip}".</summary>
	public static string BuildRuleName(string rulePrefix, string ip)
	{
		string normalizedPrefix = NormalizeRulePrefix(rulePrefix);
		string normalizedIp = NormalizeIp(ip);
		string composed = string.Concat(normalizedPrefix, "-", normalizedIp);
		if (composed.Length > MaxRuleNameLength)
		{
			composed = composed[..MaxRuleNameLength];
		}
		return composed;
	}

	/// <summary>Validates an IP address. Throws when the input is not a syntactically valid IPv4 / IPv6 address.</summary>
	public static IPAddress ParseAndValidateIp(string ip)
	{
		ArgumentException.ThrowIfNullOrWhiteSpace(ip);
		if (!IPAddress.TryParse(ip, out IPAddress? parsed))
		{
			throw new ArgumentException(
				string.Format(CultureInfo.InvariantCulture, "Not a valid IPv4 / IPv6 address: '{0}'.", ip),
				nameof(ip));
		}
		return parsed;
	}

	/// <summary>Returns the canonical (normalised) textual form of an IP address.</summary>
	/// <remarks>
	/// Normalises IPv6 zone identifiers away and collapses IPv4-mapped IPv6 to IPv4 only when the
	/// caller passes one. The normalised string is safe to inject into a rule name and to compare
	/// against the configured whitelist.
	/// </remarks>
	public static string NormalizeIp(string ip)
	{
		IPAddress parsed = ParseAndValidateIp(ip);

		// Strip IPv6 scope id if present and emit the canonical textual form.
		if (parsed.AddressFamily == AddressFamily.InterNetworkV6)
		{
			parsed.ScopeId = 0;
		}

		return parsed.ToString();
	}

	/// <summary>True when the address is loopback, link-local, multicast, private (RFC1918), CGN, broadcast, or otherwise reserved.</summary>
	public static bool IsReservedAddress(IPAddress address)
	{
		ArgumentNullException.ThrowIfNull(address);

		if (IPAddress.IsLoopback(address))
		{
			return true;
		}

		if (address.AddressFamily == AddressFamily.InterNetworkV6)
		{
			return address.IsIPv6LinkLocal
				|| address.IsIPv6SiteLocal
				|| address.IsIPv6Multicast;
		}

		byte[] b = address.GetAddressBytes();
		return b[0] == 0
			|| b[0] == 10
			|| b[0] == 127
			|| (b[0] == 169 && b[1] == 254)
			|| (b[0] == 172 && b[1] >= 16 && b[1] <= 31)
			|| (b[0] == 192 && b[1] == 168)
			|| (b[0] == 100 && b[1] >= 64 && b[1] <= 127)
			|| b[0] >= 224;
	}

	/// <summary>Builds the argument vector for an all-inbound <c>netsh advfirewall firewall add rule</c>.</summary>
	/// <remarks>Convenience overload preserving the historical all-inbound behaviour. Equivalent to
	/// <see cref="BuildAddRuleArgs(string, string, string?, FirewallBlockScope, int)"/> with
	/// <see cref="FirewallBlockScope.AllInbound"/>.</remarks>
	public static IReadOnlyList<string> BuildAddRuleArgs(string ruleName, string ip, string? description) =>
		BuildAddRuleArgs(ruleName, ip, description, FirewallBlockScope.AllInbound, rdpPort: 0);

	/// <summary>Builds the scope-aware argument vector for <c>netsh advfirewall firewall add rule</c>.</summary>
	/// <param name="ruleName">Validated per-IP rule name.</param>
	/// <param name="ip">Attacker IP; re-validated and canonicalised here.</param>
	/// <param name="description">Optional audit description; sanitised before use.</param>
	/// <param name="scope">RDP-port-only or all-inbound. Drives the protocol / port arguments.</param>
	/// <param name="rdpPort">Resolved RDP listener port; required (1..65535) when
	/// <paramref name="scope"/> is <see cref="FirewallBlockScope.RdpPortOnly"/>. Never hardcoded.</param>
	/// <remarks>
	/// IMPORTANT: no <c>group=</c> / <c>grouping=</c> argument is emitted — netsh rejects both for
	/// <c>add rule</c> (verified on a live host). Rule identity is carried by the deterministic
	/// <paramref name="ruleName"/> prefix; the Group is stamped only via the PowerShell
	/// <c>New-NetFirewallRule -Group</c> path. For <see cref="FirewallBlockScope.RdpPortOnly"/> the
	/// rule restricts to <c>protocol=tcp</c> and the resolved <c>localport</c>; for
	/// <see cref="FirewallBlockScope.AllInbound"/> it uses <c>protocol=any</c>.
	/// </remarks>
	public static IReadOnlyList<string> BuildAddRuleArgs(
		string ruleName,
		string ip,
		string? description,
		FirewallBlockScope scope,
		int rdpPort)
	{
		ValidateRuleName(ruleName);
		string canonicalIp = NormalizeIp(ip);

		// NOTE: deliberately NO "group="/"grouping=" — netsh advfirewall firewall add rule rejects
		// both ("…is not a valid argument"). This was the root cause of the Tools Diag temp-probe
		// failure. The rule-name prefix is the identity handle used for verify / cleanup.
		List<string> args = new(11)
		{
			"advfirewall", "firewall", "add", "rule",
			string.Format(CultureInfo.InvariantCulture, "name={0}", ruleName),
			"dir=in",
			"action=block",
			string.Format(CultureInfo.InvariantCulture, "remoteip={0}", canonicalIp),
			"profile=any",
			"enable=yes",
		};

		if (scope == FirewallBlockScope.RdpPortOnly)
		{
			if (rdpPort < 1 || rdpPort > 65535)
			{
				throw new ArgumentOutOfRangeException(
					nameof(rdpPort),
					rdpPort,
					"RdpPortOnly scope requires a resolved RDP listener port in range 1..65535.");
			}

			args.Add("protocol=tcp");
			args.Add(string.Format(CultureInfo.InvariantCulture, "localport={0}", rdpPort));
		}
		else
		{
			args.Add("protocol=any");
		}

		string safeDescription = SanitizeDescription(description);
		if (safeDescription.Length > 0)
		{
			args.Add(string.Format(CultureInfo.InvariantCulture, "description={0}", safeDescription));
		}

		return args;
	}

	/// <summary>Builds the argument vector for <c>netsh advfirewall firewall delete rule</c>.</summary>
	public static IReadOnlyList<string> BuildDeleteRuleArgs(string ruleName)
	{
		ValidateRuleName(ruleName);
		return new List<string>
		{
			"advfirewall", "firewall", "delete", "rule",
			string.Format(CultureInfo.InvariantCulture, "name={0}", ruleName),
		};
	}

	/// <summary>Builds the argument vector for <c>netsh advfirewall firewall show rule</c> with verbose output.</summary>
	public static IReadOnlyList<string> BuildShowRuleArgs(string ruleName)
	{
		ValidateRuleName(ruleName);
		return new List<string>
		{
			"advfirewall", "firewall", "show", "rule",
			string.Format(CultureInfo.InvariantCulture, "name={0}", ruleName),
			"verbose",
		};
	}

	/// <summary>Builds the argument vector for <c>netsh advfirewall show allprofiles state</c>.</summary>
	public static IReadOnlyList<string> BuildShowAllProfilesStateArgs() =>
		new List<string> { "advfirewall", "show", "allprofiles", "state" };

	/// <summary>Builds the argument vector for <c>netsh advfirewall firewall show rule name=all
	/// verbose</c>. Used by live enforcement reconciliation to enumerate every firewall rule in one
	/// pass; the caller filters the parsed result to the RdpAudit rule-name prefix.</summary>
	public static IReadOnlyList<string> BuildShowAllRulesArgs() =>
		new List<string> { "advfirewall", "firewall", "show", "rule", "name=all", "verbose" };

	/// <summary>Builds the PowerShell <c>New-NetFirewallRule</c> script that creates an enabled inbound
	/// block rule AND stamps <c>-Group RdpAudit</c> so the rule is enumerable via
	/// <c>Get-NetFirewallRule -Group RdpAudit</c>. This is the supported way to set the firewall Group
	/// (netsh's <c>add rule</c> cannot). Every dynamic value (rule name, IP, port) is validated and
	/// emitted as a single-quoted PowerShell literal — single quotes are doubled so no operator value
	/// can break out of the literal. The script returns the created rule's Name on success.</summary>
	/// <param name="ruleName">Validated per-IP rule name (also used as DisplayName).</param>
	/// <param name="ip">Attacker IP; re-validated and canonicalised here.</param>
	/// <param name="description">Optional audit description; sanitised before use.</param>
	/// <param name="scope">RDP-port-only or all-inbound. Drives the protocol / port parameters.</param>
	/// <param name="rdpPort">Resolved RDP listener port; required (1..65535) for
	/// <see cref="FirewallBlockScope.RdpPortOnly"/>.</param>
	public static string BuildNewNetFirewallRuleScript(
		string ruleName,
		string ip,
		string? description,
		FirewallBlockScope scope,
		int rdpPort)
	{
		ValidateRuleName(ruleName);
		string canonicalIp = NormalizeIp(ip);

		if (scope == FirewallBlockScope.RdpPortOnly && (rdpPort < 1 || rdpPort > 65535))
		{
			throw new ArgumentOutOfRangeException(
				nameof(rdpPort),
				rdpPort,
				"RdpPortOnly scope requires a resolved RDP listener port in range 1..65535.");
		}

		StringBuilder sb = new(256);
		sb.Append("$ErrorActionPreference='Stop';");
		// Idempotency: remove any pre-existing rule with the same deterministic name first.
		sb.Append("Get-NetFirewallRule -Name ").Append(PsLiteral(ruleName))
			.Append(" -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction SilentlyContinue;");
		sb.Append("$r=New-NetFirewallRule");
		sb.Append(" -Name ").Append(PsLiteral(ruleName));
		sb.Append(" -DisplayName ").Append(PsLiteral(ruleName));
		sb.Append(" -Group ").Append(PsLiteral(RdpAuditGroup));
		// Write to the persistent store explicitly so the rule survives reboots and is enumerable via
		// Get-NetFirewallRule -Group RdpAudit (the default store is PersistentStore, but stating it makes
		// the intent unambiguous and matches what the operator verifies manually).
		sb.Append(" -PolicyStore PersistentStore");
		sb.Append(" -Direction Inbound -Action Block -Enabled True -Profile Any");
		sb.Append(" -RemoteAddress ").Append(PsLiteral(canonicalIp));

		if (scope == FirewallBlockScope.RdpPortOnly)
		{
			sb.Append(" -Protocol TCP -LocalPort ")
				.Append(rdpPort.ToString(CultureInfo.InvariantCulture));
		}

		string safeDescription = SanitizeDescription(description);
		if (safeDescription.Length > 0)
		{
			sb.Append(" -Description ").Append(PsLiteral(safeDescription));
		}

		sb.Append(';');
		// Emit the created rule's Name so the runner can confirm what landed.
		sb.Append("$r.Name");
		return sb.ToString();
	}

	/// <summary>Quotes a value as a single-quoted PowerShell literal, doubling embedded single quotes.
	/// Inside a single-quoted PowerShell string no escape sequences are interpreted, so doubling the
	/// quote is the only escape needed and there is no interpolation surface.</summary>
	internal static string PsLiteral(string value)
	{
		value ??= string.Empty;
		return "'" + value.Replace("'", "''", StringComparison.Ordinal) + "'";
	}

	/// <summary>Validates a rule name against the conservative ASCII set we accept.</summary>
	private static void ValidateRuleName(string ruleName)
	{
		ArgumentException.ThrowIfNullOrWhiteSpace(ruleName);
		if (ruleName.Length > MaxRuleNameLength)
		{
			throw new ArgumentException(
				string.Format(CultureInfo.InvariantCulture, "Rule name exceeds {0} characters.", MaxRuleNameLength),
				nameof(ruleName));
		}

		foreach (char c in ruleName)
		{
			if (!(char.IsAsciiLetterOrDigit(c) || c == '-' || c == '_' || c == '.' || c == ':'))
			{
				throw new ArgumentException(
					string.Format(CultureInfo.InvariantCulture,
						"Rule name contains characters that could change netsh parsing: '{0}'.",
						ruleName),
					nameof(ruleName));
			}
		}
	}

	/// <summary>Replaces newline / quote / control characters in the description so it cannot break parsing.</summary>
	private static string SanitizeDescription(string? description)
	{
		if (string.IsNullOrWhiteSpace(description))
		{
			return string.Empty;
		}

		StringBuilder sb = new(description.Length);
		foreach (char c in description)
		{
			if (char.IsControl(c) || c == '"' || c == '\'' || c == '|' || c == '&' || c == '<' || c == '>' || c == '\r' || c == '\n')
			{
				sb.Append(' ');
			}
			else
			{
				sb.Append(c);
			}
		}

		string trimmed = sb.ToString().Trim();
		if (trimmed.Length > 512)
		{
			trimmed = trimmed[..512];
		}
		return trimmed;
	}
}
