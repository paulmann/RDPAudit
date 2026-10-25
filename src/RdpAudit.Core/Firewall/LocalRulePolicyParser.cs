// File:    src/RdpAudit.Core/Firewall/LocalRulePolicyParser.cs
// Module:  RdpAudit.Core.Firewall
// Purpose: Pure parser for `netsh advfirewall show allprofiles` output that surfaces the
//          `LocalFirewallRules` (and related `LocalConSecRules`) policy hints. On hosts where
//          group policy forces firewall rules to live in the GPO store, netsh emits
//          `LocalFirewallRules    N/A (GPO-store only)` instead of `Enable`/`Disable`. Stage 4
//          diagnostics need to recognise this row so the "Windows Firewall RDP rule present"
//          probe can explain to the operator that local writes are not allowed by policy —
//          rather than reporting a generic netsh failure.
//
//          The parser is intentionally lenient: it accepts case variations and trailing notes
//          such as "(GPO-store only)" and reports a single tri-state per profile when the row
//          is present.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

namespace RdpAudit.Core.Firewall;

/// <summary>Tri-state describing the `LocalFirewallRules` policy hint for one profile.</summary>
public enum LocalRulePolicyHint
{
	/// <summary>The row was not present in the output, or could not be parsed.</summary>
	Unknown = 0,

	/// <summary>The row reported a concrete value (Enable / Disable / Yes / No).</summary>
	Allowed = 1,

	/// <summary>The row reported `N/A (GPO-store only)` — local writes are blocked by policy.</summary>
	GpoStoreOnly = 2,

	/// <summary>The row reported `Disable` / `No` — local writes are explicitly disabled.</summary>
	Disabled = 3,
}

/// <summary>One row from <c>netsh advfirewall show allprofiles</c> describing the
/// `LocalFirewallRules` value for a single profile.</summary>
public sealed record LocalRulePolicyRow(string? ProfileLabel, LocalRulePolicyHint Hint, string? RawValue);

/// <summary>Pure parser for the `LocalFirewallRules` row in `netsh advfirewall show allprofiles`.</summary>
public static class LocalRulePolicyParser
{
	private const string ProfileHeaderSuffix = "Profile Settings:";
	private const string LocalRulesKey = "LocalFirewallRules";
	private const string GpoMarker = "GPO-store only";

	/// <summary>Parses every <c>LocalFirewallRules</c> row in <paramref name="netshOutput"/> and
	/// returns one record per profile. When no rows are present the returned list is empty —
	/// the caller can fall back to Unknown.</summary>
	public static IReadOnlyList<LocalRulePolicyRow> ParseAllProfiles(string netshOutput)
	{
		List<LocalRulePolicyRow> rows = new();
		if (string.IsNullOrEmpty(netshOutput))
		{
			return rows;
		}

		string[] lines = netshOutput.Replace("\r\n", "\n", StringComparison.Ordinal).Split('\n');
		string? currentProfile = null;

		foreach (string raw in lines)
		{
			string line = raw.Trim();
			if (line.Length == 0)
			{
				continue;
			}

			if (line.EndsWith(ProfileHeaderSuffix, StringComparison.OrdinalIgnoreCase))
			{
				// e.g. "Domain Profile Settings:" → "Domain"
				currentProfile = line[..^ProfileHeaderSuffix.Length].Trim();
				continue;
			}

			if (!line.StartsWith(LocalRulesKey, StringComparison.OrdinalIgnoreCase))
			{
				continue;
			}

			string remainder = line[LocalRulesKey.Length..].Trim();
			if (remainder.StartsWith(':'))
			{
				remainder = remainder[1..].Trim();
			}

			LocalRulePolicyHint hint = Classify(remainder);
			rows.Add(new LocalRulePolicyRow(currentProfile, hint, remainder));
		}

		return rows;
	}

	/// <summary>True when any parsed row reports GPO-store-only (i.e. local writes blocked by policy).</summary>
	public static bool AnyProfileIsGpoStoreOnly(string netshOutput)
	{
		foreach (LocalRulePolicyRow row in ParseAllProfiles(netshOutput))
		{
			if (row.Hint == LocalRulePolicyHint.GpoStoreOnly)
			{
				return true;
			}
		}
		return false;
	}

	/// <summary>Classifies a raw `LocalFirewallRules` value. Accepts the documented netsh tokens
	/// `Enable`, `Disable`, `Yes`, `No`, and the GPO-store-only `N/A` marker.</summary>
	public static LocalRulePolicyHint Classify(string? rawValue)
	{
		if (string.IsNullOrWhiteSpace(rawValue))
		{
			return LocalRulePolicyHint.Unknown;
		}

		string trimmed = rawValue.Trim();
		if (trimmed.Contains(GpoMarker, StringComparison.OrdinalIgnoreCase)
			|| trimmed.StartsWith("N/A", StringComparison.OrdinalIgnoreCase))
		{
			return LocalRulePolicyHint.GpoStoreOnly;
		}

		if (trimmed.StartsWith("Enable", StringComparison.OrdinalIgnoreCase)
			|| trimmed.StartsWith("Yes", StringComparison.OrdinalIgnoreCase))
		{
			return LocalRulePolicyHint.Allowed;
		}

		if (trimmed.StartsWith("Disable", StringComparison.OrdinalIgnoreCase)
			|| trimmed.StartsWith("No", StringComparison.OrdinalIgnoreCase))
		{
			return LocalRulePolicyHint.Disabled;
		}

		return LocalRulePolicyHint.Unknown;
	}
}
