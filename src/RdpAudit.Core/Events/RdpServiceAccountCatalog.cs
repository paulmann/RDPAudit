// File:    src/RdpAudit.Core/Events/RdpServiceAccountCatalog.cs
// Module:  RdpAudit.Core.Events
// Purpose: Pure, UI-free catalog that decodes the well-known Windows service / built-in / RDP
//          session account names (DWM-1, UMFD-0, SYSTEM, LOCAL SERVICE, "$"-suffixed machine
//          accounts, …) into a human-readable explanation. The "Top 10 Attempted Logins" column
//          frequently mixes genuine attacker usernames with these internal accounts, so the
//          Configurator uses this catalog to append a legend to that column's header tooltip.
// Depends: (none — plain static maps over strings)
// Extends: To document a new internal account, add an exact match to ExactMatches or a family
//          rule to the prefix scan in Describe(). Keep entries English and one-line.
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System.Collections.ObjectModel;
using System.Globalization;
using System.Text;

namespace RdpAudit.Core.Events;

/// <summary>Decodes well-known Windows service / built-in / RDP session accounts into text.</summary>
public static class RdpServiceAccountCatalog
{
	// ── Data ─────────────────────────────────────────────────────────────────────

	/// <summary>Exact, case-insensitive built-in / well-known security principals.</summary>
	private static readonly ReadOnlyDictionary<string, string> ExactMatches =
		new ReadOnlyDictionary<string, string>(new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
		{
			["SYSTEM"] = "Local System (NT AUTHORITY\\SYSTEM) — the most privileged local account; "
				+ "used by the OS kernel and core services, never a real remote logon.",
			["LOCAL SERVICE"] = "NT AUTHORITY\\LOCAL SERVICE — a low-privilege account used by services "
				+ "that need no network identity.",
			["NETWORK SERVICE"] = "NT AUTHORITY\\NETWORK SERVICE — a low-privilege account used by services "
				+ "that present the computer's identity on the network.",
			["ANONYMOUS LOGON"] = "NT AUTHORITY\\ANONYMOUS LOGON — an unauthenticated (null-session) logon.",
			["LOCAL"] = "NT AUTHORITY\\LOCAL — the local console pseudo-account.",
			["DWM"] = "Desktop Window Manager base name (per-session accounts appear as DWM-<sessionId>).",
			["UMFD"] = "User Mode Font Driver host base name (per-session accounts appear as UMFD-<sessionId>).",
		});

	/// <summary>Case-insensitive prefixes that identify a per-session internal account family.</summary>
	private static readonly (string Prefix, string Description)[] PrefixFamilies =
	{
		("DWM-", "Desktop Window Manager session account (DWM-<sessionId>). Windows creates one per "
			+ "interactive/RDP session to composite the desktop. It is an OS-generated account, not an attacker login."),
		("UMFD-", "User Mode Font Driver Host session account (UMFD-<sessionId>). Windows spawns one per "
			+ "session to render fonts out-of-process. OS-generated, not an attacker login."),
	};

	// ── Public API ───────────────────────────────────────────────────────────────

	/// <summary>Returns a human-readable description for a login name when it is a recognised
	/// Windows service / built-in / RDP session account; returns null for ordinary usernames.</summary>
	public static string? Describe(string? login)
	{
		if (string.IsNullOrWhiteSpace(login))
		{
			return null;
		}

		string name = login.Trim();

		if (ExactMatches.TryGetValue(name, out string? exact))
		{
			return exact;
		}

		foreach ((string prefix, string description) in PrefixFamilies)
		{
			if (name.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
			{
				return description;
			}
		}

		// A trailing "$" marks a computer (machine) account — e.g. "WIN-SRV01$".
		if (name.EndsWith('$'))
		{
			return "Computer (machine) account — a trailing '$' denotes the Active Directory computer "
				+ "object, used for machine-to-machine authentication, not a human login.";
		}

		return null;
	}

	/// <summary>True when the login is a recognised Windows service / built-in / RDP session account
	/// (i.e. <see cref="Describe"/> would return a non-null explanation).</summary>
	public static bool IsServiceAccount(string? login) => Describe(login) is not null;

	/// <summary>Builds a static legend of the common RDP-protocol service accounts, one per line.
	/// Used to enrich the "Top 10 Attempted Logins" column header tooltip so an operator can tell
	/// OS-generated session accounts apart from genuine attacker usernames.</summary>
	public static string BuildLegend()
	{
		StringBuilder sb = new();
		sb.AppendLine("Service / built-in accounts commonly seen alongside RDP activity:");
		sb.AppendLine("• DWM-<n> — Desktop Window Manager, one per session (desktop compositing).");
		sb.AppendLine("• UMFD-<n> — User Mode Font Driver Host, one per session (font rendering).");
		sb.AppendLine("• SYSTEM — NT AUTHORITY\\SYSTEM, the OS kernel/core-services account.");
		sb.AppendLine("• LOCAL SERVICE / NETWORK SERVICE — low-privilege service accounts.");
		sb.AppendLine("• ANONYMOUS LOGON — unauthenticated null-session logon.");
		sb.Append("• NAME$ — an Active Directory computer (machine) account.");
		return sb.ToString();
	}

	/// <summary>Returns a one-line inline annotation for a single login, e.g.
	/// "DWM-2 → Desktop Window Manager session account …", or the login unchanged when ordinary.</summary>
	public static string AnnotateInline(string login)
	{
		string? description = Describe(login);
		return description is null
			? login
			: string.Format(CultureInfo.InvariantCulture, "{0} → {1}", login, description);
	}
}
