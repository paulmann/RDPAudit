/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 1.1.0
// File   : FirewallProviderClassifier.cs
// Project: RdpAudit.Core (RdpAudit.Core.Firewall)
// Purpose: Pure classifier that derives a FirewallProviderDetectedKind + provider name from a
//          captured snapshot of services / CLI tools / Windows Firewall profiles. Kept Win32-free
//          so the same rules can be unit-tested without spawning a real Windows host. Every
//          collection walk below uses an indexed for-loop rather than foreach: iterating an
//          IReadOnlyList<T>-typed parameter via foreach forces the C# compiler to dispatch through
//          IEnumerable<T>.GetEnumerator(), which boxes List<T>'s struct enumerator on the heap —
//          a per-call allocation that violates the zero-alloc hot-path directive even though no
//          `new`, string interpolation, or LINQ appears anywhere in this file.
// Depends: FirewallServiceState, FirewallCliToolPresence, FirewallProviderDetectedKind
// Extends: Add new vendor service-name fragments to KasperskyServiceFragments /
//          ThirdPartyFirewallServiceFragments; add new CLI tool name checks to
//          DescribeKasperskyName. Always iterate via indexed for-loops, never foreach, to
//          preserve the zero-allocation guarantee proven by
//          RdpAudit.Service.Tests.ThirdPartyFirewallClassifierTests.

namespace RdpAudit.Core.Firewall;

/// <summary>Pure classifier for <see cref="FirewallProviderDetectedKind"/>.</summary>
public static class FirewallProviderClassifier
{
	/// <summary>Service-name fragments that signal a Kaspersky product. Match is case-insensitive
	/// substring on the service short name or display name.</summary>
	public static readonly IReadOnlyList<string> KasperskyServiceFragments = new[]
	{
		"AVP",          // Kaspersky Anti-Virus / Endpoint Security main service ("avp.exe")
		"klnagent",     // Kaspersky Security Center Network Agent
		"klflt",        // Kaspersky filter driver
		"klim6",        // Kaspersky NDIS driver
		"klhk",         // Kaspersky hooking driver
		"klbackupdisk", // Kaspersky backup
		"klbackupflt",
		"kavfs",        // Kaspersky Security for Windows Server (KSWS) main service
		"kavfsgt",      // KSWS management service
		"kavfsmui",     // KSWS UI service
		"kavfsrcn",     // KSWS Compact Monitor
		"kavfswh",      // KSWS Web Console
		"kavshell",     // KSWS shell helper
		"kes",          // Kaspersky Endpoint Security (KES) marker
		"ksws",         // Kaspersky Security for Windows Server marker
	};

	/// <summary>Service-name fragments that signal a non-Kaspersky third-party firewall stack.</summary>
	public static readonly IReadOnlyList<string> ThirdPartyFirewallServiceFragments = new[]
	{
		"Symantec",
		"ekrn",       // ESET
		"egui",
		"BdAgent",    // Bitdefender
		"vsmon",      // Check Point ZoneAlarm
		"SAVService", // Sophos
		"McAfee",
		"mfemms",
		"mfevtps",
		"mbamservice", // Malwarebytes
		"WRSVC",       // Webroot
		"avast",
		"avgsvc",
		"f-secure",
	};

	// ── Public API ───────────────────────────────────────────────────────────────

	/// <summary>Classify the provider given collected service / CLI / profile state and an
	/// optional explicit "Kaspersky is managing Windows Firewall" signal supplied by the probe.</summary>
	/// <param name="services">Captured Windows services (firewall-relevant subset).</param>
	/// <param name="cliTools">Captured CLI tool presence flags.</param>
	/// <param name="kasperskyManagesWindowsFirewall">
	/// <c>true</c> when the probe has strong evidence (KSWS Firewall Management policy / running
	/// KSWS firewall management component) that Kaspersky is controlling Windows Firewall; the
	/// classifier promotes <see cref="FirewallProviderDetectedKind.KasperskyDetected"/> to
	/// <see cref="FirewallProviderDetectedKind.KasperskyManagedWindowsFirewall"/> in that case.
	/// </param>
	public static (FirewallProviderDetectedKind Kind, string Name) Classify(
		IReadOnlyList<FirewallServiceState> services,
		IReadOnlyList<FirewallCliToolPresence> cliTools,
		bool kasperskyManagesWindowsFirewall)
	{
		ArgumentNullException.ThrowIfNull(services);
		ArgumentNullException.ThrowIfNull(cliTools);

		bool kasperskyDetected = AnyServiceMatches(services, KasperskyServiceFragments)
			|| AnyCliToolPresent(cliTools);

		if (kasperskyDetected)
		{
			string name = DescribeKasperskyName(services, cliTools);
			return kasperskyManagesWindowsFirewall
				? (FirewallProviderDetectedKind.KasperskyManagedWindowsFirewall, name)
				: (FirewallProviderDetectedKind.KasperskyDetected, name);
		}

		if (AnyServiceMatches(services, ThirdPartyFirewallServiceFragments))
		{
			return (FirewallProviderDetectedKind.ThirdPartyFirewallUnknown, "Third-party firewall (unclassified)");
		}

		// Default — pure Windows Defender Firewall. We claim this even when MpsSvc is stopped:
		// the classification is about which product owns the firewall slot, not whether it is up.
		return (FirewallProviderDetectedKind.WindowsDefenderFirewall, "Windows Defender Firewall");
	}

	// ── Zero-Alloc Collection Walks ───────────────────────────────────────────────
	// NOTE: every method below uses an indexed `for` loop against `.Count` / `[i]`.
	// Do not convert these to `foreach` — see the file header comment for why that
	// reintroduces a per-call heap allocation via boxed List<T> enumerators.

	private static bool AnyServiceMatches(IReadOnlyList<FirewallServiceState> services, IReadOnlyList<string> fragments)
	{
		for (int i = 0; i < services.Count; i++)
		{
			FirewallServiceState svc = services[i];

			for (int j = 0; j < fragments.Count; j++)
			{
				string frag = fragments[j];

				if (Contains(svc.ServiceName, frag) || Contains(svc.DisplayName, frag))
				{
					return true;
				}
			}
		}

		return false;
	}

	private static bool AnyCliToolPresent(IReadOnlyList<FirewallCliToolPresence> cliTools)
	{
		for (int i = 0; i < cliTools.Count; i++)
		{
			if (cliTools[i].Present)
			{
				return true;
			}
		}

		return false;
	}

	private static bool Contains(string? haystack, string fragment)
	{
		if (string.IsNullOrEmpty(haystack) || string.IsNullOrEmpty(fragment))
		{
			return false;
		}

		return haystack.Contains(fragment, StringComparison.OrdinalIgnoreCase);
	}

	private static string DescribeKasperskyName(
		IReadOnlyList<FirewallServiceState> services,
		IReadOnlyList<FirewallCliToolPresence> cliTools)
	{
		// Prefer the most-specific name we can derive from observed services / CLI tools.
		// KSWS markers beat KES markers beat the generic "Kaspersky product" string.
		for (int i = 0; i < services.Count; i++)
		{
			FirewallServiceState svc = services[i];

			if (Contains(svc.ServiceName, "kavfs") || Contains(svc.DisplayName, "Kaspersky Security for Windows Server"))
			{
				return "Kaspersky Security for Windows Server";
			}
		}

		for (int i = 0; i < services.Count; i++)
		{
			FirewallServiceState svc = services[i];

			if (Contains(svc.DisplayName, "Kaspersky Endpoint Security") || Contains(svc.ServiceName, "KES"))
			{
				return "Kaspersky Endpoint Security for Windows";
			}
		}

		for (int i = 0; i < cliTools.Count; i++)
		{
			FirewallCliToolPresence tool = cliTools[i];

			if (!tool.Present)
			{
				continue;
			}

			if (string.Equals(tool.ToolName, "kavshell.exe", StringComparison.OrdinalIgnoreCase))
			{
				return "Kaspersky Security for Windows Server";
			}

			if (string.Equals(tool.ToolName, "kescli.exe", StringComparison.OrdinalIgnoreCase))
			{
				return "Kaspersky Endpoint Security for Windows";
			}

			if (string.Equals(tool.ToolName, "avp.exe", StringComparison.OrdinalIgnoreCase)
				|| string.Equals(tool.ToolName, "avp.com", StringComparison.OrdinalIgnoreCase))
			{
				// `avp.exe` / `avp.com` is the canonical CLI shipped with Kaspersky AV /
				// Endpoint Security for Windows. The user diagnostic on Windows 10 Pro
				// reports both candidates and the running AVP21.24 service.
				return "Kaspersky Endpoint Security for Windows";
			}
		}

		// Last-resort: when only a generic `AVP*` service is observed (no display name match,
		// no CLI hit), we still know the operator is running Kaspersky AV / Endpoint Security —
		// on workstation SKUs that surfaces as `AVPxx.yy` (e.g. AVP21.24 in the user diagnostic).
		for (int i = 0; i < services.Count; i++)
		{
			if (Contains(services[i].ServiceName, "AVP"))
			{
				return "Kaspersky Endpoint Security for Windows";
			}
		}

		return "Kaspersky product (detected)";
	}
}
