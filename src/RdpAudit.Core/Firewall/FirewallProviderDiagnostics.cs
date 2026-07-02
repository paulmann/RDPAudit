/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 1.2.0
// File   : FirewallProviderDiagnostics.cs
// Project: RdpAudit.Core (RdpAudit.Core.Firewall)
// Purpose: Pure detection / diagnostics models for the firewall environment surrounding the
//          RDP listener: which Windows Firewall profiles are enabled, which third-party
//          security products (Kaspersky in particular) appear to be present, and whether
//          direct Windows Firewall rule management is expected to succeed. The detection
//          providers live in the platform-specific hosts (Configurator touches Win32
//          services/processes/WMI/filesystem; Service touches ServiceController); the pure
//          result models and diagnostic-text formatter live here so both hosts and unit
//          tests can consume the same shape without any Win32 dependency.
// Depends: LocalRulePolicyRow, LocalRulePolicyHint, CultureInfo, StringBuilder
// Extends: Add new diagnostic fields here when introducing a new provider signal or report
//          section; preserve positional-record parameter names and enum ordinals for
//          backward compatibility across Configurator, Service, and test call sites.

using System.Globalization;
using System.Text;

namespace RdpAudit.Core.Firewall;

/// <summary>Identifies the detected firewall provider context on the host. Distinct from
/// <see cref="RdpAudit.Core.Config.FirewallProviderKind"/> which controls which provider
/// RdpAudit will <em>drive</em>; this enum reports what is <em>installed and active</em>.</summary>
/// <remarks>Append-only enum: ordinals must not be reused or reordered.</remarks>
public enum FirewallProviderDetectedKind
{
	/// <summary>Detection has not been attempted, or no firewall stack was identified.</summary>
	Unknown = 0,

	/// <summary>Plain Windows Defender Firewall (no managing third-party).</summary>
	WindowsDefenderFirewall = 1,

	/// <summary>A Kaspersky product is installed/running but its relationship to Windows
	/// Firewall is not confirmed (e.g. Kaspersky Endpoint Security on a workstation).</summary>
	KasperskyDetected = 2,

	/// <summary>A Kaspersky product is installed/running AND signals (services, policies)
	/// suggest it is managing Windows Firewall — direct netsh writes may be blocked.</summary>
	KasperskyManagedWindowsFirewall = 3,

	/// <summary>A third-party firewall stack was detected but its identity was not classified.</summary>
	ThirdPartyFirewallUnknown = 4,
}

/// <summary>State of a single Windows Firewall profile.</summary>
public sealed record FirewallProfileState(
	string ProfileName,
	bool Enabled,
	string? DefaultInboundAction,
	string? DefaultOutboundAction,
	bool? AllowLocalFirewallRules,
	string? PolicySource);

/// <summary>State of one Windows service relevant to the firewall stack.</summary>
public sealed record FirewallServiceState(
	string ServiceName,
	string? DisplayName,
	string Status,
	bool IsRunning);

/// <summary>State of one detected third-party CLI tool.</summary>
/// <remarks>
/// Kept as a positional record with parameter names <c>ToolName</c>, <c>Path</c>, <c>Present</c>
/// so every existing call site across Configurator, Service, and unit tests that uses named
/// arguments (<c>Present:</c>, <c>Path:</c>) continues to compile unchanged. <see cref="FullPath"/>
/// is an additive, non-breaking extension populated via <see cref="WithFullPath"/> for probes
/// that resolve a concrete on-disk location distinct from the legacy <see cref="Path"/> field.
/// </remarks>
public sealed record FirewallCliToolPresence(string ToolName, string? Path, bool Present)
{
	/// <summary>Concrete filesystem path, when known. Defaults to <see cref="Path"/> so existing
	/// callers that never set it still get a sensible value.</summary>
	public string FullPath { get; init; } = Path ?? string.Empty;

	/// <summary>Factory for probes that resolved a concrete full path and want it mirrored into
	/// both <see cref="Path"/> and <see cref="FullPath"/> without adding an ambiguous constructor
	/// overload to the positional record above.</summary>
	public static FirewallCliToolPresence WithFullPath(string toolName, string fullPath, bool present) =>
		new(toolName, present ? fullPath : null, present) { FullPath = fullPath ?? string.Empty };
}

/// <summary>Snapshot of the firewall environment, suitable for UI display and clipboard export.</summary>
/// <remarks>
/// All collections are non-null. Missing data points should be represented as <c>null</c>
/// scalars or empty collections rather than synthesised placeholders so the UI can render
/// a faithful "unknown" rather than misleading "off".
/// </remarks>
public sealed class FirewallProviderDiagnostics
{
	// ── Public API ───────────────────────────────────────────────────────────────

	/// <summary>Detection classification — see <see cref="FirewallProviderDetectedKind"/>.</summary>
	public FirewallProviderDetectedKind ProviderKind { get; init; } = FirewallProviderDetectedKind.Unknown;

	/// <summary>Human-readable provider name (e.g. "Windows Defender Firewall",
	/// "Kaspersky Endpoint Security for Windows"). Never null.</summary>
	public string ProviderName { get; init; } = "Unknown";

	/// <summary>Windows services that contribute to the detected firewall context.</summary>
	public IReadOnlyList<FirewallServiceState> ProviderServices { get; init; } = Array.Empty<FirewallServiceState>();

	/// <summary>Third-party CLI tools detected on the host (kescli / kavshell / avp).
	/// Reported regardless of whether RdpAudit can drive them.</summary>
	public IReadOnlyList<FirewallCliToolPresence> DetectedCliTools { get; init; } = Array.Empty<FirewallCliToolPresence>();

	/// <summary>Per-profile state for the three Windows Firewall profiles (Domain/Private/Public)
	/// when readable. Empty when no profile data was collected.</summary>
	public IReadOnlyList<FirewallProfileState> WindowsFirewallProfiles { get; init; } = Array.Empty<FirewallProfileState>();

	/// <summary>Whether local Windows Firewall rule management appears allowed.
	/// <c>null</c> = unknown (no policy data collected).</summary>
	public bool? LocalRuleManagementAllowed { get; init; }

	/// <summary>Parsed per-profile <c>LocalFirewallRules</c> rows from
	/// <c>netsh advfirewall show allprofiles</c>. Empty when the probe did not collect them.
	/// One entry per profile recognised; <see cref="LocalRulePolicyHint.GpoStoreOnly"/> means
	/// local rule writes are blocked by Group Policy (<c>N/A (GPO-store only)</c>).</summary>
	public IReadOnlyList<LocalRulePolicyRow> LocalRulePolicyRows { get; init; } = Array.Empty<LocalRulePolicyRow>();

	/// <summary>Configured RDP TCP port observed on the host. <c>null</c> when not resolved.</summary>
	public int? ConfiguredRdpPort { get; init; }

	/// <summary>Optional free-form notes appended by the probe (errors, fallback explanations).</summary>
	public IReadOnlyList<string> Notes { get; init; } = Array.Empty<string>();

	/// <summary>True when the detected provider kind implies a third-party firewall/security
	/// stack is present and should be surfaced as a caveat in enforcement diagnostics. This is
	/// the single source of truth consumed by both Configurator UI and Service IPC responses.</summary>
	public bool ThirdPartyFirewallSuspected =>
		ProviderKind is FirewallProviderDetectedKind.KasperskyDetected
			or FirewallProviderDetectedKind.KasperskyManagedWindowsFirewall
			or FirewallProviderDetectedKind.ThirdPartyFirewallUnknown;

	/// <summary>True when at least one profile reports the GPO-store-only marker — direct local
	/// firewall writes (<c>netsh ... add rule</c>) are expected to be rejected by policy.</summary>
	public bool LocalRulesAreGpoStoreOnly
	{
		get
		{
			foreach (LocalRulePolicyRow row in LocalRulePolicyRows)
			{
				if (row.Hint == LocalRulePolicyHint.GpoStoreOnly)
				{
					return true;
				}
			}

			return false;
		}
	}

	// ── Core Logic ───────────────────────────────────────────────────────────────

	/// <summary>Builds a single, copy-paste-friendly diagnostics text block summarising every
	/// captured field. Stable English output; never localised.</summary>
	public string BuildDiagnosticsText()
	{
		StringBuilder sb = new();

		sb.Append("Firewall provider: ")
			.Append(ProviderName)
			.Append(" (kind=")
			.Append(ProviderKind)
			.Append(')')
			.Append('\n');

		if (ConfiguredRdpPort is int port)
		{
			sb.Append("Configured RDP port: ")
				.Append(port.ToString(CultureInfo.InvariantCulture))
				.Append('\n');
		}

		if (LocalRuleManagementAllowed is bool allowed)
		{
			sb.Append("Local Windows Firewall rule management allowed: ")
				.Append(allowed ? "yes" : "no")
				.Append('\n');
		}

		if (LocalRulePolicyRows.Count > 0)
		{
			sb.Append("LocalFirewallRules policy (per profile):")
				.Append('\n');

			foreach (LocalRulePolicyRow row in LocalRulePolicyRows)
			{
				sb.Append("  - ")
					.Append(string.IsNullOrEmpty(row.ProfileLabel) ? "(profile)" : row.ProfileLabel)
					.Append(": ")
					.Append(row.Hint);

				if (!string.IsNullOrEmpty(row.RawValue))
				{
					sb.Append(" [")
						.Append(row.RawValue)
						.Append(']');
				}

				sb.Append('\n');
			}

			if (LocalRulesAreGpoStoreOnly)
			{
				sb.Append("Note: at least one profile reports LocalFirewallRules N/A (GPO-store only) — direct local netsh writes are blocked by Group Policy.")
					.Append('\n');
			}
		}

		if (ProviderServices.Count > 0)
		{
			sb.Append("Services:")
				.Append('\n');

			foreach (FirewallServiceState svc in ProviderServices)
			{
				sb.Append("  - ")
					.Append(svc.ServiceName);

				if (!string.IsNullOrEmpty(svc.DisplayName) &&
					!string.Equals(svc.DisplayName, svc.ServiceName, StringComparison.Ordinal))
				{
					sb.Append(" (")
						.Append(svc.DisplayName)
						.Append(')');
				}

				sb.Append(": ")
					.Append(string.IsNullOrEmpty(svc.Status)
						? (svc.IsRunning ? "Running" : "Stopped")
						: svc.Status)
					.Append('\n');
			}
		}

		if (DetectedCliTools.Count > 0)
		{
			sb.Append("Detected CLI tools:")
				.Append('\n');

			foreach (FirewallCliToolPresence tool in DetectedCliTools)
			{
				sb.Append("  - ")
					.Append(tool.ToolName)
					.Append(": ");

				if (tool.Present)
				{
					string? displayPath = !string.IsNullOrEmpty(tool.Path)
						? tool.Path
						: (!string.IsNullOrEmpty(tool.FullPath) ? tool.FullPath : null);

					sb.Append(displayPath ?? "(present, path unknown)");
				}
				else
				{
					sb.Append("not present");
				}

				sb.Append('\n');
			}
		}

		if (WindowsFirewallProfiles.Count > 0)
		{
			sb.Append("Windows Firewall profiles:")
				.Append('\n');

			foreach (FirewallProfileState profile in WindowsFirewallProfiles)
			{
				sb.Append("  - ")
					.Append(profile.ProfileName)
					.Append(": enabled=")
					.Append(profile.Enabled ? "yes" : "no");

				if (profile.DefaultInboundAction is not null)
				{
					sb.Append(", inbound=")
						.Append(profile.DefaultInboundAction);
				}

				if (profile.DefaultOutboundAction is not null)
				{
					sb.Append(", outbound=")
						.Append(profile.DefaultOutboundAction);
				}

				if (profile.AllowLocalFirewallRules is bool localRules)
				{
					sb.Append(", allowLocalRules=")
						.Append(localRules ? "yes" : "no");
				}

				if (!string.IsNullOrEmpty(profile.PolicySource))
				{
					sb.Append(", policy=")
						.Append(profile.PolicySource);
				}

				sb.Append('\n');
			}
		}

		if (Notes.Count > 0)
		{
			sb.Append("Notes:")
				.Append('\n');

			foreach (string note in Notes)
			{
				sb.Append("  - ")
					.Append(note)
					.Append('\n');
			}
		}

		return sb.ToString().TrimEnd('\n');
	}
}
