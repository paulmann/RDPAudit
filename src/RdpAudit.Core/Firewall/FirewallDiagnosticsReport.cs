// File:    src/RdpAudit.Core/Firewall/FirewallDiagnosticsReport.cs
// Module:  RdpAudit.Core.Firewall
// Purpose: Pure formatter for the "Copy firewall diagnostics" report. Aggregates the firewall-
//          enforcement facts an operator needs to confirm that RdpAudit's IP blocking is actually
//          in effect: configured provider/backend, the resolved (non-hardcoded) RDP listener port,
//          per-provider availability, RdpAudit-group inbound block rules present in the Windows
//          firewall store, enabled-allow inbound TCP ports (so a stale 3389 allow rule is visible
//          next to the real listener port), route-blackhole / IPsec backend state, third-party
//          firewall (e.g. Kaspersky) interference notes, and a reconciliation of active enforcement
//          against blocklist / active-block database rows. Produces a single English block the
//          operator can paste into a support ticket. Pure formatting; no I/O. Callers pass pre-read
//          facts so this stays unit-testable cross-platform and never depends on Win32 / EF.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System.Globalization;
using System.Text;
using RdpAudit.Core.Config;

namespace RdpAudit.Core.Firewall;

/// <summary>Per-provider readiness line used by <see cref="FirewallDiagnosticsReportBuilder"/>.</summary>
public sealed record FirewallProviderDiagnostic(
	string ProviderId,
	bool Available,
	int ActiveBlockCount,
	string? Message);

/// <summary>The concrete shape of one live RdpAudit-owned inbound block rule, projected down to the
/// fields that determine its block scope: the protocol it restricts to (if any) and the local ports
/// it pins (empty when it blocks every port). Used to detect drift between the configured
/// <see cref="FirewallBlockScope"/> and the rules actually installed in the firewall.</summary>
public sealed record FirewallRuleShape(string RuleName, string? Protocol, IReadOnlyList<int> LocalPorts);

/// <summary>One detected mismatch between a live rule's shape and the configured block scope.</summary>
public sealed record FirewallScopeMismatch(string RuleName, string Detail);

/// <summary>Pure analyzer that classifies live RdpAudit rule shapes against the configured block
/// scope and resolved RDP port. Cross-platform / unit-testable: performs no I/O and depends only on
/// the projected <see cref="FirewallRuleShape"/> values the service reads from the firewall.</summary>
public static class FirewallScopeMismatchAnalyzer
{
	/// <summary>Returns one <see cref="FirewallScopeMismatch"/> per live rule whose shape does not match
	/// the configured scope. For <see cref="FirewallBlockScope.AllInbound"/> a rule is expected to
	/// pin no protocol / no local port (it blocks everything); a rule that restricts to a TCP local port
	/// is flagged as still RDP-port-only. For <see cref="FirewallBlockScope.RdpPortOnly"/> a rule
	/// is expected to restrict to TCP on <paramref name="resolvedRdpPort"/>; a rule that pins no port (or a
	/// different port) is flagged as still all-inbound / wrong-port.</summary>
	public static IReadOnlyList<FirewallScopeMismatch> Analyze(
		FirewallBlockScope configuredScope,
		int resolvedRdpPort,
		IReadOnlyList<FirewallRuleShape> liveRules)
	{
		ArgumentNullException.ThrowIfNull(liveRules);

		List<FirewallScopeMismatch> mismatches = new();
		foreach (FirewallRuleShape rule in liveRules)
		{
			bool pinsPort = rule.LocalPorts is { Count: > 0 };
			bool isTcp = string.Equals(rule.Protocol, "TCP", StringComparison.OrdinalIgnoreCase);

			if (configuredScope == FirewallBlockScope.AllInbound)
			{
				if (pinsPort)
				{
					mismatches.Add(new FirewallScopeMismatch(
						rule.RuleName,
						string.Format(
							CultureInfo.InvariantCulture,
							"configured AllInbound but rule restricts to {0} LocalPort={1} (still RDP-port-only). "
								+ "Re-apply to widen it to all inbound traffic.",
							rule.Protocol ?? "TCP",
							FormatPorts(rule.LocalPorts))));
				}

				continue;
			}

			// configuredScope == RdpPortOnly
			if (!pinsPort)
			{
				mismatches.Add(new FirewallScopeMismatch(
					rule.RuleName,
					string.Format(
						CultureInfo.InvariantCulture,
						"configured RdpPortOnly (TCP {0}) but rule pins no local port (still blocks all inbound). "
							+ "Re-apply to narrow it to the resolved RDP port.",
						resolvedRdpPort)));
			}
			else if (!isTcp || !rule.LocalPorts.Contains(resolvedRdpPort))
			{
				mismatches.Add(new FirewallScopeMismatch(
					rule.RuleName,
					string.Format(
						CultureInfo.InvariantCulture,
						"configured RdpPortOnly (TCP {0}) but rule pins {1} LocalPort={2}. "
							+ "Re-apply to match the resolved RDP port.",
						resolvedRdpPort,
						rule.Protocol ?? "(unspecified)",
						FormatPorts(rule.LocalPorts))));
			}
		}

		return mismatches;
	}

	private static string FormatPorts(IReadOnlyList<int> ports) =>
		ports.Count == 0
			? "(none)"
			: string.Join(",", ports.Select(p => p.ToString(CultureInfo.InvariantCulture)));
}

/// <summary>Aggregate diagnostic input for <see cref="FirewallDiagnosticsReportBuilder.Build"/>.
/// Every field is pre-resolved by the service so the builder performs no I/O.</summary>
public sealed record FirewallDiagnosticsInput(
	string ConfiguredProviderKind,
	string ConfiguredEnforcementBackend,
	string ConfiguredBlockScope,
	int ResolvedRdpPort,
	bool RdpPortFromRegistry,
	IReadOnlyList<FirewallProviderDiagnostic> Providers,
	int RdpAuditGroupBlockRuleCount,
	IReadOnlyList<int> EnabledAllowInboundTcpPorts,
	bool RdpAuditAllowRuleForResolvedPort,
	string RouteBackendState,
	string IPsecBackendState,
	bool ThirdPartyFirewallSuspected,
	string? ThirdPartyFirewallNote,
	int BlocklistRowCount,
	int ActiveBlockRowCount,
	int VerifiedEnforcedCount)
{
	/// <summary>Per-IP reconciled enforcement lines (IP, status, confidence, recommended action).
	/// Empty when a live reconciliation pass was not available. Optional so existing callers bind.</summary>
	public IReadOnlyList<ReconciledEnforcementLine> ReconciledBlocks { get; init; } =
		Array.Empty<ReconciledEnforcementLine>();

	/// <summary>Orphaned RdpAudit firewall rule names discovered with no backing database row.</summary>
	public IReadOnlyList<string> OrphanedRuleNames { get; init; } = Array.Empty<string>();

	/// <summary>Which enumeration backend produced the firewall scan: "PowerShellJson" (locale-
	/// independent, preferred), "NetshText" (locale-fragile fallback), or "None" (not scanned).</summary>
	public string ScannerBackend { get; init; } = "None";

	/// <summary>Optional human-readable note from the firewall scan (backend detail / failure cause).</summary>
	public string? ScannerNote { get; init; }

	/// <summary>Live shapes of discovered RdpAudit-owned inbound block rules, used to detect scope drift
	/// against <see cref="ConfiguredBlockScope"/> / <see cref="ResolvedRdpPort"/>. Empty when a live scan
	/// was not available; optional so existing positional callers keep binding.</summary>
	public IReadOnlyList<FirewallRuleShape> DiscoveredRuleShapes { get; init; } =
		Array.Empty<FirewallRuleShape>();
}

/// <summary>One per-IP reconciled enforcement line for the diagnostics report.</summary>
/// <remarks>The backend-detail members are optional (init-only) so existing positional callers keep
/// compiling; when populated they let the report show exactly what the last block attempt ran instead
/// of an opaque "Failed / Failed".</remarks>
public sealed record ReconciledEnforcementLine(
	string Ip,
	string Status,
	string Confidence,
	string? EnforcementObjectId,
	string RecommendedAction)
{
	/// <summary>Last provider error for this IP, when the most recent attempt failed.</summary>
	public string? LastError { get; init; }

	/// <summary>UTC timestamp of the most recent block / repair attempt for this IP.</summary>
	public DateTime? LastAttemptUtc { get; init; }

	/// <summary>Backend command line of the most recent attempt (e.g. the netsh argument vector).</summary>
	public string? BackendCommand { get; init; }

	/// <summary>Bounded stdout preview of the most recent backend attempt.</summary>
	public string? BackendStdoutPreview { get; init; }

	/// <summary>Bounded stderr preview of the most recent backend attempt.</summary>
	public string? BackendStderrPreview { get; init; }

	/// <summary>Process exit code of the most recent backend attempt; null when none captured.</summary>
	public int? ExitCode { get; init; }

	/// <summary>True when the most recent backend attempt hit its hard timeout.</summary>
	public bool? TimedOut { get; init; }

	/// <summary>Wall-clock duration in milliseconds of the most recent backend attempt.</summary>
	public long? DurationMs { get; init; }

	/// <summary>Rule name created / verified by the most recent attempt.</summary>
	public string? RuleName { get; init; }

	/// <summary>Backend rule handle of the most recent attempt.</summary>
	public string? RuleHandle { get; init; }

	/// <summary>Scanner / runner backend used for the most recent attempt (e.g. NetshText).</summary>
	public string? ScannerBackend { get; init; }

	/// <summary>Human-readable reason the verifier reached its verdict on the most recent attempt.</summary>
	public string? VerifierReason { get; init; }
}

/// <summary>Pure formatter for the Copy firewall diagnostics block.</summary>
public static class FirewallDiagnosticsReportBuilder
{
	/// <summary>Builds the firewall diagnostics report from pre-read facts.</summary>
	public static string Build(FirewallDiagnosticsInput input)
	{
		ArgumentNullException.ThrowIfNull(input);

		StringBuilder sb = new();
		sb.Append("RdpAudit firewall diagnostics — ")
			.AppendLine(DateTime.UtcNow.ToString("u", CultureInfo.InvariantCulture));
		sb.AppendLine();

		sb.AppendLine("[Configuration]");
		sb.Append("  Provider: ").AppendLine(input.ConfiguredProviderKind);
		sb.Append("  Enforcement backend: ").AppendLine(input.ConfiguredEnforcementBackend);
		sb.Append("  Block scope: ").AppendLine(input.ConfiguredBlockScope);
		sb.Append("  Resolved RDP port: ")
			.Append(input.ResolvedRdpPort.ToString(CultureInfo.InvariantCulture))
			.Append(input.RdpPortFromRegistry ? " (from registry)" : " (documented default)")
			.AppendLine();
		sb.AppendLine();

		sb.AppendLine("[Providers]");
		if (input.Providers.Count == 0)
		{
			sb.AppendLine("  (no providers registered)");
		}
		else
		{
			foreach (FirewallProviderDiagnostic p in input.Providers)
			{
				sb.Append("  ").Append(p.ProviderId).Append(": ")
					.Append(p.Available ? "available" : "unavailable")
					.Append(", activeBlocks=")
					.Append(p.ActiveBlockCount.ToString(CultureInfo.InvariantCulture));
				if (!string.IsNullOrEmpty(p.Message))
				{
					sb.Append(" — ").Append(p.Message);
				}

				sb.AppendLine();
			}
		}

		sb.AppendLine();
		sb.AppendLine("[Firewall scanner backend used]");
		sb.Append("  Backend: ").AppendLine(DescribeScannerBackend(input.ScannerBackend));
		if (!string.IsNullOrEmpty(input.ScannerNote))
		{
			sb.Append("  Note: ").AppendLine(input.ScannerNote);
		}

		if (string.Equals(input.ScannerBackend, "NetshText", StringComparison.OrdinalIgnoreCase))
		{
			sb.AppendLine("  WARNING: rules were enumerated by parsing localized netsh text. On a non-English "
				+ "Windows host the rule labels are translated, so this path can report zero rules even when "
				+ "rules exist. The PowerShell JSON backend (Get-NetFirewallRule) is locale-independent and "
				+ "should be preferred.");
		}

		sb.AppendLine("  Manual equivalent (run as Administrator):");
		sb.AppendLine("    Get-NetFirewallRule -Group 'RdpAudit' | "
			+ "Select-Object Name,DisplayName,Direction,Action,Enabled | Format-Table -AutoSize");
		sb.AppendLine("    Get-NetFirewallRule -Group 'RdpAudit' | "
			+ "ForEach-Object { $_ | Get-NetFirewallAddressFilter | Select-Object RemoteAddress }");

		sb.AppendLine();
		sb.AppendLine("[Windows firewall store]");
		sb.Append("  RdpAudit-group inbound block rules: ")
			.AppendLine(input.RdpAuditGroupBlockRuleCount.ToString(CultureInfo.InvariantCulture));
		sb.Append("  Allow-inbound rule for resolved RDP port (")
			.Append(input.ResolvedRdpPort.ToString(CultureInfo.InvariantCulture))
			.Append("): ")
			.AppendLine(input.RdpAuditAllowRuleForResolvedPort ? "present" : "ABSENT");
		sb.Append("  Enabled allow-inbound TCP ports: ")
			.AppendLine(FormatPorts(input.EnabledAllowInboundTcpPorts));
		sb.AppendLine();

		AppendBlockScopeSection(sb, input);

		sb.AppendLine("[Alternate backends]");
		sb.Append("  Route blackhole: ").AppendLine(input.RouteBackendState);
		sb.Append("  IPsec policy: ").AppendLine(input.IPsecBackendState);
		sb.AppendLine();

		sb.AppendLine("[Third-party firewall]");
		bool scanFailed = string.Equals(input.ScannerBackend, "NetshText", StringComparison.OrdinalIgnoreCase)
			|| string.Equals(input.ScannerBackend, "None", StringComparison.OrdinalIgnoreCase);
		if (input.ThirdPartyFirewallSuspected)
		{
			sb.AppendLine("  Detected: YES (a third-party firewall such as Kaspersky is present).");
			sb.AppendLine("  Interference: UNKNOWN until a live block is tested. Detection alone does not prove "
				+ "the third-party stack rejected or bypassed an RdpAudit rule — rules may still be created "
				+ "and enforced normally.");
			if (scanFailed)
			{
				sb.AppendLine("  Caution: the firewall scan did not use the locale-independent PowerShell backend, "
					+ "so a reported 'zero rules' here may be a scanner limitation rather than third-party "
					+ "interference. Do not attribute missing rules to the third-party firewall on this basis.");
			}
		}
		else
		{
			sb.AppendLine("  Detected: no third-party firewall positively identified.");
		}

		if (!string.IsNullOrEmpty(input.ThirdPartyFirewallNote))
		{
			sb.Append("  Note: ").AppendLine(input.ThirdPartyFirewallNote);
		}

		sb.AppendLine();
		sb.AppendLine("[Enforcement reconciliation]");
		sb.AppendLine("  Counts below come from three distinct sources and are NOT expected to be equal:");
		sb.Append("  - Blocklist rows (enabled, intent in DB): ")
			.AppendLine(input.BlocklistRowCount.ToString(CultureInfo.InvariantCulture));
		sb.Append("  - Active-block rows (active/pending, attempted enforcement): ")
			.AppendLine(input.ActiveBlockRowCount.ToString(CultureInfo.InvariantCulture));
		sb.Append("  - Per-IP reconciled lines (one per active-block, see below): ")
			.AppendLine(input.ReconciledBlocks.Count.ToString(CultureInfo.InvariantCulture));
		sb.Append("  - Verified enforced (live firewall rule confirmed present): ")
			.AppendLine(input.VerifiedEnforcedCount.ToString(CultureInfo.InvariantCulture));
		sb.AppendLine("  An enabled blocklist row only becomes an active-block (and a per-IP line) once "
			+ "enforcement is attempted; a row can be enabled in the blocklist without yet having an "
			+ "active-block, which is why these two counts legitimately differ.");

		int unenforced = input.ActiveBlockRowCount - input.VerifiedEnforcedCount;
		if (unenforced > 0)
		{
			sb.Append("  WARNING: ")
				.Append(unenforced.ToString(CultureInfo.InvariantCulture))
				.AppendLine(" active-block row(s) have NO confirmed firewall enforcement — "
					+ "a database row alone does not block traffic. Use Blocklist → Repair Selected / "
					+ "Repair All Enabled to (re-)install and verify the firewall rules.");
		}

		if (input.ReconciledBlocks.Count > 0)
		{
			sb.AppendLine();
			sb.AppendLine("[Per-IP reconciliation]");
			foreach (ReconciledEnforcementLine line in input.ReconciledBlocks)
			{
				sb.Append("  ").Append(line.Ip)
					.Append(": ").Append(line.Status)
					.Append(" / ").Append(line.Confidence);
				if (!string.IsNullOrEmpty(line.EnforcementObjectId))
				{
					sb.Append(" [").Append(line.EnforcementObjectId).Append(']');
				}

				sb.Append(" — ").AppendLine(line.RecommendedAction);
				AppendBackendDetail(sb, line);
			}
		}

		if (input.OrphanedRuleNames.Count > 0)
		{
			sb.AppendLine();
			sb.AppendLine("[Orphaned RdpAudit rules (no backing database row)]");
			foreach (string ruleName in input.OrphanedRuleNames)
			{
				sb.Append("  ").AppendLine(ruleName);
			}
		}

		return sb.ToString();
	}

	/// <summary>Appends the per-attempt backend detail under a reconciled line so a failed IP shows the
	/// exact command, exit code, rule, scanner backend and error instead of a bare "Failed / Failed".</summary>
	private static void AppendBackendDetail(StringBuilder sb, ReconciledEnforcementLine line)
	{
		if (!string.IsNullOrEmpty(line.LastError))
		{
			sb.Append("      LastError: ").AppendLine(line.LastError);
		}

		if (line.LastAttemptUtc is { } attempt)
		{
			sb.Append("      LastAttemptUtc: ")
				.AppendLine(attempt.ToString("u", CultureInfo.InvariantCulture));
		}

		if (line.ExitCode is { } exit)
		{
			sb.Append("      ExitCode: ").Append(exit.ToString(CultureInfo.InvariantCulture));
			if (line.TimedOut == true)
			{
				sb.Append(" (timed-out)");
			}

			if (line.DurationMs is { } ms)
			{
				sb.Append(" durationMs=").Append(ms.ToString(CultureInfo.InvariantCulture));
			}

			sb.AppendLine();
		}

		if (!string.IsNullOrEmpty(line.RuleName) || !string.IsNullOrEmpty(line.RuleHandle))
		{
			sb.Append("      Rule: ").Append(line.RuleName ?? "(none)");
			if (!string.IsNullOrEmpty(line.RuleHandle)
				&& !string.Equals(line.RuleHandle, line.RuleName, StringComparison.Ordinal))
			{
				sb.Append(" handle=").Append(line.RuleHandle);
			}

			sb.AppendLine();
		}

		if (!string.IsNullOrEmpty(line.ScannerBackend))
		{
			sb.Append("      ScannerBackend: ").AppendLine(line.ScannerBackend);
		}

		if (!string.IsNullOrEmpty(line.VerifierReason))
		{
			sb.Append("      VerifierReason: ").AppendLine(line.VerifierReason);
		}

		if (!string.IsNullOrEmpty(line.BackendCommand))
		{
			sb.Append("      BackendCommand: ").AppendLine(line.BackendCommand);
		}

		if (!string.IsNullOrEmpty(line.BackendStdoutPreview))
		{
			sb.Append("      stdout: ").AppendLine(line.BackendStdoutPreview);
		}

		if (!string.IsNullOrEmpty(line.BackendStderrPreview))
		{
			sb.Append("      stderr: ").AppendLine(line.BackendStderrPreview);
		}
	}

	/// <summary>Renders the configured block scope, the expected rule shape for that scope, and any
	/// detected mismatches between the live RdpAudit rules and the configured scope. This is the section
	/// that prevents the UI from silently claiming RdpPortOnly while existing rules still block all
	/// inbound traffic — every drifting rule is named with a concrete remediation hint.</summary>
	private static void AppendBlockScopeSection(StringBuilder sb, FirewallDiagnosticsInput input)
	{
		bool rdpOnly = string.Equals(input.ConfiguredBlockScope, "RdpPortOnly", StringComparison.OrdinalIgnoreCase);

		sb.AppendLine("[Block scope]");
		sb.Append("  Configured scope: ").AppendLine(input.ConfiguredBlockScope);
		if (rdpOnly)
		{
			sb.Append("  Expected rule shape: inbound block, TCP, LocalPort=")
				.Append(input.ResolvedRdpPort.ToString(CultureInfo.InvariantCulture))
				.AppendLine(" (the resolved RDP listener port).");
		}
		else
		{
			sb.AppendLine("  Expected rule shape: inbound block, Protocol=Any, LocalPort=Any "
				+ "(every inbound port from the source IP). LocalPort=Any is EXPECTED because BlockScope=AllInbound.");
		}

		FirewallBlockScope scopeEnum = rdpOnly ? FirewallBlockScope.RdpPortOnly : FirewallBlockScope.AllInbound;
		IReadOnlyList<FirewallScopeMismatch> mismatches =
			FirewallScopeMismatchAnalyzer.Analyze(scopeEnum, input.ResolvedRdpPort, input.DiscoveredRuleShapes);

		if (input.DiscoveredRuleShapes.Count == 0)
		{
			sb.AppendLine("  Existing rule mismatches: (no live rule shapes were scanned).");
		}
		else if (mismatches.Count == 0)
		{
			sb.Append("  Existing rule mismatches: none — all ")
				.Append(input.DiscoveredRuleShapes.Count.ToString(CultureInfo.InvariantCulture))
				.AppendLine(" scanned RdpAudit rule(s) match the configured scope.");
		}
		else
		{
			sb.Append("  WARNING: ")
				.Append(mismatches.Count.ToString(CultureInfo.InvariantCulture))
				.Append(" of ")
				.Append(input.DiscoveredRuleShapes.Count.ToString(CultureInfo.InvariantCulture))
				.AppendLine(" RdpAudit rule(s) do NOT match the configured scope. Use the Firewall tab "
					+ "'Apply scope to existing rules' (Repair all enabled) to reconcile them:");
			foreach (FirewallScopeMismatch m in mismatches)
			{
				sb.Append("    ").Append(m.RuleName).Append(": ").AppendLine(m.Detail);
			}
		}

		sb.AppendLine();
	}

	private static string DescribeScannerBackend(string backend) => backend switch
	{
		"PowerShellJson" => "PowerShell Get-NetFirewallRule JSON (locale-independent; preferred)",
		"NetshText" => "netsh verbose text parse (locale-fragile fallback)",
		"None" => "none (no live scan was performed)",
		_ => backend,
	};

	private static string FormatPorts(IReadOnlyList<int> ports)
	{
		if (ports.Count == 0)
		{
			return "(none)";
		}

		StringBuilder sb = new();
		for (int i = 0; i < ports.Count; i++)
		{
			if (i > 0)
			{
				sb.Append(", ");
			}

			sb.Append(ports[i].ToString(CultureInfo.InvariantCulture));
		}

		return sb.ToString();
	}
}
