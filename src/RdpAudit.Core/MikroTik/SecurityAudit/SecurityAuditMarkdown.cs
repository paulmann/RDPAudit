// File:    src/RdpAudit.Core/MikroTik/SecurityAudit/SecurityAuditMarkdown.cs
// Module:  RdpAudit.Core.MikroTik.SecurityAudit
// Purpose: Renders a SecurityAuditReport as Markdown for the operator: summary with the risk index,
//          a findings table (id, severity, finding, evidence, autofix), per-finding details with the
//          reason and the ready RouterOS commands, and an explicit list of what was not evaluated.
//          Pure formatting — no device access, no secrets beyond what the findings already carry.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System;
using System.Collections.Generic;
using System.Globalization;
using System.Text;

namespace RdpAudit.Core.MikroTik.SecurityAudit;

/// <summary>Markdown rendering of an audit report.</summary>
public static class SecurityAuditMarkdown
{
	/// <summary>Renders the whole report. The result is stable for a given report (no clock reads).</summary>
	public static string Render(SecurityAuditReport report)
	{
		ArgumentNullException.ThrowIfNull(report);
		StringBuilder sb = new(4096);

		// Every value below arrives from the device over REST (device name, firmware, board, uptime).
		// A line break inside one of them would start a new Markdown block - a heading, a link or an
		// image the operator's viewer then fetches - so each is flattened to a single inline span.
		string device = SafeInlineOr(report.DeviceName, "(unnamed device)");
		sb.Append("# RouterOS security audit — ").AppendLine(device);
		sb.AppendLine();

		sb.Append("- RouterOS: ").AppendLine(SafeInlineOr(report.RouterOsVersion, "(unknown)"));
		sb.Append("- Board: ").AppendLine(SafeInlineOr(report.BoardName, "(unknown)"));
		if (!string.IsNullOrWhiteSpace(report.Uptime))
		{
			sb.Append("- Uptime: ").AppendLine(SafeInline(report.Uptime));
		}
		sb.Append("- Captured: ")
			.Append(report.CapturedUtc.ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture))
			.AppendLine(" UTC");
		sb.AppendLine();

		sb.Append("**Risk index: ").Append(report.RiskIndex.ToString(CultureInfo.InvariantCulture)).Append("/100 — ")
			.Append(report.Verdict).AppendLine("**");
		sb.AppendLine();

		sb.Append("Findings: ").AppendLine(report.SeveritySummary());
		sb.Append("Automatically fixable: ")
			.Append(report.AutoFixableCount.ToString(CultureInfo.InvariantCulture))
			.AppendLine(" (everything else needs a decision or cannot be done over the API).");
		sb.AppendLine();

		if (report.Total == 0)
		{
			sb.AppendLine("No findings. Every rule in the catalogue was evaluated and none matched.");
			sb.AppendLine();
		}
		else
		{
			sb.AppendLine("## Findings");
			sb.AppendLine();
			sb.AppendLine("| ID | Severity | Finding | Evidence | Autofix |");
			sb.AppendLine("|---|---|---|---|---|");
			foreach (SecurityAuditFinding finding in report.Findings)
			{
				sb.Append("| ").Append(finding.RuleId)
					.Append(" | ").Append(SeverityLabel(finding.Severity))
					.Append(" | ").Append(Escape(finding.Title))
					.Append(" | ").Append(Escape(finding.Evidence))
					.Append(" | ").Append(AutofixLabel(finding.Autofix))
					.AppendLine(" |");
			}
			sb.AppendLine();

			sb.AppendLine("## Details");
			sb.AppendLine();
			foreach (SecurityAuditFinding finding in report.Findings)
			{
				sb.Append("### ").Append(finding.RuleId).Append(" — ").AppendLine(SafeInline(finding.Title));
				sb.AppendLine();
				sb.Append("- Evidence: ").AppendLine(CodeSpan(finding.Evidence));
				sb.Append("- Why it matters: ").AppendLine(SafeInline(finding.Why));
				sb.Append("- What to do: ").AppendLine(SafeInline(finding.Recommendation));
				if (finding.Commands.Count > 0)
				{
					sb.AppendLine("- RouterOS commands:");
					sb.AppendLine();
					sb.AppendLine("```");
					foreach (string command in finding.Commands)
					{
						// A fence inside the value would close the block early and let the rest of the
						// report be reshaped by the device.
						sb.AppendLine(SafeInline(command).Replace("```", "'''", StringComparison.Ordinal));
					}
					sb.AppendLine("```");
				}
				sb.AppendLine();
			}
		}

		if (report.UnavailableMenus.Count > 0)
		{
			sb.AppendLine("## Menus this device does not have");
			sb.AppendLine();
			sb.AppendLine("Not findings: the package is absent, so the rules over these menus do not apply.");
			sb.AppendLine();
			foreach (string menu in report.UnavailableMenus)
			{
				sb.Append("- ").Append(CodeSpan(menu)).AppendLine();
			}
			sb.AppendLine();
		}

		sb.AppendLine("---");
		sb.AppendLine("Secrets (passwords, keys, SNMP communities, note text) are never printed in this report.");
		return sb.ToString();
	}

	/// <summary>Flattens a value onto one line and removes backticks.</summary>
	/// <remarks>
	/// The device name, firmware version, board name, uptime and every evidence value come from the
	/// router. A line break would start a new Markdown block in the rendered report (a heading, a
	/// link, an image the viewer fetches), and a backtick would close the inline code span it is
	/// quoted in; neither belongs in a one-line field, so both are neutralised here rather than at
	/// each call site.
	/// </remarks>
	private static string SafeInline(string? value)
	{
		if (string.IsNullOrEmpty(value))
		{
			return string.Empty;
		}

		StringBuilder sb = new(value.Length);
		foreach (char c in value)
		{
			if (c is '\r' or '\n' or '\t')
			{
				sb.Append(' ');
			}
			else if (c == '`')
			{
				sb.Append('\'');
			}
			else
			{
				sb.Append(c);
			}
		}

		return sb.ToString();
	}

	/// <summary><see cref="SafeInline"/> with a fallback for a blank value.</summary>
	private static string SafeInlineOr(string? value, string fallback)
		=> string.IsNullOrWhiteSpace(value) ? fallback : SafeInline(value);

	/// <summary>Renders a value as an inline code span that cannot be closed from inside it.</summary>
	private static string CodeSpan(string? value) => "`" + SafeInline(value) + "`";

	/// <summary>Short label used in the table and in the UI grid.</summary>
	public static string SeverityLabel(SecurityAuditSeverity severity) => severity switch
	{
		SecurityAuditSeverity.Critical => "critical",
		SecurityAuditSeverity.High => "high",
		SecurityAuditSeverity.Medium => "medium",
		SecurityAuditSeverity.Low => "low",
		_ => "info",
	};

	/// <summary>Short label of the autofix class.</summary>
	public static string AutofixLabel(SecurityAuditAutofix autofix) => autofix switch
	{
		SecurityAuditAutofix.Auto => "auto",
		SecurityAuditAutofix.Risky => "risky",
		SecurityAuditAutofix.Manual => "manual",
		_ => "none",
	};

	private static string Escape(string value)
	{
		// A pipe inside a table cell would split the row; the evidence always contains menu :: value.
		return (value ?? string.Empty).Replace("|", "\\|", StringComparison.Ordinal);
	}
}
