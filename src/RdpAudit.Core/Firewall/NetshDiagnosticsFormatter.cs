// File:    src/RdpAudit.Core/Firewall/NetshDiagnosticsFormatter.cs
// Module:  RdpAudit.Core.Firewall
// Purpose: Pure formatter that converts a captured netsh probe outcome (command, args, exit
//          code, stdout, stderr, configured port) into a single actionable diagnostic string.
//          Replaces the previous "netsh exit 1" detail with explicit operator-facing context
//          including the rule name attempted, the configured RDP port, the captured streams,
//          and — when supplied — the firewall provider environment.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System.Globalization;
using System.Text;

namespace RdpAudit.Core.Firewall;

/// <summary>Captured outcome of a single netsh probe invocation. All streams are stored as-is
/// (caller may pass empty strings when nothing was captured).</summary>
public sealed record NetshProbeOutcome(
	string Command,
	IReadOnlyList<string> Arguments,
	int ExitCode,
	string StdOut,
	string StdErr,
	int ConfiguredRdpPort,
	string? RuleNameAttempted,
	bool TimedOut);

/// <summary>Pure formatter for an <see cref="NetshProbeOutcome"/> diagnostic.</summary>
public static class NetshDiagnosticsFormatter
{
	/// <summary>Maximum number of characters from each captured stream to include in the
	/// short-form diagnostic; the full streams are still included in <see cref="FormatFull"/>.</summary>
	public const int ShortStreamLimit = 200;

	/// <summary>Short form suitable for the Prerequisites tab's "Detail" cell.</summary>
	public static string FormatShort(NetshProbeOutcome outcome)
	{
		ArgumentNullException.ThrowIfNull(outcome);
		StringBuilder sb = new();
		sb.Append("netsh exit ").Append(outcome.ExitCode.ToString(CultureInfo.InvariantCulture));
		sb.Append("; port=").Append(outcome.ConfiguredRdpPort.ToString(CultureInfo.InvariantCulture));
		if (!string.IsNullOrEmpty(outcome.RuleNameAttempted))
		{
			sb.Append("; rule=").Append(outcome.RuleNameAttempted);
		}
		if (outcome.TimedOut)
		{
			sb.Append("; timed-out");
		}

		string stdOutSnippet = Snippet(outcome.StdOut, ShortStreamLimit);
		if (!string.IsNullOrEmpty(stdOutSnippet))
		{
			sb.Append("; stdout=").Append(stdOutSnippet);
		}

		string stdErrSnippet = Snippet(outcome.StdErr, ShortStreamLimit);
		if (!string.IsNullOrEmpty(stdErrSnippet))
		{
			sb.Append("; stderr=").Append(stdErrSnippet);
		}

		return sb.ToString();
	}

	/// <summary>Long form, suitable for the Copy diagnostics clipboard payload.</summary>
	public static string FormatFull(NetshProbeOutcome outcome, FirewallProviderDiagnostics? providerDiagnostics = null)
	{
		ArgumentNullException.ThrowIfNull(outcome);
		StringBuilder sb = new();
		sb.Append("netsh firewall probe").Append('\n');
		sb.Append("  command: ").Append(outcome.Command);
		foreach (string a in outcome.Arguments)
		{
			sb.Append(' ').Append(a);
		}
		sb.Append('\n');
		sb.Append("  exit code: ").Append(outcome.ExitCode.ToString(CultureInfo.InvariantCulture)).Append('\n');
		sb.Append("  configured RDP port: ")
			.Append(outcome.ConfiguredRdpPort.ToString(CultureInfo.InvariantCulture)).Append('\n');
		if (!string.IsNullOrEmpty(outcome.RuleNameAttempted))
		{
			sb.Append("  rule name attempted: ").Append(outcome.RuleNameAttempted).Append('\n');
		}
		if (outcome.TimedOut)
		{
			sb.Append("  timed out: yes").Append('\n');
		}

		sb.Append("  stdout:");
		AppendStreamBlock(sb, outcome.StdOut);
		sb.Append("  stderr:");
		AppendStreamBlock(sb, outcome.StdErr);

		if (providerDiagnostics is not null)
		{
			sb.Append('\n').Append(providerDiagnostics.BuildDiagnosticsText());
		}

		return sb.ToString().TrimEnd('\n');
	}

	private static void AppendStreamBlock(StringBuilder sb, string? raw)
	{
		if (string.IsNullOrEmpty(raw))
		{
			sb.Append(" (empty)").Append('\n');
			return;
		}

		sb.Append('\n');
		foreach (string line in raw.Replace("\r\n", "\n", StringComparison.Ordinal).Split('\n'))
		{
			sb.Append("    ").Append(line).Append('\n');
		}
	}

	private static string Snippet(string? value, int max)
	{
		if (string.IsNullOrEmpty(value))
		{
			return string.Empty;
		}

		string flat = value
			.Replace('\r', ' ')
			.Replace('\n', ' ')
			.Trim();
		return flat.Length <= max ? flat : flat[..max] + "…";
	}
}
