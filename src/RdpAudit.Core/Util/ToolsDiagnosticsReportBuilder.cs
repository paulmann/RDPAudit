// File:    src/RdpAudit.Core/Util/ToolsDiagnosticsReportBuilder.cs
// Module:  RdpAudit.Core.Util
// Purpose: Pure formatter for the Tools Diag transcript. Renders each ToolProbeResultDto as a labelled
//          block showing tool name, resolved executable, arguments, runner mode, working directory, exit
//          code, duration, timed-out flag, pass/fail, locale hint and bounded stdout / stderr previews,
//          plus a temporary-firewall-rule probe transcript. Kept in Core with no I/O so it is unit-
//          testable on Linux CI with fake probe results — no Windows command ever runs under test.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System.Globalization;
using System.Text;
using RdpAudit.Core.Ipc.Contracts;

namespace RdpAudit.Core.Util;

/// <summary>Pure formatter for the Tools Diag copy/save transcript.</summary>
public static class ToolsDiagnosticsReportBuilder
{
	/// <summary>Builds the full Tools Diag transcript from the probe set.</summary>
	public static string Build(IReadOnlyList<ToolProbeResultDto> probes, DateTime generatedUtc)
	{
		ArgumentNullException.ThrowIfNull(probes);

		StringBuilder sb = new();
		sb.Append("RdpAudit Tools Diag — ")
			.AppendLine(generatedUtc.ToString("u", CultureInfo.InvariantCulture));
		sb.Append("Probes: ").Append(probes.Count.ToString(CultureInfo.InvariantCulture)).AppendLine();
		sb.AppendLine();

		for (int i = 0; i < probes.Count; i++)
		{
			AppendProbe(sb, probes[i], i + 1);
			sb.AppendLine();
		}

		return sb.ToString();
	}

	/// <summary>Builds the temporary-firewall-rule probe transcript.</summary>
	public static string BuildTemporaryProbe(TemporaryFirewallProbeDto probe)
	{
		ArgumentNullException.ThrowIfNull(probe);

		StringBuilder sb = new();
		sb.Append("RdpAudit temporary firewall rule probe — ")
			.AppendLine(probe.GeneratedUtc.ToString("u", CultureInfo.InvariantCulture));
		sb.Append("  Test IP: ").AppendLine(probe.TestIp);
		sb.Append("  Rule name: ").AppendLine(probe.RuleName);
		if (!string.IsNullOrEmpty(probe.RuleHandle))
		{
			sb.Append("  Rule handle: ").AppendLine(probe.RuleHandle);
		}

		if (!string.IsNullOrEmpty(probe.ScannerBackend))
		{
			sb.Append("  Scanner backend: ").AppendLine(probe.ScannerBackend);
		}

		sb.Append("  Created+verified+cleaned up: ")
			.AppendLine(probe.CreatedVerifiedAndCleanedUp ? "YES" : "NO");
		if (!string.IsNullOrEmpty(probe.Message))
		{
			sb.Append("  Note: ").AppendLine(probe.Message);
		}

		sb.AppendLine();
		for (int i = 0; i < probe.Steps.Count; i++)
		{
			AppendProbe(sb, probe.Steps[i], i + 1);
			sb.AppendLine();
		}

		return sb.ToString();
	}

	private static void AppendProbe(StringBuilder sb, ToolProbeResultDto p, int index)
	{
		sb.Append('[').Append(index.ToString(CultureInfo.InvariantCulture)).Append("] ")
			.Append(p.ToolName)
			.Append("  —  ").AppendLine(p.Passed ? "PASS" : "FAIL");
		sb.Append("    Executable: ").AppendLine(p.Executable.Length > 0 ? p.Executable : "(none)");
		sb.Append("    Arguments: ").AppendLine(p.Arguments.Length > 0 ? p.Arguments : "(none)");
		sb.Append("    Runner mode: ").AppendLine(p.RunnerMode);
		if (p.WorkingDirectory.Length > 0)
		{
			sb.Append("    Working dir: ").AppendLine(p.WorkingDirectory);
		}

		sb.Append("    Exit code: ").Append(p.ExitCode.ToString(CultureInfo.InvariantCulture));
		sb.Append("  durationMs=").Append(p.DurationMs.ToString(CultureInfo.InvariantCulture));
		if (p.TimedOut)
		{
			sb.Append("  (timed-out)");
		}

		sb.AppendLine();
		if (p.LocaleHint.Length > 0)
		{
			sb.Append("    Locale hint: ").AppendLine(p.LocaleHint);
		}

		if (!string.IsNullOrEmpty(p.Note))
		{
			sb.Append("    Note: ").AppendLine(p.Note);
		}

		if (p.StdoutPreview.Length > 0)
		{
			sb.Append("    stdout: ").AppendLine(p.StdoutPreview);
		}

		if (p.StderrPreview.Length > 0)
		{
			sb.Append("    stderr: ").AppendLine(p.StderrPreview);
		}
	}
}
