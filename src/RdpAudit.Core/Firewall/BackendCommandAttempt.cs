// File:    src/RdpAudit.Core/Firewall/BackendCommandAttempt.cs
// Module:  RdpAudit.Core.Firewall
// Purpose: Captures the full backend-command detail of a single firewall block / verify attempt so
//          per-IP diagnostics can show exactly what ran instead of an opaque "Failed / Failed". Carries
//          the resolved executable, argument line, runner mode, exit code, timeout flag, wall-clock
//          duration, and bounded stdout / stderr previews. When the backend exits non-zero with empty
//          stderr the stdout preview is the only failure signal, so it is always populated independently.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System.Globalization;

namespace RdpAudit.Core.Firewall;

/// <summary>Runner mode used to spawn a backend command.</summary>
/// <remarks>Append-only enum: values must never be reused or reordered.</remarks>
public enum BackendRunnerMode
{
	Unknown = 0,
	EnglishConsole = 1,
	Direct = 2,
	PowerShellJson = 3,
	Cim = 4,
	Raw = 5,
}

/// <summary>Full backend-command detail of a single firewall block / verify attempt.</summary>
/// <remarks>Previews are bounded and control-character-flattened by the producer so the record is
/// safe to persist and surface in operator UI without leaking multi-line raw output.</remarks>
public sealed record BackendCommandAttempt(
	string CommandLabel,
	string Executable,
	string Arguments,
	BackendRunnerMode RunnerMode,
	int ExitCode,
	bool TimedOut,
	long DurationMs,
	string StdoutPreview,
	string StderrPreview,
	string? ScannerBackend = null)
{
	/// <summary>Maximum characters retained for either stdout or stderr preview.</summary>
	public const int PreviewLimit = 512;

	/// <summary>True when the command exited cleanly with code zero and did not time out.</summary>
	public bool Success => !TimedOut && ExitCode == 0;

	/// <summary>Bounds and flattens a raw stdout / stderr string into a single-line preview.</summary>
	public static string BuildPreview(string? value, int max = PreviewLimit)
	{
		if (string.IsNullOrEmpty(value))
		{
			return string.Empty;
		}

		System.Text.StringBuilder sb = new(value!.Length);
		foreach (char c in value)
		{
			sb.Append(char.IsControl(c) ? ' ' : c);
		}

		string trimmed = sb.ToString().Trim();
		return trimmed.Length <= max ? trimmed : trimmed[..max] + "…";
	}

	/// <summary>Renders exactly one well-formed backend command line for operator display, built from
	/// the same structured executable / argument vector used for execution. <see cref="CommandLabel"/>
	/// is a short human label (e.g. <c>"New-NetFirewallRule -Group RdpAudit"</c>) and <see cref="Arguments"/>
	/// is the full argument line; naively concatenating the two duplicates the verb
	/// (<c>"New-NetFirewallRule -Group RdpAudit New-NetFirewallRule -Name …"</c>). This method instead
	/// joins <see cref="Executable"/> and <see cref="Arguments"/> — the actual invocation — and falls back
	/// to the label only when neither is populated. The result never contains a duplicated leading verb.</summary>
	public string RenderCommandLine()
	{
		bool hasExe = !string.IsNullOrWhiteSpace(Executable);
		bool hasArgs = !string.IsNullOrWhiteSpace(Arguments);

		if (hasExe && hasArgs)
		{
			return Executable + " " + Arguments;
		}

		if (hasArgs)
		{
			return Arguments;
		}

		if (hasExe)
		{
			return Executable;
		}

		return CommandLabel;
	}

	/// <summary>Builds a single-line operator-facing diagnostic. When the command exited non-zero with
	/// empty stderr the stdout preview is included so a silent exit=1 still carries a failure signal.</summary>
	public string BuildDiagnostic()
	{
		System.Text.StringBuilder sb = new();
		sb.Append(CommandLabel);
		sb.Append(" [runner=").Append(RunnerMode.ToString());
		if (!string.IsNullOrEmpty(ScannerBackend))
		{
			sb.Append(" scanner=").Append(ScannerBackend);
		}

		sb.Append("] exe=").Append(Executable);
		if (!string.IsNullOrEmpty(Arguments))
		{
			sb.Append(" args=\"").Append(Arguments).Append('"');
		}

		sb.Append(" exit=").Append(ExitCode.ToString(CultureInfo.InvariantCulture));
		sb.Append(" ms=").Append(DurationMs.ToString(CultureInfo.InvariantCulture));
		if (TimedOut)
		{
			sb.Append(" (timed-out)");
		}

		if (StderrPreview.Length > 0)
		{
			sb.Append(" stderr=\"").Append(StderrPreview).Append('"');
		}

		// A non-zero exit with empty stderr is the case the operator needs stdout for.
		if (StdoutPreview.Length > 0 && (ExitCode != 0 || StderrPreview.Length == 0))
		{
			sb.Append(" stdout=\"").Append(StdoutPreview).Append('"');
		}

		return sb.ToString();
	}
}
