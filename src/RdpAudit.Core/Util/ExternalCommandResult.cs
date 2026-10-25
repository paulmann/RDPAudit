// File:    src/RdpAudit.Core/Util/ExternalCommandResult.cs
// Module:  RdpAudit.Core.Util
// Purpose: Pure result record returned by every external command invocation routed through
//          the centralized RdpAudit command-execution helper. Captures everything required
//          to (a) decide whether the call succeeded, (b) parse the captured stdout, and
//          (c) produce a safe single-line diagnostic summary for logs / UI. The record is
//          intentionally provider-agnostic and contains no Windows-specific types so it can
//          live in Core and be returned by both the Configurator-side and Service-side
//          process adapters.
//
//          Safe diagnostic summary:
//              * The summary NEVER includes raw stdout / stderr beyond a bounded truncation —
//                anything longer than 240 chars is collapsed.
//              * Newlines and other control characters are flattened so the summary stays a
//                single grep-friendly line.
//              * Secrets are never logged; the helper only invokes whitelisted tools whose
//                stdout does not contain credential material in normal operation.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System.Globalization;

namespace RdpAudit.Core.Util;

/// <summary>Outcome of one external command invocation routed through the centralized helper.</summary>
/// <param name="CommandLabel">Stable human-readable label for the command (e.g. "qwinsta",
/// "netsh advfirewall show allprofiles", "auditpol /get") used in logs and UI. Never null.</param>
/// <param name="Executable">Absolute path or unqualified file name of the spawned binary
/// (e.g. <c>cmd.exe</c> when the English console wrapper is used; <c>netsh.exe</c> when
/// direct argument-list execution is used). Never null.</param>
/// <param name="ExitCode">Process exit code; 0 indicates success. <c>-1</c> when the process
/// could not be started or when a hard timeout fired.</param>
/// <param name="StdOut">Captured stdout, decoded with the runner's text encoding. Never null
/// (empty when nothing was written).</param>
/// <param name="StdErr">Captured stderr, decoded with the runner's text encoding. Never null
/// (empty when nothing was written).</param>
/// <param name="TimedOut">True when the hard timeout fired and the process was killed.</param>
/// <param name="Duration">Wall-clock duration measured by the runner.</param>
/// <param name="EnglishConsoleMode">True when the command was wrapped through
/// <c>cmd /d /c "chcp 437 >nul &amp; ..."</c> for parse-stable English stdout. False for
/// direct argument-list execution.</param>
public sealed record ExternalCommandResult(
	string CommandLabel,
	string Executable,
	int ExitCode,
	string StdOut,
	string StdErr,
	bool TimedOut,
	TimeSpan Duration,
	bool EnglishConsoleMode)
{
	/// <summary>True when the process exited cleanly with code zero and did not time out.</summary>
	public bool Success => !TimedOut && ExitCode == 0;

	/// <summary>Builds a single-line diagnostic summary suitable for logs and UI. The summary
	/// contains: label, exit code, timeout flag, English-console flag, total ms, and bounded
	/// stderr/stdout snippets. No raw multi-line content reaches the log.</summary>
	public string BuildDiagnosticSummary()
	{
		string flat(string? value, int max)
		{
			if (string.IsNullOrEmpty(value))
			{
				return string.Empty;
			}

			System.Text.StringBuilder sb = new(value.Length);
			foreach (char c in value)
			{
				sb.Append(char.IsControl(c) ? ' ' : c);
			}

			string trimmed = sb.ToString().Trim();
			return trimmed.Length <= max ? trimmed : trimmed[..max] + "…";
		}

		string err = flat(StdErr, 240);
		string @out = flat(StdOut, 120);

		System.Text.StringBuilder result = new();
		result.Append(CommandLabel);
		result.Append(" exit=").Append(ExitCode.ToString(CultureInfo.InvariantCulture));
		result.Append(" ms=").Append(((int)Duration.TotalMilliseconds).ToString(CultureInfo.InvariantCulture));
		if (TimedOut)
		{
			result.Append(" (timed-out)");
		}

		if (EnglishConsoleMode)
		{
			result.Append(" (en-console)");
		}

		if (err.Length > 0)
		{
			result.Append(" stderr=\"").Append(err).Append('"');
		}

		if (@out.Length > 0 && ExitCode != 0)
		{
			result.Append(" stdout=\"").Append(@out).Append('"');
		}

		return result.ToString();
	}
}
