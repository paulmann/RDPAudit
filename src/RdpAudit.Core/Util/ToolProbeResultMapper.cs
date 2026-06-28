// File:    src/RdpAudit.Core/Util/ToolProbeResultMapper.cs
// Module:  RdpAudit.Core.Util
// Purpose: Pure mapper that projects an ExternalCommandResult (the output of the centralized command
//          runner) onto the Tools Diag ToolProbeResultDto, filling in runner mode, bounded stdout /
//          stderr previews, a best-effort locale hint and the pass/fail verdict. Kept in Core with no
//          Windows-specific types so the Tools Diag formatting / metadata is unit-testable on Linux CI
//          with fake runner outputs — no Windows-only command ever has to execute under test.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using RdpAudit.Core.Firewall;
using RdpAudit.Core.Ipc.Contracts;

namespace RdpAudit.Core.Util;

/// <summary>Pure mapper from <see cref="ExternalCommandResult"/> to <see cref="ToolProbeResultDto"/>.</summary>
public static class ToolProbeResultMapper
{
	/// <summary>Maximum characters retained for either stdout or stderr preview.</summary>
	public const int PreviewLimit = 1024;

	/// <summary>Builds a <see cref="ToolProbeResultDto"/> from a command result and an explicit argument
	/// line / runner-mode label (the runner does not echo the argument vector back).</summary>
	public static ToolProbeResultDto Map(
		ExternalCommandResult result,
		string toolName,
		string arguments,
		string runnerMode,
		string workingDirectory = "",
		string? note = null)
	{
		ArgumentNullException.ThrowIfNull(result);

		string stdout = Flatten(result.StdOut, PreviewLimit);
		string stderr = Flatten(result.StdErr, PreviewLimit);

		return new ToolProbeResultDto
		{
			ToolName = toolName,
			Executable = result.Executable,
			Arguments = arguments,
			RunnerMode = runnerMode.Length > 0 ? runnerMode : (result.EnglishConsoleMode ? "EnglishConsole" : "Direct"),
			WorkingDirectory = workingDirectory,
			ExitCode = result.ExitCode,
			DurationMs = (long)result.Duration.TotalMilliseconds,
			TimedOut = result.TimedOut,
			StdoutPreview = stdout,
			StderrPreview = stderr,
			LocaleHint = DetectLocaleHint(result.StdOut),
			Passed = result.Success,
			Note = note,
		};
	}

	/// <summary>Projects a firewall <see cref="BackendCommandAttempt"/> (one create / verify / cleanup
	/// step of the temporary-firewall-rule probe) onto a <see cref="ToolProbeResultDto"/>, preserving the
	/// exact command, runner mode, exit code, timed-out flag, duration and bounded stdout / stderr.</summary>
	public static ToolProbeResultDto FromBackendAttempt(
		BackendCommandAttempt attempt,
		string toolName,
		string? note = null) =>
		new()
		{
			ToolName = toolName,
			Executable = attempt.Executable,
			Arguments = attempt.Arguments,
			RunnerMode = attempt.RunnerMode.ToString(),
			WorkingDirectory = string.Empty,
			ExitCode = attempt.ExitCode,
			DurationMs = attempt.DurationMs,
			TimedOut = attempt.TimedOut,
			StdoutPreview = attempt.StdoutPreview,
			StderrPreview = attempt.StderrPreview,
			LocaleHint = string.Empty,
			Passed = attempt.Success,
			Note = note,
		};

	/// <summary>Builds a skipped/unavailable probe result (e.g. when running on a non-Windows host).</summary>
	public static ToolProbeResultDto Skipped(string toolName, string arguments, string note) =>
		new()
		{
			ToolName = toolName,
			Executable = string.Empty,
			Arguments = arguments,
			RunnerMode = "Skipped",
			WorkingDirectory = string.Empty,
			ExitCode = -1,
			DurationMs = 0,
			TimedOut = false,
			StdoutPreview = string.Empty,
			StderrPreview = string.Empty,
			LocaleHint = string.Empty,
			Passed = false,
			Note = note,
		};

	/// <summary>Best-effort locale hint: reports whether the output contains any non-ASCII characters,
	/// which on a localized Windows host is the signal that English-token parsing may be unreliable.</summary>
	internal static string DetectLocaleHint(string? output)
	{
		if (string.IsNullOrEmpty(output))
		{
			return string.Empty;
		}

		foreach (char c in output!)
		{
			if (c > 0x7F)
			{
				return "non-ASCII characters present (output may be localized)";
			}
		}

		return "ASCII-only output";
	}

	private static string Flatten(string? value, int max)
	{
		if (string.IsNullOrEmpty(value))
		{
			return string.Empty;
		}

		System.Text.StringBuilder sb = new(value!.Length);
		foreach (char c in value)
		{
			sb.Append(char.IsControl(c) && c != ' ' ? ' ' : c);
		}

		string trimmed = sb.ToString().Trim();
		return trimmed.Length <= max ? trimmed : trimmed[..max] + "…";
	}
}
