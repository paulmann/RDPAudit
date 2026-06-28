// File:    src/RdpAudit.Core/Ipc/Contracts/ToolsDiagnosticsDto.cs
// Module:  RdpAudit.Core.Ipc.Contracts
// Purpose: IPC DTOs for the Tools Diag tab. ToolProbeResultDto captures one external-command probe with
//          full runner metadata (tool name, resolved executable, arguments, runner mode, working dir,
//          exit code, duration, timed-out flag, stdout / stderr previews, detected locale hint and a
//          pass/fail verdict). ToolsDiagnosticsDto bundles the probe set plus a single-block report text
//          the operator can copy / save. The temporary-firewall-rule probe reuses ToolProbeResultDto for
//          each of its create / verify / cleanup steps and reports the rule name, handle and backend.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using MessagePack;

namespace RdpAudit.Core.Ipc.Contracts;

/// <summary>One external-command probe with full runner metadata for the Tools Diag tab.</summary>
[MessagePackObject(keyAsPropertyName: false)]
public sealed class ToolProbeResultDto
{
	/// <summary>Operator-facing tool name (e.g. "qwinsta", "netsh show allprofiles").</summary>
	[Key(0)]
	public string ToolName { get; set; } = string.Empty;

	/// <summary>Resolved executable that ran (e.g. "cmd.exe", "netsh.exe", "powershell.exe").</summary>
	[Key(1)]
	public string Executable { get; set; } = string.Empty;

	/// <summary>Argument line that was passed to the executable.</summary>
	[Key(2)]
	public string Arguments { get; set; } = string.Empty;

	/// <summary>Runner mode used to spawn the command (EnglishConsole / Direct / PowerShellJson / Raw / ...).</summary>
	[Key(3)]
	public string RunnerMode { get; set; } = string.Empty;

	/// <summary>Working directory of the spawned process (empty when the process default was used).</summary>
	[Key(4)]
	public string WorkingDirectory { get; set; } = string.Empty;

	/// <summary>Process exit code; -1 when the process could not be started or timed out.</summary>
	[Key(5)]
	public int ExitCode { get; set; }

	/// <summary>Wall-clock duration in milliseconds.</summary>
	[Key(6)]
	public long DurationMs { get; set; }

	/// <summary>True when the hard timeout fired and the process was killed.</summary>
	[Key(7)]
	public bool TimedOut { get; set; }

	/// <summary>Bounded, control-character-flattened stdout preview.</summary>
	[Key(8)]
	public string StdoutPreview { get; set; } = string.Empty;

	/// <summary>Bounded, control-character-flattened stderr preview.</summary>
	[Key(9)]
	public string StderrPreview { get; set; } = string.Empty;

	/// <summary>Detected language / locale hint inferred from the output, when practical (e.g. "non-ASCII
	/// characters present in output" / "ASCII-only"). Empty when not assessed.</summary>
	[Key(10)]
	public string LocaleHint { get; set; } = string.Empty;

	/// <summary>True when the probe is considered to have passed (exit 0 and not timed out).</summary>
	[Key(11)]
	public bool Passed { get; set; }

	/// <summary>Optional note explaining the verdict or a skipped probe (e.g. "skipped on non-Windows host").</summary>
	[Key(12)]
	public string? Note { get; set; }
}

/// <summary>Aggregate result for the Tools Diag tab: the probe set plus a copyable / savable report block.</summary>
[MessagePackObject(keyAsPropertyName: false)]
public sealed class ToolsDiagnosticsDto
{
	[Key(0)]
	public IpcResultStatus Status { get; set; } = IpcResultStatus.Success;

	[Key(1)]
	public DateTime GeneratedUtc { get; set; }

	/// <summary>Per-tool probe results in execution order.</summary>
	[Key(2)]
	public List<ToolProbeResultDto> Probes { get; set; } = new();

	/// <summary>Single-block, copy/save-ready transcript of every probe; never contains secret material.</summary>
	[Key(3)]
	public string ReportText { get; set; } = string.Empty;

	[Key(4)]
	public string? Message { get; set; }
}

/// <summary>Result of the explicit temporary-firewall-rule probe: the create / verify / cleanup steps
/// plus the rule name, backend rule handle, scanner backend and an overall verdict.</summary>
[MessagePackObject(keyAsPropertyName: false)]
public sealed class TemporaryFirewallProbeDto
{
	[Key(0)]
	public IpcResultStatus Status { get; set; } = IpcResultStatus.Success;

	[Key(1)]
	public DateTime GeneratedUtc { get; set; }

	/// <summary>The test IP that was used for the probe.</summary>
	[Key(2)]
	public string TestIp { get; set; } = string.Empty;

	/// <summary>Deterministic rule name used for the temporary probe rule.</summary>
	[Key(3)]
	public string RuleName { get; set; } = string.Empty;

	/// <summary>Backend rule handle of the created rule, when the backend assigned one.</summary>
	[Key(4)]
	public string? RuleHandle { get; set; }

	/// <summary>Scanner / runner backend used (e.g. NetshText, PowerShellJson).</summary>
	[Key(5)]
	public string? ScannerBackend { get; set; }

	/// <summary>True when the rule was created, verified present, and then cleaned up successfully.</summary>
	[Key(6)]
	public bool CreatedVerifiedAndCleanedUp { get; set; }

	/// <summary>The create / verify / cleanup steps in execution order.</summary>
	[Key(7)]
	public List<ToolProbeResultDto> Steps { get; set; } = new();

	/// <summary>Single-block, copy/save-ready transcript of the probe.</summary>
	[Key(8)]
	public string ReportText { get; set; } = string.Empty;

	[Key(9)]
	public string? Message { get; set; }
}
