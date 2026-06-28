// File:    src/RdpAudit.Core/Models/OperationLog.cs
// Module:  RdpAudit.Core.Models
// Purpose: Durable record of an action the program performed — bans, firewall add/remove, registry /
//          policy changes, service install / start / stop / repair, settings changes, cleanup,
//          diagnostics runs, IPC command outcomes, background-job progress and failures, purge /
//          maintenance. This is deliberately SEPARATE from the security / attack event log
//          (RawEvent / Alert): it is the operator-facing audit trail of what RdpAudit itself did,
//          surfaced concisely in normal mode and with full detail (exception type / message / stack
//          and a free-form details JSON) when DEBUG mode is enabled.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

namespace RdpAudit.Core.Models;

/// <summary>Durable record of an action the program performed (not a security attack event).</summary>
public sealed class OperationLog
{
	public long Id { get; set; }

	/// <summary>When the action occurred. Always UTC.</summary>
	public DateTime TimeUtc { get; set; }

	/// <summary>Severity of the entry.</summary>
	public OperationLogSeverity Severity { get; set; }

	/// <summary>Logical subsystem that produced the entry (e.g. "Ipc", "Firewall", "Maintenance",
	/// "Service", "Settings", "Backfill").</summary>
	public string Source { get; set; } = string.Empty;

	/// <summary>Short operation identifier within the source (e.g. "ClearAllBlocklist",
	/// "ServiceStartup", "BanInstalled").</summary>
	public string Operation { get; set; } = string.Empty;

	/// <summary>Human-readable, concise one-line summary shown in normal mode.</summary>
	public string Message { get; set; } = string.Empty;

	/// <summary>Optional structured details (JSON). Surfaced only in DEBUG mode.</summary>
	public string? DetailsJson { get; set; }

	/// <summary>Optional exception type name when the entry records a failure.</summary>
	public string? ExceptionType { get; set; }

	/// <summary>Optional exception message when the entry records a failure.</summary>
	public string? ExceptionMessage { get; set; }

	/// <summary>Optional stack trace. Populated only when DEBUG mode is enabled to avoid storing
	/// large traces on every failure in normal operation.</summary>
	public string? StackTrace { get; set; }

	/// <summary>Optional correlation id linking related entries (e.g. one IPC command's start /
	/// success / failure entries, or one background-job run).</summary>
	public string? CorrelationId { get; set; }

	/// <summary>Optional duration of the operation in milliseconds.</summary>
	public long? DurationMs { get; set; }

	/// <summary>True when this entry was written while DEBUG mode was enabled. Lets the Logs tab
	/// reason about whether detail fields are expected to be present.</summary>
	public bool IsDebug { get; set; }

	/// <summary>Optional actor / principal context (e.g. the service account or the originating IPC
	/// command name) for the action.</summary>
	public string? Actor { get; set; }
}
