// File:    src/RdpAudit.Core/Data/IOperationLogWriter.cs
// Module:  RdpAudit.Core.Data
// Purpose: Abstraction for writing durable operation-log entries (program actions, not security
//          attack events) from anywhere in the service — IPC handlers, background workers, firewall
//          and settings code, maintenance and purge paths — without creating a dependency cycle.
//          Implementations MUST be best-effort: a logging failure must never propagate to or crash
//          the caller. Detail fields (stack trace, details JSON) are persisted only when DEBUG mode
//          is enabled so normal operation stays compact.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com
// Version: 1.4.1

using RdpAudit.Core.Models;

namespace RdpAudit.Core.Data;

/// <summary>Writes durable operation-log entries. Best-effort: never throws to the caller.</summary>
public interface IOperationLogWriter
{
	/// <summary>Persists a single operation-log entry. Swallows and self-logs any failure so the
	/// calling action is never disrupted by a logging problem.</summary>
	Task WriteAsync(OperationLogEntry entry, CancellationToken ct = default);

	/// <summary>Convenience overload for a concise informational entry.</summary>
	Task InfoAsync(string source, string operation, string message, CancellationToken ct = default);

	/// <summary>Convenience overload for a warning entry with optional structured details.</summary>
	Task WarnAsync(string source, string operation, string message, string? detailsJson = null, CancellationToken ct = default);

	/// <summary>Convenience overload for a failure entry carrying an exception. Stack trace is
	/// stored only when DEBUG mode is enabled.</summary>
	Task ErrorAsync(string source, string operation, string message, Exception? exception, OperationLogSeverity severity = OperationLogSeverity.Error, CancellationToken ct = default);

	/// <summary>
	/// Verbose DEBUG-only trace. Writes an Information-severity entry (flagged IsDebug, so it is hidden
	/// from the default Logs view and surfaced only when the operator turns DEBUG mode on) ONLY when
	/// DEBUG mode is currently enabled; otherwise it is a cheap no-op that allocates nothing. Use this
	/// liberally to record the full "what and why" of an operation — inputs, intermediate decisions,
	/// and outcomes — without bloating the log in normal operation. The optional <paramref name="detailsBuilder"/>
	/// is invoked lazily only when DEBUG is on, so building an expensive details payload costs nothing
	/// in normal mode.
	/// </summary>
	Task DebugAsync(string source, string operation, string message, Func<string?>? detailsBuilder = null, string? correlationId = null, CancellationToken ct = default);

	/// <summary>True when DEBUG mode is currently enabled. Callers can gate the construction of
	/// expensive diagnostic strings on this without invoking <see cref="DebugAsync"/>.</summary>
	bool IsDebugEnabled { get; }
}

/// <summary>Immutable payload describing one operation-log entry to persist. The writer fills in
/// <see cref="OperationLog.TimeUtc"/> and the DEBUG-gating of detail fields.</summary>
public sealed record OperationLogEntry
{
	public required OperationLogSeverity Severity { get; init; }

	public required string Source { get; init; }

	public required string Operation { get; init; }

	public required string Message { get; init; }

	public string? DetailsJson { get; init; }

	public Exception? Exception { get; init; }

	public string? CorrelationId { get; init; }

	public long? DurationMs { get; init; }

	public string? Actor { get; init; }
}
