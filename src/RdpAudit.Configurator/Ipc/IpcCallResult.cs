// File:    src/RdpAudit.Configurator/Ipc/IpcCallResult.cs
// Module:  RdpAudit.Configurator.Ipc
// Purpose: Structured outcome of a single IPC round-trip. Replaces the historic "everything that is
//          not a payload collapses to null" behaviour that made the UI conflate a slow firewall
//          repair, a timed-out connect, a service-side command error and a genuinely stopped service
//          into one misleading "service not running" message. Carries command-level tracing fields
//          (command name, start, duration, timeout, pipe-connected, response-received, outcome,
//          error type / message) so the UI can render an honest, actionable status line.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System.Globalization;
using RdpAudit.Core.Ipc;

namespace RdpAudit.Configurator.Ipc;

/// <summary>Distinguishes the ways a single IPC round-trip can end. The UI maps each to a different,
/// honest message rather than the historic blanket "service not running".</summary>
public enum IpcCallOutcome
{
	/// <summary>Service responded with Success=true and a deserializable payload.</summary>
	Success = 0,

	/// <summary>Service responded with Success=true but no payload (a valid "nothing to return").</summary>
	SuccessNoPayload = 1,

	/// <summary>The named pipe could not be connected within the connect timeout — the service is
	/// most likely stopped or not installed.</summary>
	ConnectFailed = 2,

	/// <summary>The pipe connected but the service did not finish within the (per-command) deadline —
	/// the service is reachable but an operation is taking too long or is still in progress.</summary>
	Timeout = 3,

	/// <summary>The service responded with Success=false and a curated error string.</summary>
	ServiceError = 4,

	/// <summary>A transport / framing / deserialization error occurred mid-stream after connecting.</summary>
	TransportError = 5,
}

/// <summary>Structured result of one IPC round-trip, including the deserialized payload (when any) and
/// command-level tracing fields. Immutable; produced by <see cref="IpcClient.SendDetailedAsync{T}"/>.</summary>
/// <typeparam name="T">Expected payload type.</typeparam>
public sealed class IpcCallResult<T>
{
	public IpcCallResult(
		IpcCommand command,
		IpcCallOutcome outcome,
		T? value,
		string? error,
		string? errorType,
		DateTime startUtc,
		long durationMs,
		int timeoutMs,
		bool pipeConnected,
		bool responseReceived)
	{
		Command = command;
		Outcome = outcome;
		Value = value;
		Error = error;
		ErrorType = errorType;
		StartUtc = startUtc;
		DurationMs = durationMs;
		TimeoutMs = timeoutMs;
		PipeConnected = pipeConnected;
		ResponseReceived = responseReceived;
	}

	public IpcCommand Command { get; }

	public IpcCallOutcome Outcome { get; }

	public T? Value { get; }

	/// <summary>Curated error text (service-supplied or transport description); null on success.</summary>
	public string? Error { get; }

	/// <summary>Exception / category name for the failure (e.g. "TimeoutException"); null on success.</summary>
	public string? ErrorType { get; }

	public DateTime StartUtc { get; }

	public long DurationMs { get; }

	public int TimeoutMs { get; }

	/// <summary>True once <c>ConnectAsync</c> succeeded — distinguishes a stopped service from a slow one.</summary>
	public bool PipeConnected { get; }

	/// <summary>True once a complete response frame was read back from the service.</summary>
	public bool ResponseReceived { get; }

	/// <summary>True when the service handled the command (payload present or an explicit empty success).</summary>
	public bool IsSuccess => Outcome is IpcCallOutcome.Success or IpcCallOutcome.SuccessNoPayload;

	/// <summary>True when the service was reached but could not be confirmed to be down — i.e. the call
	/// connected, or failed for a reason other than a connect failure. Used to decide whether to keep
	/// last-known UI data (transient) versus blank it (service genuinely gone).</summary>
	public bool ServiceLikelyReachable => Outcome != IpcCallOutcome.ConnectFailed;

	/// <summary>Short, operator-facing reason for the outcome, suitable for a one-line status label.
	/// For richer, SCM-aware diagnostics use <c>ServiceReachabilityProbe</c>.</summary>
	public string Headline() => Outcome switch
	{
		IpcCallOutcome.Success or IpcCallOutcome.SuccessNoPayload => "OK",
		IpcCallOutcome.ConnectFailed => "service unreachable (pipe connect failed — service stopped or not installed)",
		IpcCallOutcome.Timeout => "service reachable but timed out (an operation may be in progress)",
		IpcCallOutcome.ServiceError => "service error: " + (Error ?? "(no detail)"),
		IpcCallOutcome.TransportError => "transport error: " + (Error ?? "(no detail)"),
		_ => "no result",
	};

	/// <summary>Compact one-line tracing summary suitable for a status label / diagnostics transcript.</summary>
	public string TraceLine => string.Format(
		CultureInfo.InvariantCulture,
		"cmd={0} outcome={1} connected={2} responded={3} duration={4}ms timeout={5}ms{6}",
		Command,
		Outcome,
		PipeConnected,
		ResponseReceived,
		DurationMs,
		TimeoutMs,
		string.IsNullOrEmpty(Error) ? string.Empty : " error=" + ErrorType + ": " + Error);
}
