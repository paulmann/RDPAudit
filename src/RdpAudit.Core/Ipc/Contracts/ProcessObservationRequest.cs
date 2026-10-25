// File:    src/RdpAudit.Core/Ipc/Contracts/ProcessObservationRequest.cs
// Module:  RdpAudit.Core.Ipc.Contracts
// Purpose: Request/response shapes for the ReportProcessObservation IPC command (ordinal 73).
//          An operator (or a DEBUG-panel button) forces one process identity through the same
//          baseline evaluation NewProcessRule uses, records a bounded ProcessObservations row
//          and optionally arms the automated session close. MessagePack keys are append-only.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using MessagePack;

namespace RdpAudit.Core.Ipc.Contracts;

/// <summary>Request payload for <c>ReportProcessObservation</c>.</summary>
[MessagePackObject(keyAsPropertyName: false)]
public sealed class ProcessObservationRequest
{
	/// <summary>Process image name or path (any path segments are discarded server-side).</summary>
	[Key(0)]
	public string ProcessName { get; set; } = string.Empty;

	/// <summary>Process owner account (optionally Domain\User); blank means a system process.</summary>
	[Key(1)]
	public string? UserName { get; set; }

	/// <summary>Domain of the owner account; blank means no domain prefix.</summary>
	[Key(2)]
	public string? Domain { get; set; }

	/// <summary>Windows Terminal Services session id, when known; -1 means unknown.</summary>
	[Key(3)]
	public int SessionId { get; set; } = -1;

	/// <summary>When true, the response carries a queued automated session-close request.
	/// Always respects SessionControl.Enabled / AllowLogoff and the auto-close rate limit.</summary>
	[Key(4)]
	public bool AutoClose { get; set; }
}

/// <summary>Response payload for <c>ReportProcessObservation</c>.</summary>
[MessagePackObject(keyAsPropertyName: false)]
public sealed class ProcessObservationResult
{
	/// <summary>Outcome of the command. InvalidRequest when ProcessName is unusable or
	/// SessionId is invalid; Refused when the requested auto-close is disallowed by policy.</summary>
	[Key(0)]
	public IpcResultStatus Status { get; set; } = IpcResultStatus.Success;

	/// <summary>True when the identity already existed in the baseline before this observation.</summary>
	[Key(1)]
	public bool IsAlreadyKnown { get; set; }

	/// <summary>True when the identity is newer than the configured alert window.</summary>
	[Key(2)]
	public bool IsNew { get; set; }

	/// <summary>Id of the persisted ProcessObservations journal row.</summary>
	[Key(3)]
	public long RecordingId { get; set; }

	/// <summary>The PROCESS_NEW alert raised by this observation, when one was raised.</summary>
	[Key(4)]
	public ProcessAlertDto? Alert { get; set; }

	/// <summary>True when an automated session-close response was queued for the alert.</summary>
	[Key(5)]
	public bool AutoCloseQueued { get; set; }

	/// <summary>Operator-facing message; never carries secret material.</summary>
	[Key(6)]
	public string? Message { get; set; }
}
