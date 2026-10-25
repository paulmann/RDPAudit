// File:    src/RdpAudit.Core/Ipc/Contracts/SetProcessAutoCloseRequest.cs
// Module:  RdpAudit.Core.Ipc.Contracts
// Purpose: Request/response shapes for the SetProcessAutoClose IPC command (ordinal 76).
//          Arming the automated session close is append-only: once a ProcessAlertResponses row
//          exists for an alert it is never deleted, only transitioned to its final state by the
//          responder - so the UI checkbox reflects the persisted row rather than a boolean edge.
//          MessagePack keys are append-only.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using MessagePack;

namespace RdpAudit.Core.Ipc.Contracts;

/// <summary>Request payload for <c>SetProcessAutoClose</c>.</summary>
[MessagePackObject(keyAsPropertyName: false)]
public sealed class SetProcessAutoCloseRequest
{
	/// <summary>Alert row id of the PROCESS_NEW alert.</summary>
	[Key(0)]
	public long AlertId { get; set; }

	/// <summary>True arms the automated session close; false cancels a still-queued request.
	/// A response already in a final state cannot be re-queued or cancelled.</summary>
	[Key(1)]
	public bool Enabled { get; set; }

	/// <summary>Optional operator-provided reason text recorded in the audit log.</summary>
	[Key(2)]
	public string? Reason { get; set; }
}

/// <summary>Response payload for <c>SetProcessAutoClose</c>.</summary>
[MessagePackObject(keyAsPropertyName: false)]
public sealed class ProcessAutoCloseActionResult
{
	/// <summary>Outcome. NotFound when the alert id is unknown / not PROCESS_NEW;
	/// Refused when the requested state is disallowed (terminal state reached, no target
	/// session, or SessionControl.AllowLogoff off); InvalidRequest for malformed input.</summary>
	[Key(0)]
	public IpcResultStatus Status { get; set; } = IpcResultStatus.Success;

	/// <summary>The affected alert projection (with AutoCloseEnabled updated).</summary>
	[Key(1)]
	public ProcessAlertDto? Alert { get; set; }

	/// <summary>Persisted automated-response state after the change.</summary>
	[Key(2)]
	public ProcessAlertResponseDto? Response { get; set; }

	/// <summary>Operator-facing message; never carries secret material.</summary>
	[Key(3)]
	public string? Message { get; set; }
}
