// File:    src/RdpAudit.Core/Ipc/Contracts/ProcessAlertDetailsDto.cs
// Module:  RdpAudit.Core.Ipc.Contracts
// Purpose: Request/response shapes for the GetProcessAlertDetails IPC command (ordinal 75).
//          Returns one PROCESS_NEW alert together with its raw Details JSON and the persisted
//          automated-response state, backing the Configurator's alert-details panel. Unlike the
//          list projection this response intentionally carries the forensic Details payload.
//          MessagePack keys are append-only.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using MessagePack;

namespace RdpAudit.Core.Ipc.Contracts;

/// <summary>Request payload for <c>GetProcessAlertDetails</c>.</summary>
[MessagePackObject(keyAsPropertyName: false)]
public sealed class GetProcessAlertDetailsRequest
{
	/// <summary>Alert row id of the PROCESS_NEW alert to load.</summary>
	[Key(0)]
	public long AlertId { get; set; }
}

/// <summary>Persistent state of the automated session-close response attached to one alert.</summary>
[MessagePackObject(keyAsPropertyName: false)]
public sealed class ProcessAlertResponseDto
{
	/// <summary>Ordinal of ProcessAutoCloseStatus: 0 = Queued, 1 = Completed, 2 = Failed.
	/// False when no response row exists for the alert.</summary>
	[Key(0)]
	public bool HasResponse { get; set; }

	/// <summary>Windows Terminal Services session id the response targets; -1 when absent.</summary>
	[Key(1)]
	public int SessionId { get; set; } = -1;

	/// <summary>ProcessAutoCloseStatus ordinal; 0 while queued.</summary>
	[Key(2)]
	public int Status { get; set; }

	/// <summary>Operator-facing outcome text, when the attempt has finished.</summary>
	[Key(3)]
	public string? ResultText { get; set; }

	/// <summary>UTC instant the response was queued.</summary>
	[Key(4)]
	public DateTime? RequestedAtUtc { get; set; }

	/// <summary>UTC instant the attempt finished; null while queued.</summary>
	[Key(5)]
	public DateTime? CompletedAtUtc { get; set; }
}

/// <summary>Response payload for <c>GetProcessAlertDetails</c>.</summary>
[MessagePackObject(keyAsPropertyName: false)]
public sealed class ProcessAlertDetailsDto
{
	/// <summary>Outcome of the query. NotFound when the alert id is unknown or not PROCESS_NEW.</summary>
	[Key(0)]
	public IpcResultStatus Status { get; set; } = IpcResultStatus.Success;

	/// <summary>Base alert projection; null when Status != Success.</summary>
	[Key(1)]
	public ProcessAlertDto? Alert { get; set; }

	/// <summary>Raw forensic Details JSON stored on the alert row (sanitised on creation).</summary>
	[Key(2)]
	public string? DetailsJson { get; set; }

	/// <summary>Persisted automated-response state, when one exists.</summary>
	[Key(3)]
	public ProcessAlertResponseDto? Response { get; set; }

	/// <summary>Operator-facing message; never carries secret material.</summary>
	[Key(4)]
	public string? Message { get; set; }
}
