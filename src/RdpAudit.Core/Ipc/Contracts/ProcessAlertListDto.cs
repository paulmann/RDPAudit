// File:    src/RdpAudit.Core/Ipc/Contracts/ProcessAlertListDto.cs
// Module:  RdpAudit.Core.Ipc.Contracts
// Purpose: Response payload of the ListProcessAlerts IPC command (ordinal 74). Returns the
//          bounded, newest-first list of PROCESS_NEW alert projections for the Configurator's
//          process-monitoring alert panel. Deliberately omits raw Details JSON - that stays
//          behind the dedicated GetProcessAlertDetails command. MessagePack keys are append-only.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using MessagePack;

namespace RdpAudit.Core.Ipc.Contracts;

/// <summary>Request payload for <c>ListProcessAlerts</c>.</summary>
[MessagePackObject(keyAsPropertyName: false)]
public sealed class ListProcessAlertsRequest
{
	/// <summary>Maximum rows to return; 0 means the service default. Clamped to 1..500 server-side.</summary>
	[Key(0)]
	public int Limit { get; set; }
}

/// <summary>Response payload for <c>ListProcessAlerts</c>.</summary>
[MessagePackObject(keyAsPropertyName: false)]
public sealed class ProcessAlertListDto
{
	/// <summary>Outcome of the query; Success even when the result is empty.</summary>
	[Key(0)]
	public IpcResultStatus Status { get; set; } = IpcResultStatus.Success;

	/// <summary>Total PROCESS_NEW alert rows that matched, before the limit.</summary>
	[Key(1)]
	public int Total { get; set; }

	/// <summary>Newest-first alert projections (bounded by the applied limit).</summary>
	[Key(2)]
	public List<ProcessAlertDto> Items { get; set; } = new();

	/// <summary>Operator-facing message; never carries secret material.</summary>
	[Key(3)]
	public string? Message { get; set; }
}
