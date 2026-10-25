/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// File   : ZabbixPushResultDto.cs
// Project: RdpAudit.Core (RdpAudit.Core.Ipc.Contracts)
// Purpose: Result of one push cycle, whether it was triggered by the worker or by the Push now button.
//          "Accepted 7 of 7" and "server rejected 7 of 7" must never look the same.
// Extends: System.Object

using MessagePack;

namespace RdpAudit.Core.Ipc.Contracts;

/// <summary>Outcome of one push cycle.</summary>
/// <remarks>MessagePack keys are append-only: add new members at the end with the next free key.</remarks>
[MessagePackObject(keyAsPropertyName: false)]
public sealed class ZabbixPushResultDto
{
	/// <summary>Outcome discriminator.</summary>
	[Key(0)]
	public IpcResultStatus Status { get; set; } = IpcResultStatus.Success;

	/// <summary>True when the server accepted every value of the batch.</summary>
	[Key(1)]
	public bool Delivered { get; set; }

	/// <summary>Values the server accepted.</summary>
	[Key(2)]
	public int Processed { get; set; }

	/// <summary>Values the server rejected.</summary>
	[Key(3)]
	public int Failed { get; set; }

	/// <summary>Values in the batch.</summary>
	[Key(4)]
	public int Total { get; set; }

	/// <summary>Incidents carried by the batch.</summary>
	[Key(5)]
	public int IncidentsInBatch { get; set; }

	/// <summary>Incidents discarded by the backlog cap before this batch.</summary>
	[Key(6)]
	public int Skipped { get; set; }

	/// <summary>Operator-facing message.</summary>
	[Key(7)]
	public string Message { get; set; } = string.Empty;

	/// <summary>Moment of the attempt (UTC).</summary>
	[Key(8)]
	public DateTime PushedUtc { get; set; }

	/// <summary>Highest Zabbix severity in the batch, 0 when the batch carried no incident.</summary>
	[Key(9)]
	public int MaxSeverity { get; set; }

	/// <summary>Sequence number of this batch.</summary>
	[Key(10)]
	public long Sequence { get; set; }
}
