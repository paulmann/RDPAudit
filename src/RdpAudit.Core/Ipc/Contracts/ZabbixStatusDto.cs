/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// File   : ZabbixStatusDto.cs
// Project: RdpAudit.Core (RdpAudit.Core.Ipc.Contracts)
// Purpose: State of the push pipeline as the Zabbix tab renders it: last attempt, last success, the
//          sequence number, the backlog and the incidents carried by the last accepted batch.
// Extends: System.Object

using MessagePack;

namespace RdpAudit.Core.Ipc.Contracts;

/// <summary>Status of the Zabbix push pipeline.</summary>
/// <remarks>MessagePack keys are append-only: add new members at the end with the next free key.</remarks>
[MessagePackObject(keyAsPropertyName: false)]
public sealed class ZabbixStatusDto
{
	/// <summary>Outcome discriminator for the status read itself.</summary>
	[Key(0)]
	public IpcResultStatus Status { get; set; } = IpcResultStatus.Success;

	/// <summary>True when the push worker is enabled.</summary>
	[Key(1)]
	public bool Enabled { get; set; }

	/// <summary>Technical host name in use.</summary>
	[Key(2)]
	public string HostName { get; set; } = string.Empty;

	/// <summary>Server and port the sender talks to, formatted for display.</summary>
	[Key(3)]
	public string Endpoint { get; set; } = string.Empty;

	/// <summary>Moment of the last push attempt, successful or not (UTC).</summary>
	[Key(4)]
	public DateTime? LastPushUtc { get; set; }

	/// <summary>Moment of the last push the server accepted (UTC).</summary>
	[Key(5)]
	public DateTime? LastSuccessUtc { get; set; }

	/// <summary>Monotonic counter of the last attempted batch.</summary>
	[Key(6)]
	public long Sequence { get; set; }

	/// <summary>Consecutive failed attempts since the last success.</summary>
	[Key(7)]
	public int ConsecutiveFailures { get; set; }

	/// <summary>Values accepted across the machine's lifetime of this state file.</summary>
	[Key(8)]
	public long ValuesSent { get; set; }

	/// <summary>Values rejected across the machine's lifetime of this state file.</summary>
	[Key(9)]
	public long ValuesFailed { get; set; }

	/// <summary>Last failure text; empty when the last attempt succeeded.</summary>
	[Key(10)]
	public string LastError { get; set; } = string.Empty;

	/// <summary>Incidents still waiting to be pushed (newer than the acknowledged alert id).</summary>
	[Key(11)]
	public int PendingBacklog { get; set; }

	/// <summary>Incidents carried by the last accepted batch, newest first.</summary>
	[Key(12)]
	public List<ZabbixSentIncidentDto> RecentIncidents { get; set; } = new();

	/// <summary>Operator-facing summary line.</summary>
	[Key(13)]
	public string Message { get; set; } = string.Empty;

	/// <summary>Incidents discarded by the backlog cap over the lifetime of this state file.</summary>
	[Key(14)]
	public long IncidentsSkipped { get; set; }

	/// <summary>Moment the next automatic push is due (UTC), when the worker is enabled.</summary>
	[Key(15)]
	public DateTime? NextPushDueUtc { get; set; }

	/// <summary>Single-window Problems URL for the whole fleet.</summary>
	[Key(16)]
	public string ProblemsUrl { get; set; } = string.Empty;
}
