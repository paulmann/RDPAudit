/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// File   : ZabbixSentIncidentDto.cs
// Project: RdpAudit.Core (RdpAudit.Core.Ipc.Contracts)
// Purpose: One row of the "recently pushed incidents" list on the Zabbix tab.
// Extends: System.Object

using MessagePack;

namespace RdpAudit.Core.Ipc.Contracts;

/// <summary>An incident that was handed to the Zabbix sender.</summary>
/// <remarks>MessagePack keys are append-only: add new members at the end with the next free key.</remarks>
[MessagePackObject(keyAsPropertyName: false)]
public sealed class ZabbixSentIncidentDto
{
	/// <summary>Local alert identifier.</summary>
	[Key(0)]
	public long AlertId { get; set; }

	/// <summary>Moment the alert was raised (UTC).</summary>
	[Key(1)]
	public DateTime TimeUtc { get; set; }

	/// <summary>Alert rule identifier.</summary>
	[Key(2)]
	public string RuleId { get; set; } = string.Empty;

	/// <summary>Internal severity name.</summary>
	[Key(3)]
	public string Severity { get; set; } = string.Empty;

	/// <summary>Zabbix severity 1..5 derived from <see cref="Severity"/>.</summary>
	[Key(4)]
	public int ZabbixSeverity { get; set; }

	/// <summary>Attacker address, when the alert carries one.</summary>
	[Key(5)]
	public string SourceIp { get; set; } = string.Empty;

	/// <summary>Account involved, when known.</summary>
	[Key(6)]
	public string UserName { get; set; } = string.Empty;

	/// <summary>Operator-facing description.</summary>
	[Key(7)]
	public string Message { get; set; } = string.Empty;

	/// <summary>True when the address was correlated rather than read from the event.</summary>
	[Key(8)]
	public bool SourceIpDerived { get; set; }

	/// <summary>Moment the batch carrying this incident was accepted by the server (UTC).</summary>
	[Key(9)]
	public DateTime DeliveredUtc { get; set; }
}
