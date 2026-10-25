/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// File   : ZabbixProvisionResultDto.cs
// Project: RdpAudit.Core (RdpAudit.Core.Ipc.Contracts)
// Purpose: What the provisioning call actually created and what already existed. Separate counters,
//          because "nothing created" is the normal outcome of a second run and must not read as a
//          failure.
// Extends: System.Object

using MessagePack;

namespace RdpAudit.Core.Ipc.Contracts;

/// <summary>Outcome of provisioning the host, its items and its triggers in Zabbix.</summary>
/// <remarks>MessagePack keys are append-only: add new members at the end with the next free key.</remarks>
[MessagePackObject(keyAsPropertyName: false)]
public sealed class ZabbixProvisionResultDto
{
	/// <summary>Outcome discriminator.</summary>
	[Key(0)]
	public IpcResultStatus Status { get; set; } = IpcResultStatus.Success;

	/// <summary>True when the host group was created by this call.</summary>
	[Key(1)]
	public bool GroupCreated { get; set; }

	/// <summary>True when the host group already existed.</summary>
	[Key(2)]
	public bool GroupExisted { get; set; }

	/// <summary>True when the host was created by this call.</summary>
	[Key(3)]
	public bool HostCreated { get; set; }

	/// <summary>True when the host already existed.</summary>
	[Key(4)]
	public bool HostExisted { get; set; }

	/// <summary>Number of items created by this call.</summary>
	[Key(5)]
	public int ItemsCreated { get; set; }

	/// <summary>Number of items that already existed.</summary>
	[Key(6)]
	public int ItemsExisted { get; set; }

	/// <summary>Number of triggers created by this call.</summary>
	[Key(7)]
	public int TriggersCreated { get; set; }

	/// <summary>Number of triggers that already existed.</summary>
	[Key(8)]
	public int TriggersExisted { get; set; }

	/// <summary>True when the shared dashboard was created by this call.</summary>
	[Key(9)]
	public bool DashboardCreated { get; set; }

	/// <summary>True when the shared dashboard already existed.</summary>
	[Key(10)]
	public bool DashboardExisted { get; set; }

	/// <summary>Problems URL filtered to this integration: the single window across all machines.</summary>
	[Key(11)]
	public string ProblemsUrl { get; set; } = string.Empty;

	/// <summary>Operator-facing summary; never contains a credential.</summary>
	[Key(12)]
	public string Message { get; set; } = string.Empty;

	/// <summary>Frontend origin, so the tab can open the Problems view in a browser.</summary>
	[Key(13)]
	public string FrontendUrl { get; set; } = string.Empty;

	/// <summary>Items whose allowed-hosts list had to be widened during this call.</summary>
	[Key(14)]
	public int ItemsUpdated { get; set; }
}
