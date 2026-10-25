/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// File   : ZabbixTestResultDto.cs
// Project: RdpAudit.Core (RdpAudit.Core.Ipc.Contracts)
// Purpose: Result of the connection test. The sender port and the API are probed separately, because
//          they fail for different reasons and only one of them is needed by the push worker.
// Extends: System.Object

using MessagePack;

namespace RdpAudit.Core.Ipc.Contracts;

/// <summary>Outcome of a Zabbix connection test.</summary>
/// <remarks>MessagePack keys are append-only: add new members at the end with the next free key.</remarks>
[MessagePackObject(keyAsPropertyName: false)]
public sealed class ZabbixTestResultDto
{
	/// <summary>Outcome discriminator: Success only when every probe that was attempted succeeded.</summary>
	[Key(0)]
	public IpcResultStatus Status { get; set; } = IpcResultStatus.Success;

	/// <summary>True when the trapper port accepted a TCP connection.</summary>
	[Key(1)]
	public bool SenderReachable { get; set; }

	/// <summary>Detail for the sender probe.</summary>
	[Key(2)]
	public string SenderMessage { get; set; } = string.Empty;

	/// <summary>True when the JSON-RPC API answered a version request.</summary>
	[Key(3)]
	public bool ApiReachable { get; set; }

	/// <summary>Version string reported by the API, empty when unreachable.</summary>
	[Key(4)]
	public string ApiVersion { get; set; } = string.Empty;

	/// <summary>True when authentication against the API succeeded.</summary>
	[Key(5)]
	public bool CredentialValid { get; set; }

	/// <summary>Operator-facing summary; never contains a credential.</summary>
	[Key(6)]
	public string Message { get; set; } = string.Empty;

	/// <summary>Wall-clock duration of the whole test.</summary>
	[Key(7)]
	public int ElapsedMilliseconds { get; set; }

	/// <summary>API endpoint that was probed.</summary>
	[Key(8)]
	public string ApiEndpoint { get; set; } = string.Empty;

	/// <summary>Technical host name that would be used by the next push.</summary>
	[Key(9)]
	public string HostName { get; set; } = string.Empty;
}
