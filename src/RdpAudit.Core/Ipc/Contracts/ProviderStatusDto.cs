// File:    src/RdpAudit.Core/Ipc/Contracts/ProviderStatusDto.cs
// Module:  RdpAudit.Core.Ipc.Contracts
// Purpose: DTO returned by GetAbuseIpDbStatus / GetMikroTikStatus describing provider readiness.
//          Never carries plaintext secret material.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using MessagePack;

namespace RdpAudit.Core.Ipc.Contracts;

/// <summary>DTO returned by external-provider status IPC commands.</summary>
[MessagePackObject(keyAsPropertyName: false)]
public sealed class ProviderStatusDto
{
	[Key(0)]
	public IpcResultStatus Status { get; set; } = IpcResultStatus.Success;

	[Key(1)]
	public bool Enabled { get; set; }

	[Key(2)]
	public bool Configured { get; set; }

	/// <summary>True when the credential surface (envelope) is present, regardless of its validity.</summary>
	[Key(3)]
	public bool CredentialPresent { get; set; }

	[Key(4)]
	public DateTime? LastCheckedUtc { get; set; }

	[Key(5)]
	public string? Message { get; set; }
}
