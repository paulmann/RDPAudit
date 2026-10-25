// File:    src/RdpAudit.Core/Ipc/Contracts/SessionActionResult.cs
// Module:  RdpAudit.Core.Ipc.Contracts
// Purpose: DTO returned by session-control IPC commands with a stable status discriminator and
//          a human-readable operator-facing message.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using MessagePack;

namespace RdpAudit.Core.Ipc.Contracts;

/// <summary>DTO returned by session-control IPC commands.</summary>
[MessagePackObject(keyAsPropertyName: false)]
public sealed class SessionActionResult
{
	[Key(0)]
	public IpcResultStatus Status { get; set; } = IpcResultStatus.Success;

	[Key(1)]
	public int SessionId { get; set; }

	[Key(2)]
	public string? Message { get; set; }
}
