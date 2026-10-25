// File:    src/RdpAudit.Core/Ipc/IpcResponse.cs
// Module:  RdpAudit.Core.Ipc
// Purpose: MessagePack-serialized response envelope returned by the Service to the Configurator.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using MessagePack;

namespace RdpAudit.Core.Ipc;

/// <summary>MessagePack-serialized response envelope.</summary>
[MessagePackObject(keyAsPropertyName: false)]
public sealed class IpcResponse
{
	[Key(0)]
	public bool Success { get; set; }

	[Key(1)]
	public string? Error { get; set; }

	[Key(2)]
	public string? Payload { get; set; }
}
