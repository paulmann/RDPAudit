// File:    src/RdpAudit.Core/Ipc/IpcRequest.cs
// Module:  RdpAudit.Core.Ipc
// Purpose: MessagePack-serialized request envelope sent from Configurator to Service.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using MessagePack;

namespace RdpAudit.Core.Ipc;

/// <summary>MessagePack-serialized request envelope.</summary>
[MessagePackObject(keyAsPropertyName: false)]
public sealed class IpcRequest
{
	[Key(0)]
	public IpcCommand Command { get; set; }

	[Key(1)]
	public string? Payload { get; set; }
}
