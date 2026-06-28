// File:    src/RdpAudit.Core/Ipc/Contracts/EventsForIpRequest.cs
// Module:  RdpAudit.Core.Ipc.Contracts
// Purpose: Request payload for GetEventsForIp. Identifies a single IP whose RawEvents the
//          Configurator wants to export, with an optional bounded row cap.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using MessagePack;

namespace RdpAudit.Core.Ipc.Contracts;

/// <summary>Request payload for <c>GetEventsForIp</c>.</summary>
[MessagePackObject(keyAsPropertyName: false)]
public sealed class EventsForIpRequest
{
	/// <summary>Target IP literal (IPv4 / IPv6); validated server-side via <c>IPAddress.TryParse</c>.</summary>
	[Key(0)]
	public string Ip { get; set; } = string.Empty;

	/// <summary>Maximum number of RawEvents to return. Zero falls back to the server default; the server clamps to a hard ceiling.</summary>
	[Key(1)]
	public int Limit { get; set; }
}
