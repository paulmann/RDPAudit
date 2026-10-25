// File:    src/RdpAudit.Core/Ipc/Contracts/AlertsForIpRequest.cs
// Module:  RdpAudit.Core.Ipc.Contracts
// Purpose: Request payload for GetAlertsForIp. Identifies a single IP whose correlated alerts the
//          Configurator wants to export to a SIEM, with an optional bounded row cap.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using MessagePack;

namespace RdpAudit.Core.Ipc.Contracts;

/// <summary>Request payload for <c>GetAlertsForIp</c>.</summary>
[MessagePackObject(keyAsPropertyName: false)]
public sealed class AlertsForIpRequest
{
	/// <summary>Target IP literal (IPv4 / IPv6); validated server-side via <c>IPAddress.TryParse</c>.</summary>
	[Key(0)]
	public string Ip { get; set; } = string.Empty;

	/// <summary>Maximum number of alerts to return. Zero falls back to the server default; the server clamps to a hard ceiling.</summary>
	[Key(1)]
	public int Limit { get; set; }
}
