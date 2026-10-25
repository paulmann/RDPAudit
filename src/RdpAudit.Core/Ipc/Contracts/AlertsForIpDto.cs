// File:    src/RdpAudit.Core/Ipc/Contracts/AlertsForIpDto.cs
// Module:  RdpAudit.Core.Ipc.Contracts
// Purpose: Response payload for GetAlertsForIp. Carries the bounded correlated-alert window for
//          one IP plus a total counter so the Configurator can label the SIEM export honestly.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using MessagePack;

namespace RdpAudit.Core.Ipc.Contracts;

/// <summary>Response payload for <c>GetAlertsForIp</c>.</summary>
[MessagePackObject(keyAsPropertyName: false)]
public sealed class AlertsForIpDto
{
	/// <summary>Controlled-result status.</summary>
	[Key(0)]
	public IpcResultStatus Status { get; set; } = IpcResultStatus.Success;

	/// <summary>Canonical IP literal echoed from the request.</summary>
	[Key(1)]
	public string Ip { get; set; } = string.Empty;

	/// <summary>UTC timestamp of the query that produced this snapshot.</summary>
	[Key(2)]
	public DateTime QueriedUtc { get; set; }

	/// <summary>Total correlated alerts stored for this IP across the full history.</summary>
	[Key(3)]
	public long TotalAlerts { get; set; }

	/// <summary>Bounded alert window, newest first; cap defined by the server (default 200).</summary>
	[Key(4)]
	public List<AlertEntryDto> Alerts { get; set; } = new();

	/// <summary>Operator-facing message; never carries secret material.</summary>
	[Key(5)]
	public string? Message { get; set; }
}
