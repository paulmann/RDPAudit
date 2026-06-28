// File:    src/RdpAudit.Core/Ipc/Contracts/FirewallDiagnosticsDto.cs
// Module:  RdpAudit.Core.Ipc.Contracts
// Purpose: DTO returned by GetFirewallDiagnostics carrying the pre-rendered firewall enforcement
//          diagnostics report (provider/backend/scope, resolved RDP port, RdpAudit group rules,
//          alternate backends, third-party interference, enforcement reconciliation). The report is
//          assembled service-side by FirewallDiagnosticsReportBuilder so the Configurator only has to
//          display it. Never contains secret material.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using MessagePack;

namespace RdpAudit.Core.Ipc.Contracts;

/// <summary>DTO returned by <c>GetFirewallDiagnostics</c> carrying the rendered firewall report.</summary>
[MessagePackObject(keyAsPropertyName: false)]
public sealed class FirewallDiagnosticsDto
{
	[Key(0)]
	public IpcResultStatus Status { get; set; } = IpcResultStatus.Success;

	/// <summary>The multi-line firewall diagnostics transcript; never contains secret material.</summary>
	[Key(1)]
	public string ReportText { get; set; } = string.Empty;

	/// <summary>Operator-facing message or error detail.</summary>
	[Key(2)]
	public string? Message { get; set; }
}
