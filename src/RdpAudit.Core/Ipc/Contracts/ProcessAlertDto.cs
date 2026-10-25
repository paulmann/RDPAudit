// File:    src/RdpAudit.Core/Ipc/Contracts/ProcessAlertDto.cs
// Module:  RdpAudit.Core.Ipc.Contracts
// Purpose: Typed projection of one PROCESS_NEW alert returned by the process-monitoring IPC
//          commands (ReportProcessObservation / ListProcessAlerts / GetProcessAlertDetails /
//          SetProcessAutoClose). Carries the alert's process identity (ProcessName, UserName),
//          the baseline window it was flagged against, the optional target session and the
//          auto-close state. It deliberately omits the raw Details JSON - that stays behind
//          the dedicated GetProcessAlertDetails command, so list responses never leak raw
//          forensic detail. MessagePack keys are append-only.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using MessagePack;
using RdpAudit.Core.Models;

namespace RdpAudit.Core.Ipc.Contracts;

/// <summary>Projection of one PROCESS_NEW alert for the Configurator's alert list.</summary>
[MessagePackObject(keyAsPropertyName: false)]
public sealed class ProcessAlertDto
{
	/// <summary>Alert row id (stable external identifier).</summary>
	[Key(0)]
	public long Id { get; set; }

	/// <summary>Alert rule id - always "PROCESS_NEW" for these projections.</summary>
	[Key(1)]
	public string RuleId { get; set; } = string.Empty;

	/// <summary>Alert severity classification (always High for PROCESS_NEW).</summary>
	[Key(2)]
	public AlertSeverity Severity { get; set; }

	/// <summary>UTC time the alert was raised.</summary>
	[Key(3)]
	public DateTime TimeUtc { get; set; }

	/// <summary>Correlated source IP; null when the alert carries no IP.</summary>
	[Key(4)]
	public string? SourceIp { get; set; }

	/// <summary>Process owner identity attached to the alert, when available.</summary>
	[Key(5)]
	public string? UserName { get; set; }

	/// <summary>Exact lower-cased process filename the alert was raised for.</summary>
	[Key(6)]
	public string ProcessName { get; set; } = string.Empty;

	/// <summary>Windows Terminal Services session id the process appeared in; null when unknown.</summary>
	[Key(7)]
	public int? SessionId { get; set; }

	/// <summary>UTC instant of the very first observation of this process identity.</summary>
	[Key(8)]
	public DateTime FirstObservedUtc { get; set; }

	/// <summary>Configured alert window (days) the identity was evaluated against.</summary>
	[Key(9)]
	public int AlertWindowDays { get; set; }

	/// <summary>True when an automated session-close response is armed for this alert.</summary>
	[Key(10)]
	public bool AutoCloseEnabled { get; set; }

	/// <summary>True when the alert has been acknowledged by an operator.</summary>
	[Key(11)]
	public bool Acknowledged { get; set; }
}
