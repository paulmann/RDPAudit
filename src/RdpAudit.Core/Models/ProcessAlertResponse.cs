// File:    src/RdpAudit.Core/Models/ProcessAlertResponse.cs
// Module:  RdpAudit.Core.Models
// Purpose: Persistent state of the automated session-close response attached to one PROCESS_NEW
//          alert. ProcessAlertAutoResponder polls rows in Queued status, performs exactly one
//          logoff attempt via the existing RdpSessionManager logoff pipeline, and records the
//          outcome (Completed / Failed). One row per alert (AlertId is the primary key) so a
//          completed response can never be queued again.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

namespace RdpAudit.Core.Models;

/// <summary>Persistent automated-response state for one PROCESS_NEW alert.</summary>
public sealed class ProcessAlertResponse
{
	/// <summary>Alert row id this response belongs to (primary key - one response per alert).</summary>
	public long AlertId { get; set; }

	/// <summary>Windows Terminal Services session id to log off; -1 when the alert carried no session.</summary>
	public int SessionId { get; set; } = -1;

	/// <summary>Ordinal of <see cref="RdpAudit.Core.ProcessMonitoring.ProcessAutoCloseStatus"/>:
	/// 0 = Queued, 1 = Completed, 2 = Failed.</summary>
	public int Status { get; set; }

	/// <summary>Operator-facing outcome text (diagnostic summary of the logoff attempt).</summary>
	public string? ResultText { get; set; }

	/// <summary>UTC instant when the response was queued.</summary>
	public DateTime RequestedAtUtc { get; set; }

	/// <summary>UTC instant when the attempt finished (success or failure); null while Queued.</summary>
	public DateTime? CompletedAtUtc { get; set; }
}
