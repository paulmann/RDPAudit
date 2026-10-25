// File:    src/RdpAudit.Core/Models/ProcessObservationRecord.cs
// Module:  RdpAudit.Core.Models
// Purpose: Append-only audit / debug journal of process observations (every 4688 event that
//          NewProcessRule evaluates, plus operator-forced ReportProcessObservation requests).
//          Backs diagnostics and the Configurator's process-monitoring alert list; bounded by
//          ProcessMonitoringOptions.MaxObservations with oldest-first deletion.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

namespace RdpAudit.Core.Models;

/// <summary>Bounded append-only journal row for one process observation.</summary>
public sealed class ProcessObservationRecord
{
	/// <summary>Surrogate primary key.</summary>
	public long Id { get; set; }

	/// <summary>UTC instant the observation was recorded.</summary>
	public DateTime ObservedUtc { get; set; }

	/// <summary>Exact lower-cased process filename.</summary>
	public string ProcessName { get; set; } = string.Empty;

	/// <summary>Normalized <c>Domain\User</c> identity; null for system observations.</summary>
	public string? UserName { get; set; }

	/// <summary>Windows Terminal Services session id, when known.</summary>
	public int? SessionId { get; set; }

	/// <summary>RawEvent.Id that triggered this observation; 0 for operator-forced reports.</summary>
	public long RawEventId { get; set; }

	/// <summary>True when the observation produced a PROCESS_NEW alert.</summary>
	public bool Alerted { get; set; }

	/// <summary>True when the observation was forced by an operator via ReportProcessObservation.</summary>
	public bool IsForced { get; set; }
}
