// File:    src/RdpAudit.Core/Models/KnownProcess.cs
// Module:  RdpAudit.Core.Models
// Purpose: Persistent baseline row for one observed process identity (ProcessName, UserCategory,
//          UserName). NewProcessRule consults this table to decide whether a 4688 process is
//          "new" (first-ever observation, or last observation older than the configured alert
//          window) and upserts First/LastObservedUtc + ObservationCount on every observation.
//          The baseline lives here - NOT derived from RawEvents - so the 365-day window of
//          KnownProcesses survives RawEvent retention pruning.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

namespace RdpAudit.Core.Models;

/// <summary>Persistent baseline row for one process identity.</summary>
public sealed class KnownProcess
{
	/// <summary>Surrogate primary key.</summary>
	public long Id { get; set; }

	/// <summary>Exact process filename, lower-cased and sanitised (no path segments).</summary>
	public string ProcessName { get; set; } = string.Empty;

	/// <summary>Ordinal of <see cref="RdpAudit.Core.ProcessMonitoring.ProcessUserCategory"/>.
	/// 0 = System (service / built-in account), 1 = Interactive user.</summary>
	public int UserCategory { get; set; }

	/// <summary>Normalized <c>Domain\User</c> identity for interactive processes; empty string for
	/// system processes. Stored as an empty string (never NULL) so the SQLite unique index over
	/// (ProcessName, UserCategory, UserName) also deduplicates system process identities (SQLite
	/// treats NULLs as distinct values in unique indexes).</summary>
	public string UserName { get; set; } = string.Empty;

	/// <summary>UTC instant of the first observation of this identity.</summary>
	public DateTime FirstObservedUtc { get; set; }

	/// <summary>UTC instant of the most recent observation of this identity.</summary>
	public DateTime LastObservedUtc { get; set; }

	/// <summary>Total number of observations recorded for this identity.</summary>
	public long ObservationCount { get; set; }

	/// <summary>RawEvent.Id of the triggering event that created this baseline row (UI deep link).</summary>
	public long FirstObservedProcessId { get; set; }
}
