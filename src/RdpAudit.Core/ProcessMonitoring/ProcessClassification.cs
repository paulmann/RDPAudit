// File:    src/RdpAudit.Core/ProcessMonitoring/ProcessClassification.cs
// Module:  RdpAudit.Core.ProcessMonitoring
// Purpose: Append-only classification enums for the process-monitoring feature: ProcessUserCategory
//          (system vs interactive user, persisted as int in KnownProcesses.UserCategory) and
//          ProcessAutoCloseStatus (persisted as int in ProcessAlertResponses.Status). Ordinals are
//          persisted to SQLite and must NEVER be reordered, reused, or renumbered.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

namespace RdpAudit.Core.ProcessMonitoring;

/// <summary>Append-only classification of who runs a process. Ordinals are persisted to SQLite.</summary>
public enum ProcessUserCategory
{
	/// <summary>System / service / built-in account (SYSTEM, LOCAL SERVICE, NETWORK SERVICE, machine accounts).</summary>
	System = 0,

	/// <summary>Interactive user (non-empty UserName / Domain that is not a system account).</summary>
	Interactive = 1,
}

/// <summary>Append-only lifecycle state of an automated session-close response. Ordinals are persisted to SQLite.</summary>
public enum ProcessAutoCloseStatus
{
	/// <summary>The response is waiting to be executed by ProcessAlertAutoResponder.</summary>
	Queued = 0,

	/// <summary>The logoff attempt completed (or the session no longer existed).</summary>
	Completed = 1,

	/// <summary>The logoff attempt failed or was refused by policy.</summary>
	Failed = 2,
}
