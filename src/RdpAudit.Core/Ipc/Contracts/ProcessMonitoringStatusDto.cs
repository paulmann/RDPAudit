// File:    src/RdpAudit.Core/Ipc/Contracts/ProcessMonitoringStatusDto.cs
// Module:  RdpAudit.Core.Ipc.Contracts
// Purpose: Response payload of the GetProcessMonitoringStatus IPC command (ordinal 77).
//          Reports the effective process-monitoring configuration (baseline windows, alert
//          window, auto-close default) and the subsystem's persisted statistics for the
//          Configurator's Process Monitoring settings/status section. Informational only -
//          never performs a session operation and never exposes raw event detail.
//          MessagePack keys are append-only.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using MessagePack;

namespace RdpAudit.Core.Ipc.Contracts;

/// <summary>Response payload for <c>GetProcessMonitoringStatus</c>.</summary>
[MessagePackObject(keyAsPropertyName: false)]
public sealed class ProcessMonitoringStatusDto
{
	/// <summary>Outcome of the query; Success even when the feature is disabled.</summary>
	[Key(0)]
	public IpcResultStatus Status { get; set; } = IpcResultStatus.Success;

	/// <summary>True when the process-monitoring feature master switch is on.</summary>
	[Key(1)]
	public bool Enabled { get; set; }

	/// <summary>Effective baseline look-back windows in days (sorted, distinct, 1..365).</summary>
	[Key(2)]
	public List<int> BaselineWindowsDays { get; set; } = new();

	/// <summary>Effective alert window (days) used for the "new process" decision.</summary>
	[Key(3)]
	public int AlertWindowDays { get; set; }

	/// <summary>Global default for arming automated session close on new alerts.</summary>
	[Key(4)]
	public bool AutoCloseSessionDefault { get; set; }

	/// <summary>True when system-account processes may raise PROCESS_NEW alerts.</summary>
	[Key(5)]
	public bool EnableAlertOnSystemProcesses { get; set; }

	/// <summary>Total rows in the KnownProcesses baseline table.</summary>
	[Key(6)]
	public long KnownProcessCount { get; set; }

	/// <summary>PROCESS_NEW alerts raised since the service started.</summary>
	[Key(7)]
	public long AlertsSinceStart { get; set; }

	/// <summary>Automated session-close requests currently waiting in the queue.</summary>
	[Key(8)]
	public int AutoCloseLogoffPending { get; set; }

	/// <summary>Automated session-close requests that completed successfully.</summary>
	[Key(9)]
	public int AutoCloseLogoffCompleted { get; set; }

	/// <summary>Automated session-close requests that failed or were refused.</summary>
	[Key(10)]
	public int AutoCloseLogoffFailed { get; set; }

	/// <summary>UTC instant of the most recent completed automated close; null when none.</summary>
	[Key(11)]
	public DateTime? LastAutoCloseUtc { get; set; }

	/// <summary>Rows currently retained in the ProcessObservations journal.</summary>
	[Key(12)]
	public long ObservationCount { get; set; }

	/// <summary>Operator-facing message; never carries secret material.</summary>
	[Key(13)]
	public string? Message { get; set; }
}
