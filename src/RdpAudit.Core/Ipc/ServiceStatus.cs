// File:    src/RdpAudit.Core/Ipc/ServiceStatus.cs
// Module:  RdpAudit.Core.Ipc
// Purpose: Snapshot of runtime service health, surfaced via the IPC GetStatus command.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

namespace RdpAudit.Core.Ipc;

/// <summary>Snapshot of runtime service health.</summary>
public sealed class ServiceStatus
{
	public string Version { get; set; } = string.Empty;

	public DateTime StartedUtc { get; set; }

	public TimeSpan Uptime { get; set; }

	public int ProcessId { get; set; }

	public long EventsCaptured { get; set; }

	public long EventsDropped { get; set; }

	public long AlertsRaised { get; set; }

	public int ActiveSessions { get; set; }

	public Dictionary<string, string> ChannelStatus { get; set; } = new();

	/// <summary>Cumulative count of Security 4625 (failed logon) events since service start.</summary>
	public long Security4625Count { get; set; }

	/// <summary>Cumulative count of Security 4624 (successful logon) events since service start.</summary>
	public long Security4624Count { get; set; }

	/// <summary>Cumulative count of Security 4648 (explicit credentials) events since service start.</summary>
	public long Security4648Count { get; set; }

	/// <summary>Cumulative count of RDP pre-authentication observations (TS-RCM 261, RdpCoreTS 131)
	/// that did not have a matching Security 4624/4625/4648 inside the correlation window.</summary>
	public long RdpCorePreAuthOrphans { get; set; }

	/// <summary>UTC timestamp of the most recent Security 4624/4625/4648 received, or null when none.</summary>
	public DateTime? LastSecurityEventUtc { get; set; }

	/// <summary>UTC timestamp of the most recent TS-RCM 261 / RdpCoreTS 131 received, or null when none.</summary>
	public DateTime? LastRdpCorePreAuthUtc { get; set; }

	/// <summary>Human-readable diagnostic emitted when pre-auth events accumulate without matching
	/// Security events. Null until the watchdog fires. Configurator surfaces this on the dashboard.</summary>
	public string? SecurityCorrelationDiagnostic { get; set; }

	// --- v3 telemetry surface (Detect_Attack_Strategy_v3.md acceptance criterion §17). ---

	/// <summary>True once the live Security EventLogWatcher has armed at least once.</summary>
	public bool SecurityWatcherEnabled { get; set; }

	/// <summary>Cumulative count of Security events received by the live watcher path.</summary>
	public long SecurityEventsRead { get; set; }

	/// <summary>Cumulative count of Security events that completed normalization.</summary>
	public long SecurityEventsNormalized { get; set; }

	/// <summary>Cumulative count of Security events rejected with an explicit reason.</summary>
	public long SecurityEventsRejected { get; set; }

	/// <summary>UTC of the most recent Security backfill poll completion.</summary>
	public DateTime? SecurityBackfillLastRunUtc { get; set; }

	/// <summary>Cumulative count of Security records read during backfill polls.</summary>
	public long SecurityBackfillRecordsRead { get; set; }

	/// <summary>Cumulative count of Security records forwarded by backfill.</summary>
	public long SecurityBackfillRecordsForwarded { get; set; }

	/// <summary>Cumulative count of Security records dropped as duplicates by backfill.</summary>
	public long SecurityBackfillRecordsDeduped { get; set; }

	/// <summary>Most recent error message from the Security channel (live or backfill).</summary>
	public string? LastSecurityChannelError { get; set; }

	/// <summary>Most recent rejection reason for a normalized Security event.</summary>
	public string? LastSecurityRejectReason { get; set; }

	/// <summary>Cumulative count of Security events rejected, paired with <see cref="LastSecurityRejectReason"/>.</summary>
	public long SecurityRejectReasonCount { get; set; }

	/// <summary>UTC of the most recent <c>AuthAttemptFact</c> row created.</summary>
	public DateTime? LastAuthAttemptFactCreatedUtc { get; set; }

	/// <summary>Cumulative count of <c>AuthAttemptFact</c> rows created since service start.</summary>
	public long AuthAttemptFactCreated { get; set; }

	/// <summary>Cumulative count of failed/denied <c>AuthAttemptFact</c> rows since service start.</summary>
	public long AuthAttemptFactFailed { get; set; }

	/// <summary>Cumulative count of succeeded <c>AuthAttemptFact</c> rows since service start.</summary>
	public long AuthAttemptFactSucceeded { get; set; }

	// --- Security-missing diagnostic flags (Detect_Attack_Strategy_v3.md §10 + Service tab Copy
	// diagnostics requirement D.3). Each flag names a single, actionable cause for "RDP touched
	// the box but no Security 4624/4625/4771/4776 was correlated to it". The flags are derived
	// from the existing metrics + channel status map so they never disagree with the
	// SecurityCorrelationDiagnostic free-text string. ---

	/// <summary>True when the most recent backfill or live-watcher attempt against the Security
	/// channel reported ChannelNotFound / channel-unavailable.</summary>
	public bool SecurityLogMissing { get; set; }

	/// <summary>True when pre-auth events have arrived without any matching Security
	/// 4624/4625/4648 since service start — the canonical "audit-logon-success/failure policy
	/// is disabled" symptom.</summary>
	public bool AuditPolicyMissingLogon { get; set; }

	/// <summary>True when the most recent Security read attempt failed with AccessDenied —
	/// the service account is missing SeSecurityPrivilege / Event Log Readers membership.</summary>
	public bool SecurityReadDenied { get; set; }

	/// <summary>True when the live Security EventLogWatcher has never armed since the service
	/// started — typically because the channel is disabled or the manifest is unavailable.</summary>
	public bool ChannelDisabled { get; set; }

	/// <summary>True when the persisted bookmark for the Security channel is outside the
	/// channel's retention window — backfill cannot resume from where the service left off and
	/// recent events have already aged out. Operator should delete the bookmark and restart.</summary>
	public bool BookmarkStaleOrLogRetentionGap { get; set; }
}
