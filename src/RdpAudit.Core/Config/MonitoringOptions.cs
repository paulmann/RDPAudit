/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 2.2.0
// File   : MonitoringOptions.cs
// Project: RdpAudit.Core (RdpAudit.Core.Config)
// Purpose: Configures monitored event sources and bounded pre-pipeline flood protection.
// Depends: System.Collections.Generic, IngestionMode
// Extends: Add new capture controls here when an event source needs a persisted operational threshold.

namespace RdpAudit.Core.Config;

/// <summary>Configures which event channels and event IDs are monitored.</summary>
public sealed class MonitoringOptions
{
	/// <summary>
	/// Selects the event-ingestion transport. Default is <see cref="IngestionMode.EventLog"/>
	/// for compatibility with existing installations; set to <see cref="IngestionMode.Auto"/>
	/// to opt-in to ETW with graceful fallback, or <see cref="IngestionMode.Etw"/> to require
	/// ETW and fail-fast when it is unavailable.
	/// </summary>
	public IngestionMode IngestionMode { get; set; } = IngestionMode.EventLog;

	public List<string> EnabledChannels { get; set; } = new()
	{
		"Security",
		"Microsoft-Windows-TerminalServices-LocalSessionManager/Operational",
		"Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational",
		"Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational",
		"Microsoft-Windows-TerminalServices-Gateway/Operational",
		"Microsoft-Windows-TerminalServices-RDPClient/Operational",
		"System",
	};

	public List<int> EnabledEventIds { get; set; } = new();

	public bool FilterLocalAddresses { get; set; } = true;

	public bool TrackProcessCreation { get; set; } = true;

	public bool TrackScheduledTasks { get; set; } = true;

	public bool TrackAccountChanges { get; set; } = true;

	public bool TrackKerberos { get; set; } = true;

	public bool TrackObjectAccess { get; set; } = true;

	public int BatchSize { get; set; } = 100;

	public int BatchTimeoutMilliseconds { get; set; } = 500;

	public int ChannelCapacity { get; set; } = 50_000;

	/// <summary>
	/// Selects the underlying event pipe transport. Default is
	/// <see cref="RingBufferBackend.Spsc"/> for compatibility with existing installations
	/// (fast single-producer path). Set to <see cref="RingBufferBackend.Mpmc"/> when
	/// multiple producers write concurrently (ETW hybrid ingestion, parallel backfill
	/// workers). The MPMC backend is Vyukov-correct for any producer/consumer count.
	/// </summary>
	public RingBufferBackend RingBufferBackend { get; set; } = RingBufferBackend.Spsc;

	/// <summary>Enables pre-enqueue sampling of non-critical events during a per-source flood.</summary>
	public bool FloodGuardEnabled { get; set; } = true;

	/// <summary>Sliding-window duration for per-channel and per-source flood accounting.</summary>
	public int FloodGuardWindowSeconds { get; set; } = 10;

	/// <summary>Hits in one window before periodic detail sampling begins.</summary>
	public long FloodGuardSoftThreshold { get; set; } = 1_000;

	/// <summary>Hits in one window after which only aggregate accounting is retained.</summary>
	public long FloodGuardHardThreshold { get; set; } = 10_000;

	/// <summary>Retains one full-detail event for every N hits between soft and hard thresholds.</summary>
	public int FloodGuardSampleEveryN { get; set; } = 32;

	/// <summary>Fixed number of collision-tolerant flood-accounting buckets.</summary>
	public int FloodGuardBucketCount { get; set; } = 4_096;

	/// <summary>
	/// First-read lookback used when a channel has NO persisted bookmark (default 24 hours).
	/// Used in two places that would otherwise replay unbounded history: (1) the live
	/// watcher's XPath gains a TimeCreated floor this far back instead of replaying the full
	/// matching channel history; (2) the Security backfill worker's wide first pass reads back
	/// this far to hydrate/rebuild recent auth context. Set to 0 to disable the wide
	/// first-read behavior in both places (regular per-tick lookback only).
	/// </summary>
	public int FirstReadLookbackHours { get; set; } = 24;
}
