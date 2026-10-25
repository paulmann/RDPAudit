/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// File   : DecimationOptions.cs
// Project: RdpAudit.Core (RdpAudit.Core.Config)
// Purpose: Optional frequency-oriented decimation of raw event telemetry run by the retention worker.
// Depends: System
// Extends: Add per-event exclusion rules when retention-decimation policy needs finer control.

namespace RdpAudit.Core.Config;

/// <summary>
/// Settings for the optional frequency-oriented decimation pass performed by the retention
/// worker after ordinary retention pruning. Decimation shrinks monotonically high-frequency
/// bursts of a single event id coming from a single source IP by deleting only the middle of
/// each burst: the head and tail rows always survive for forensics, rare events are never
/// candidates, and rows without a source IP are ignored. Disabled by default so existing
/// installations keep today's behaviour until an operator opts in.
/// </summary>
public sealed class DecimationOptions
{
	/// <summary>Smallest effective value for <see cref="MinAgeDays"/>. Keeps decimation away
	/// from fresh events that investigators still need verbatim.</summary>
	public const int MinMinAgeDays = 7;

	/// <summary>Largest effective value for <see cref="MinAgeDays"/>. A hand-edited absurd value
	/// used to reach <see cref="DateTime.AddDays"/> as <c>-int.MaxValue</c> and throw; clamping it
	/// keeps the retention pass alive instead of failing every tick.</summary>
	public const int MaxMinAgeDays = 36_500;

	/// <summary>Smallest effective gap (seconds) that separates two bursts of the same
	/// (SourceIp, EventId) pair. Shorter gaps would split genuinely continuous traffic.</summary>
	public const int MinBurstGapSeconds = 10;

	/// <summary>Smallest effective candidate threshold. An event id must have at least this many
	/// rows in the decimation window to become a candidate at all.</summary>
	public const int MinCandidateMinRows = 10_000;

	/// <summary>Smallest effective per-burst keep count for <see cref="HeadKeepPerBurst"/> and
	/// <see cref="TailKeepPerBurst"/>.</summary>
	public const int MinKeepPerBurst = 1;

	/// <summary>Largest effective per-burst keep count. Above this, "keep everything" describes
	/// the setting more honestly than "decimate".</summary>
	public const int MaxKeepPerBurst = 100_000;

	/// <summary>Smallest effective value for <see cref="MaxCandidateEventIds"/>.</summary>
	public const int MinMaxCandidateEventIds = 1;

	/// <summary>Largest effective value for <see cref="MaxCandidateEventIds"/>. Bounds the SQL
	/// work a single decimation tick is allowed to do.</summary>
	public const int MaxMaxCandidateEventIds = 32;

	/// <summary>Smallest effective delete batch size for one decimation statement.</summary>
	public const int MinBatchSize = 100;

	/// <summary>Largest effective delete batch size. Keeps writer-lock sections short on very
	/// large databases.</summary>
	public const int MaxBatchSize = 100_000;

	/// <summary>Master switch for the decimation pass. Defaults to false: existing installations
	/// behave exactly as before until an operator explicitly enables decimation.</summary>
	public bool Enabled { get; set; }

	/// <summary>Rows newer than this many days are never decimation candidates. The decimation
	/// window starts at the ordinary retention cutoff and ends at (now - MinAgeDays). Defaults
	/// to 30 days; values below 7 are treated as 7.</summary>
	public int MinAgeDays { get; set; } = 30;

	/// <summary>Gap in seconds between consecutive rows of the same (SourceIp, EventId) pair that
	/// starts a new burst. Defaults to 300 seconds; values below 10 are treated as 10.</summary>
	public int BurstGapSeconds { get; set; } = 300;

	/// <summary>Minimum row count of one event id inside the decimation window required for that
	/// event id to become a candidate. Defaults to 100,000; values below 10,000 are treated as
	/// 10,000.</summary>
	public int CandidateMinRows { get; set; } = 100_000;

	/// <summary>Number of rows preserved at the start of every burst. Defaults to 100; clamped
	/// to [1, 100,000].</summary>
	public int HeadKeepPerBurst { get; set; } = 100;

	/// <summary>Number of rows preserved at the end of every burst. Defaults to 100; clamped
	/// to [1, 100,000].</summary>
	public int TailKeepPerBurst { get; set; } = 100;

	/// <summary>Maximum number of distinct event ids examined by one decimation tick. Defaults
	/// to 5; clamped to [1, 32].</summary>
	public int MaxCandidateEventIds { get; set; } = 5;

	/// <summary>Maximum number of rows one decimation statement may delete. Defaults to 5,000;
	/// clamped to [100, 100,000].</summary>
	public int BatchSize { get; set; } = 5_000;

	/// <summary>Returns <see cref="MinAgeDays"/> clamped to [<see cref="MinMinAgeDays"/>, <see cref="MaxMinAgeDays"/>].</summary>
	public int ResolveMinAgeDays() => Math.Clamp(MinAgeDays, MinMinAgeDays, MaxMinAgeDays);

	/// <summary>Returns <see cref="BurstGapSeconds"/> clamped to [<see cref="MinBurstGapSeconds"/>, int.MaxValue].</summary>
	public int ResolveBurstGapSeconds() => Math.Max(MinBurstGapSeconds, BurstGapSeconds);

	/// <summary>Returns <see cref="CandidateMinRows"/> clamped to [<see cref="MinCandidateMinRows"/>, int.MaxValue].</summary>
	public int ResolveCandidateMinRows() => Math.Max(MinCandidateMinRows, CandidateMinRows);

	/// <summary>Returns <see cref="HeadKeepPerBurst"/> clamped to the supported keep range.</summary>
	public int ResolveHeadKeepPerBurst() => ClampKeepPerBurst(HeadKeepPerBurst);

	/// <summary>Returns <see cref="TailKeepPerBurst"/> clamped to the supported keep range.</summary>
	public int ResolveTailKeepPerBurst() => ClampKeepPerBurst(TailKeepPerBurst);

	/// <summary>Returns <see cref="MaxCandidateEventIds"/> clamped to the supported range.</summary>
	public int ResolveMaxCandidateEventIds()
		=> Math.Clamp(MaxCandidateEventIds, MinMaxCandidateEventIds, MaxMaxCandidateEventIds);

	/// <summary>Returns <see cref="BatchSize"/> clamped to the supported range.</summary>
	public int ResolveBatchSize() => Math.Clamp(BatchSize, MinBatchSize, MaxBatchSize);

	private static int ClampKeepPerBurst(int value)
		=> Math.Clamp(value, MinKeepPerBurst, MaxKeepPerBurst);
}
