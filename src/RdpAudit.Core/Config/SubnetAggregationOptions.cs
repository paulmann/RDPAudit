/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 2.0.0
// File   : SubnetAggregationOptions.cs
// Project: RdpAudit.Core (RdpAudit.Core.Config)
// Purpose: Shard-cardinality guard thresholds. Once a distributed source-IP spray would push the
//          shard tree past a file-count or new-file-rate ceiling, low-volume new sources are routed
//          into a shared IPv4 /24 (or IPv6 /64) aggregate shard instead of a per-IP file, so a spray
//          can no longer stop sharding entirely. Every bound resolves through a clamped Resolve*
//          helper, so a hand-edited appsettings.json can never widen a limit. Disabled by default:
//          with Enabled=false the sink writes one file per IP exactly as it did before this guard.
// Depends: System
// Extends: Add a new guard trigger here together with its Resolve* clamp and its metric.

namespace RdpAudit.Core.Config;

/// <summary>
/// Settings for the optional shard-cardinality guard. The guard never rewrites or deletes an
/// existing shard: it only decides which path a <em>new</em> source is written to.
/// </summary>
public sealed class SubnetAggregationOptions
{
	// ── Supported bounds ─────────────────────────────────────────────────────────

	/// <summary>Smallest effective shard-file threshold. One file already means "the tree exists",
	/// so a smaller ceiling would aggregate every source unconditionally.</summary>
	public const int MinTotalFileThreshold = 1;

	/// <summary>Largest effective shard-file threshold. Bounds the value so a typo cannot disable the
	/// guard by demanding an unreachable file count.</summary>
	public const int MaxTotalFileThreshold = 10_000_000;

	/// <summary>Smallest effective new-file rate ceiling. One new file per interval is the most
	/// aggressive guard the sink can honour without refusing to shard at all.</summary>
	public const int MinNewFilesPerIntervalLimit = 1;

	/// <summary>Largest effective new-file rate ceiling.</summary>
	public const int MaxNewFilesPerIntervalLimit = 10_000_000;

	/// <summary>Smallest effective rate-window length in seconds.</summary>
	public const int MinIntervalSeconds = 1;

	/// <summary>Largest effective rate-window length in seconds (one day). Above this the guard reacts
	/// more slowly than any realistic spray develops.</summary>
	public const int MaxIntervalSeconds = 86_400;

	/// <summary>Largest effective low-volume row threshold.</summary>
	public const int MaxMinSourceRowsPerInterval = 10_000_000;

	// ── Settings ─────────────────────────────────────────────────────────────────

	/// <summary>Gets or sets whether the cardinality guard may route new sources into a subnet
	/// aggregate. Defaults to false: with the guard off the sink behaves exactly as before, and a
	/// reached <c>MaxShardFiles</c> still refuses new files (with an operator-visible banner)
	/// instead of silently changing where evidence is written.</summary>
	public bool Enabled { get; set; }

	/// <summary>Gets or sets the shard-file count above which new low-volume sources are aggregated.
	/// The guard engages when the tree already holds more than this many files.</summary>
	public int TotalFileThreshold { get; set; } = 4096;

	/// <summary>Gets or sets the number of new shard files one interval may create before the guard
	/// engages. Evaluated against files this process itself created.</summary>
	public int NewFilesPerIntervalLimit { get; set; } = 64;

	/// <summary>Gets or sets the length of the rate window in seconds.</summary>
	public int IntervalSeconds { get; set; } = 60;

	/// <summary>Gets or sets the per-source row count below which a source counts as low volume.
	/// A source that has already produced this many rows in the current interval keeps (or is given)
	/// its own shard file.</summary>
	public int MinSourceRowsPerInterval { get; set; } = 8;

	// ── Clamped resolution ───────────────────────────────────────────────────────

	/// <summary>Returns <see cref="TotalFileThreshold"/> clamped to the supported range.</summary>
	public int ResolveTotalFileThreshold()
		=> Math.Clamp(TotalFileThreshold, MinTotalFileThreshold, MaxTotalFileThreshold);

	/// <summary>Returns <see cref="NewFilesPerIntervalLimit"/> clamped to the supported range.</summary>
	public int ResolveNewFilesPerIntervalLimit()
		=> Math.Clamp(NewFilesPerIntervalLimit, MinNewFilesPerIntervalLimit, MaxNewFilesPerIntervalLimit);

	/// <summary>Returns <see cref="IntervalSeconds"/> clamped to the supported range.</summary>
	public int ResolveIntervalSeconds()
		=> Math.Clamp(IntervalSeconds, MinIntervalSeconds, MaxIntervalSeconds);

	/// <summary>Returns <see cref="MinSourceRowsPerInterval"/> clamped to the supported range. Zero is
	/// allowed and means "every new source is low volume", which is the strictest setting.</summary>
	public int ResolveMinSourceRowsPerInterval()
		=> Math.Clamp(MinSourceRowsPerInterval, 0, MaxMinSourceRowsPerInterval);
}
