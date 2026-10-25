/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 2.0.0
// File   : ShardCardinalityGuard.cs
// Project: RdpAudit.Core (RdpAudit.Core.Storage.Sharding)
// Purpose: Shard-cardinality guard. It answers exactly one question - "may this new source have its
//          own shard file, or must it share an IPv4 /24 (IPv6 /64) aggregate bucket?" - and answers it
//          from two ceilings plus one volume test: the number of shard files already in the tree, the
//          number of new files this process created inside the current rate window, and the number of
//          rows the source itself produced inside that window. The guard never composes a path, never
//          opens a file and never deletes anything; it only reports a decision, so the sink stays the
//          sole writer and the decision is unit-testable without a filesystem.
// Depends: SubnetAggregationOptions
// Extends: Add a new trigger as another ShardAggregationTrigger member plus its metric and its
//          operator-facing sentence; never let the guard mutate shard state itself.

using RdpAudit.Core.Config;

namespace RdpAudit.Core.Storage.Sharding;

/// <summary>Why the cardinality guard routed a source into a subnet aggregate.</summary>
public enum ShardAggregationTrigger
{
	/// <summary>The guard did not engage; the source keeps a per-IP shard file.</summary>
	None = 0,

	/// <summary>The shard tree already holds more files than <c>TotalFileThreshold</c>.</summary>
	FileCount = 1,

	/// <summary>This process already created <c>NewFilesPerIntervalLimit</c> files in the current
	/// interval, so the next one would exceed the configured rate.</summary>
	NewFileRate = 2,
}

/// <summary>One guard decision: whether to aggregate, why, and the inputs it was taken from so an
/// operator-facing message never has to guess.</summary>
/// <param name="Aggregate">True when the source must be written into the subnet aggregate bucket.</param>
/// <param name="Trigger">Why the guard engaged; <see cref="ShardAggregationTrigger.None"/> when it did not.</param>
/// <param name="ShardFileCount">Shard files the caller reported in the tree at decision time.</param>
/// <param name="NewFilesInInterval">New files this process created inside the current interval.</param>
/// <param name="SourceRowsInInterval">Rows the source produced inside the current interval, before the
/// current event.</param>
/// <param name="GuardEnabled">True when the guard is configured on. When false,
/// <paramref name="Aggregate"/> is false.</param>
public readonly record struct ShardAggregationDecision(
	bool Aggregate,
	ShardAggregationTrigger Trigger,
	long ShardFileCount,
	int NewFilesInInterval,
	int SourceRowsInInterval,
	bool GuardEnabled);

/// <summary>
/// Stateful, allocation-light cardinality guard. The thresholds are passed in on every call rather
/// than captured at construction, so a policy saved over IPC takes effect on the next event without
/// recreating the guard. Not thread-safe: the shard sink is a single-consumer writer, exactly like the
/// per-shard <see cref="ShardWriter"/>.
/// </summary>
public sealed class ShardCardinalityGuard
{
	/// <summary>Upper bound on tracked sources per interval. A distributed spray can name millions of
	/// addresses; the table is capped so the guard itself can never become the memory exhaustion it
	/// exists to prevent. A source with no entry reads as zero rows, which is the low-volume answer the
	/// guard is designed to give under a spray.</summary>
	public const int MaxTrackedSources = 65_536;

	private readonly Dictionary<string, int> _rowsBySource = new(StringComparer.Ordinal);
	private long _windowStartTicks;
	private int _newFilesInInterval;

	// ── Public API ───────────────────────────────────────────────────────────────

	/// <summary>Number of sources tracked in the current interval; exposed for diagnostics.</summary>
	public int TrackedSourceCount => _rowsBySource.Count;

	/// <summary>New shard files this process created inside the current interval.</summary>
	public int NewFilesInInterval => _newFilesInInterval;

	/// <summary>Records one event for <paramref name="sourceKey"/> and returns the number of rows that
	/// source had produced in the current interval <em>before</em> this one. Rolls the rate window over
	/// when <paramref name="nowUtcTicks"/> is at or past its end, so every caller sees a consistent
	/// window without a timer. A disabled guard tracks nothing at all and always answers zero.</summary>
	public int Observe(SubnetAggregationOptions options, long nowUtcTicks, string sourceKey)
	{
		ArgumentNullException.ThrowIfNull(options);
		ArgumentNullException.ThrowIfNull(sourceKey);
		if (!options.Enabled)
		{
			return 0;
		}

		AdvanceWindow(options, nowUtcTicks);
		if (_rowsBySource.TryGetValue(sourceKey, out int rows))
		{
			_rowsBySource[sourceKey] = rows + 1;
			return rows;
		}

		if (_rowsBySource.Count < MaxTrackedSources)
		{
			_rowsBySource[sourceKey] = 1;
		}

		return 0;
	}

	/// <summary>Records that this process created one shard file, so the rate ceiling sees it.</summary>
	public void NoteNewShardFile(SubnetAggregationOptions options, long nowUtcTicks)
	{
		ArgumentNullException.ThrowIfNull(options);
		if (!options.Enabled)
		{
			return;
		}

		AdvanceWindow(options, nowUtcTicks);
		if (_newFilesInInterval < int.MaxValue)
		{
			_newFilesInInterval++;
		}
	}

	/// <summary>True when either ceiling is already breached, regardless of the source's volume. Used
	/// for the operator-facing "the guard is engaged" signal.</summary>
	public bool IsThresholdBreached(SubnetAggregationOptions options, long shardFileCount)
	{
		ArgumentNullException.ThrowIfNull(options);
		if (!options.Enabled)
		{
			return false;
		}

		return shardFileCount > options.ResolveTotalFileThreshold()
			|| _newFilesInInterval >= options.ResolveNewFilesPerIntervalLimit();
	}

	/// <summary>Decides whether a new source is written to the subnet aggregate bucket.
	/// <paramref name="sourceRowsInInterval"/> is the value <see cref="Observe"/> returned for the event
	/// being written: a source that has already produced at least
	/// <c>MinSourceRowsPerInterval</c> rows in this interval has proved it is not part of a low-volume
	/// spray and keeps its own file.</summary>
	public ShardAggregationDecision Decide(SubnetAggregationOptions options, long shardFileCount, int sourceRowsInInterval)
	{
		ArgumentNullException.ThrowIfNull(options);
		if (!options.Enabled)
		{
			return new ShardAggregationDecision(false, ShardAggregationTrigger.None, shardFileCount, 0, sourceRowsInInterval, false);
		}

		bool fileCountBreached = shardFileCount > options.ResolveTotalFileThreshold();
		bool rateBreached = _newFilesInInterval >= options.ResolveNewFilesPerIntervalLimit();
		if (!fileCountBreached && !rateBreached)
		{
			return new ShardAggregationDecision(false, ShardAggregationTrigger.None, shardFileCount, _newFilesInInterval, sourceRowsInInterval, true);
		}

		if (sourceRowsInInterval >= options.ResolveMinSourceRowsPerInterval())
		{
			return new ShardAggregationDecision(false, ShardAggregationTrigger.None, shardFileCount, _newFilesInInterval, sourceRowsInInterval, true);
		}

		return new ShardAggregationDecision(
			Aggregate: true,
			Trigger: fileCountBreached ? ShardAggregationTrigger.FileCount : ShardAggregationTrigger.NewFileRate,
			ShardFileCount: shardFileCount,
			NewFilesInInterval: _newFilesInInterval,
			SourceRowsInInterval: sourceRowsInInterval,
			GuardEnabled: true);
	}

	// ── Core Logic ───────────────────────────────────────────────────────────────

	/// <summary>Rolls the rate window over when the tick moves past its end. Idempotent for repeated
	/// calls with the same tick, so the sink may call it from both the observer and the decision path.</summary>
	private void AdvanceWindow(SubnetAggregationOptions options, long nowUtcTicks)
	{
		long intervalTicks = TimeSpan.FromSeconds(options.ResolveIntervalSeconds()).Ticks;
		if (_windowStartTicks != 0 && nowUtcTicks - _windowStartTicks < intervalTicks)
		{
			return;
		}

		_windowStartTicks = nowUtcTicks;
		_newFilesInInterval = 0;
		// Clear() keeps the allocated buckets, so a rollover under a live spray does not re-grow the table.
		_rowsBySource.Clear();
	}
}
