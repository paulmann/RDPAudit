/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 2.0.0
// File   : BookmarkCheckpointLedger.cs
// Project: RdpAudit.Service (RdpAudit.Service.Infrastructure)
// Purpose: Ties every pending Windows event-log bookmark to the ingestion sequence of the event
//          it covers, so a bookmark is only ever persisted once the events it would skip past
//          have themselves been committed. Closes the crash window between "collector advanced
//          the bookmark" and "processor persisted the batch".
// Depends: RawEventDto.IngestionSequence (stamped by RawEventSerializer.Serialize)
// Extends: When adding a second durability sink (for example the shard writer), advance the
//          watermark only after ALL sinks report the sequence durable - take the minimum.

using System;
using System.Collections.Generic;

namespace RdpAudit.Service.Infrastructure;

/// <summary>
/// Correlates bookmarks with the monotonic ingestion sequence of the event they were captured
/// alongside.
/// </summary>
/// <remarks>
/// <para>
/// The collector stamps a bookmark the moment it hands an event to the pipe, but the event is
/// only durable once <c>EventProcessorWorker</c> commits its batch. Persisting the bookmark
/// before that commit means a crash in between resumes the watcher <em>past</em> events that
/// were never written - silent evidence loss, and precisely the class of gap an attacker who
/// can crash the host would exploit.
/// </para>
/// <para>
/// This ledger removes the race by making the bookmark's durability derive from the event's:
/// <list type="number">
/// <item><description>Collector calls <see cref="Record"/> with the sequence stamped on the
/// DTO it just queued.</description></item>
/// <item><description>Processor commits a batch and calls <see cref="CollectCommittable"/>
/// with the highest sequence in that batch; it writes the returned bookmarks inside the very
/// same SQLite transaction as the events.</description></item>
/// <item><description>On commit success the processor calls <see cref="Prune"/>, which advances
/// <see cref="CommittedWatermark"/>.</description></item>
/// </list>
/// </para>
/// <para>
/// <b>Dropped events.</b> Under <c>DropOldest</c> backpressure an event can be evicted before the
/// processor ever sees it, so its sequence never appears in a batch. The watermark still moves
/// past it once a later sequence commits. That is intentional: the event is already lost and is
/// already counted in <c>ServiceMetrics.EventsDropped</c>; holding the bookmark back forever
/// would stall the channel and turn a counted drop into an unbounded backlog.
/// </para>
/// <para>Thread-safe. Writers are collector callback threads (one per channel, but no such
/// guarantee is relied upon); the reader is the single processor loop.</para>
/// </remarks>
public sealed class BookmarkCheckpointLedger
{
	// ── Fields & DI ──────────────────────────────────────────────────────────────

	private readonly object _gate = new();

	/// <summary>Per-channel pending checkpoints, appended in ascending sequence order.</summary>
	private readonly Dictionary<string, List<Checkpoint>> _pending =
		new(StringComparer.OrdinalIgnoreCase);

	private long _committedWatermark;

	/// <summary>
	/// Highest ingestion sequence known to be durably committed. Zero until the first batch
	/// commits, which is why callers must treat zero as "nothing is durable yet" rather than
	/// as a valid sequence.
	/// </summary>
	public long CommittedWatermark
	{
		get
		{
			lock (_gate)
			{
				return _committedWatermark;
			}
		}
	}

	// ── Public API ───────────────────────────────────────────────────────────────

	/// <summary>
	/// Records the bookmark that becomes safe to persist once <paramref name="sequence"/> has
	/// been committed. Called by the collector immediately after the covered event was handed
	/// to the pipe.
	/// </summary>
	/// <param name="channel">Event log channel name.</param>
	/// <param name="sequence">Ingestion sequence stamped on the queued event.</param>
	/// <param name="bookmarkXml">Serialized bookmark positioned at that event.</param>
	public void Record(string channel, long sequence, string bookmarkXml)
	{
		ArgumentException.ThrowIfNullOrWhiteSpace(channel);
		ArgumentNullException.ThrowIfNull(bookmarkXml);

		lock (_gate)
		{
			if (!_pending.TryGetValue(channel, out List<Checkpoint>? list))
			{
				list = new List<Checkpoint>(capacity: 64);
				_pending[channel] = list;
			}

			// Sequences are handed out by a single Interlocked counter, so appends are already
			// ordered in practice. Collapse an out-of-order or duplicate arrival onto the tail
			// rather than trusting it, so CollectCommittable can rely on ascending order.
			if (list.Count > 0 && sequence <= list[^1].Sequence)
			{
				list[^1] = new Checkpoint(list[^1].Sequence, bookmarkXml);
				return;
			}

			list.Add(new Checkpoint(sequence, bookmarkXml));
		}
	}

	/// <summary>
	/// Collects, per channel, the newest bookmark whose covering sequence is at or below
	/// <paramref name="committedThroughSequence"/>. Does not mutate ledger state - the caller
	/// must call <see cref="Prune"/> only after its transaction actually commits.
	/// </summary>
	/// <param name="committedThroughSequence">Highest sequence the caller's transaction covers.</param>
	/// <param name="destination">Dictionary populated with channel to bookmark XML. Cleared first.</param>
	/// <returns>Number of channels whose bookmark advanced.</returns>
	public int CollectCommittable(
		long committedThroughSequence,
		Dictionary<string, string> destination)
	{
		ArgumentNullException.ThrowIfNull(destination);

		destination.Clear();
		if (committedThroughSequence <= 0)
		{
			return 0;
		}

		lock (_gate)
		{
			foreach (KeyValuePair<string, List<Checkpoint>> entry in _pending)
			{
				List<Checkpoint> list = entry.Value;

				// Walk backwards: the newest qualifying checkpoint supersedes all earlier ones
				// for the same channel, so at most one row per channel is ever written.
				for (int i = list.Count - 1; i >= 0; i--)
				{
					if (list[i].Sequence <= committedThroughSequence)
					{
						destination[entry.Key] = list[i].BookmarkXml;
						break;
					}
				}
			}

			return destination.Count;
		}
	}

	/// <summary>
	/// Discards checkpoints at or below <paramref name="committedThroughSequence"/> and advances
	/// <see cref="CommittedWatermark"/>. Call only after the enclosing transaction committed.
	/// </summary>
	/// <param name="committedThroughSequence">Highest sequence now durable.</param>
	public void Prune(long committedThroughSequence)
	{
		if (committedThroughSequence <= 0)
		{
			return;
		}

		lock (_gate)
		{
			if (committedThroughSequence > _committedWatermark)
			{
				_committedWatermark = committedThroughSequence;
			}

			foreach (KeyValuePair<string, List<Checkpoint>> entry in _pending)
			{
				List<Checkpoint> list = entry.Value;

				int keepFrom = 0;
				while (keepFrom < list.Count && list[keepFrom].Sequence <= committedThroughSequence)
				{
					keepFrom++;
				}

				// Keep the last committed checkpoint so a channel that goes idle can still be
				// flushed on shutdown without the ledger having forgotten its position.
				if (keepFrom > 1)
				{
					list.RemoveRange(0, keepFrom - 1);
				}
			}
		}
	}

	/// <summary>
	/// Removes every pending checkpoint for <paramref name="channel"/> without touching the
	/// committed watermark. Used by bookmark-reset paths so a stale pre-reset position cannot be
	/// re-persisted by the next unified commit. Idempotent when the channel is unknown.
	/// </summary>
	public void ForgetChannel(string channel)
	{
		ArgumentException.ThrowIfNullOrWhiteSpace(channel);

		lock (_gate)
		{
			_pending.Remove(channel);
		}
	}

	/// <summary>
	/// Returns the bookmarks that are safe to persist outside a unified commit - used by the
	/// collector's fallback flush path on shutdown and for idle channels. Equivalent to
	/// <see cref="CollectCommittable"/> against the current watermark.
	/// </summary>
	/// <param name="destination">Dictionary populated with channel to bookmark XML. Cleared first.</param>
	/// <returns>Number of channels with a durable bookmark to write.</returns>
	public int CollectDurable(Dictionary<string, string> destination)
		=> CollectCommittable(CommittedWatermark, destination);

	// ── Nested Types ─────────────────────────────────────────────────────────────

	private readonly struct Checkpoint(long sequence, string bookmarkXml)
	{
		public long Sequence { get; } = sequence;

		public string BookmarkXml { get; } = bookmarkXml;
	}
}
