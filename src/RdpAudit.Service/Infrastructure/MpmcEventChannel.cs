/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 2.0.2
// File   : MpmcEventChannel.cs
// Project: RdpAudit.Service (RdpAudit.Service.Infrastructure)
// Purpose: DropOldest-aware event pipe backed by the Vyukov MPMC ring buffer. Sibling
//          to RingBufferEventChannel (SPSC) with an identical outer contract so the
//          RingBufferEventPipe adapter and EventChannel composition root can pick a
//          backend by configuration without any downstream Worker changes.
// Depends: UnmanagedMpmcRingBuffer, RawEventDto, RawEventSlot, RawEventSerializer
// Extends: When wiring a third backend (e.g. shared-memory ring), add another
//          IRawEventBackend implementation and route through EventChannel.

using System;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Threading;
using RdpAudit.Core.Events;

namespace RdpAudit.Service.Infrastructure;

/// <summary>
/// DropOldest event pipe backed by <see cref="UnmanagedMpmcRingBuffer"/>. Multi-producer
/// safe by construction; multi-consumer safe as well because the underlying ring is
/// Vyukov MPMC. Enforces the same public contract as <see cref="RingBufferEventChannel"/>
/// so <c>RingBufferEventPipe</c> can adapt either backend.
/// </summary>
public sealed class MpmcEventChannel : IRawEventBackend
{
	// ── Fields & DI ──────────────────────────────────────────────────────────────

	private readonly UnmanagedMpmcRingBuffer _ringBuffer;

	// Hard-drop counter kept separate from the underlying ring's OverflowCount so we
	// can surface a single unified DropOldest counter to the outside world without
	// double-counting the honest evictions performed by TryEvictOldest.
	private long _hardDropCount;

	private int _disposed;

	// ── Construction ─────────────────────────────────────────────────────────────

	/// <summary>Total slots. Equals the underlying ring capacity (always power of two).</summary>
	public int Capacity => (int)_ringBuffer.Capacity;

	/// <summary>DropOldest evictions since construction. Reflects both honest evictions
	/// performed by the ring (<see cref="UnmanagedMpmcRingBuffer.OverflowCount"/>) and any
	/// hard drops incurred by <see cref="TryWrite"/> when the eviction path could not
	/// physically place the new payload after exhausting its retry budget. Callers only
	/// need one counter to reason about lost rows.</summary>
	public long OverflowCount => _ringBuffer.OverflowCount + Interlocked.Read(ref _hardDropCount);

	/// <summary>Builds a ring with <paramref name="capacity"/> slots. Must be a strictly
	/// positive power of two (validated by the underlying buffer).</summary>
	public MpmcEventChannel(int capacity = 1024)
	{
		_ringBuffer = new UnmanagedMpmcRingBuffer(capacity);
	}

	// ── Public API ───────────────────────────────────────────────────────────────

	/// <summary>
	/// Enqueue a DTO. Returns <see langword="true"/> on a clean write, <see langword="false"/>
	/// when the write forced a DropOldest eviction (the DTO still landed or the caller must
	/// treat the row as dropped, which is accounted for in <see cref="OverflowCount"/>).
	/// Never blocks and never allocates on the managed heap. This method is O(1) amortised
	/// and does NOT loop indefinitely; the retry budget is bounded to a small constant so
	/// producers never stall behind a slow consumer under sustained contention.
	/// </summary>
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public bool TryWrite(RawEventDto dto)
	{
		ObjectDisposedException.ThrowIf(_disposed != 0, this);

		RawEventSlot slot = RawEventSerializer.Serialize(dto);
		ReadOnlySpan<byte> payload = MemoryMarshal.AsBytes(
			MemoryMarshal.CreateReadOnlySpan(ref slot, 1));

		if (_ringBuffer.TryWrite(payload))
		{
			return true;
		}

		// Full-ring fallback: evict oldest and retry. We only make a small, fixed number
		// of outer attempts. Each iteration is (evict, retry-write). The ring's own
		// TryWrite/TryEvictOldest each spin internally with a capacity-proportional
		// budget so a single outer attempt already tolerates significant transient
		// contention. Looping thousands of times here would just stall the producer
		// behind slow consumers under a full ring and violate the "never blocks"
		// contract of this pipe.
		const int outerRetryBudget = 8;
		for (int i = 0; i < outerRetryBudget; i++)
		{
			if (_ringBuffer.TryEvictOldest())
			{
				// A slot was freed; try to place our payload into it. Whether we win
				// the follow-up TryWrite CAS or not, the DropOldest accounting was
				// already done inside TryEvictOldest, so we always return false to
				// signal "an eviction happened".
				_ = _ringBuffer.TryWrite(payload);
				return false;
			}
			// TryEvictOldest returned false: the ring looked empty at that instant
			// (usually because a consumer just drained it). Retry TryWrite before
			// declaring a hard drop; this is the fast path when a producer bursts
			// into a ring that consumers are keeping up with.
			if (_ringBuffer.TryWrite(payload))
			{
				return true;
			}
		}

		// Genuine hard drop: neither eviction nor write succeeded in the bounded budget.
		// Account for the lost row so the unified OverflowCount stays truthful without
		// putting the producer into an unbounded spin.
		Interlocked.Increment(ref _hardDropCount);
		return false;
	}

	/// <summary>
	/// Dequeue one DTO. Returns <see langword="true"/> and populates <paramref name="dto"/>
	/// on success, <see langword="false"/> when the ring was empty. Never blocks and never
	/// allocates on the managed heap.
	/// </summary>
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public bool TryRead(out RawEventDto dto)
	{
		ObjectDisposedException.ThrowIf(_disposed != 0, this);

		RawEventSlot slot = default;
		Span<byte> destination = MemoryMarshal.AsBytes(
			MemoryMarshal.CreateSpan(ref slot, 1));

		if (_ringBuffer.TryRead(destination))
		{
			dto = RawEventSerializer.Deserialize(slot);
			return true;
		}

		dto = default!;
		return false;
	}

	/// <summary>Approximate live count for observability. Do not use for control flow.</summary>
	public long ApproxCount => _ringBuffer.ApproxCount;

	// ── Disposal ─────────────────────────────────────────────────────────────────

	public void Dispose()
	{
		if (Interlocked.Exchange(ref _disposed, 1) != 0) return;
		_ringBuffer.Dispose();
	}
}
