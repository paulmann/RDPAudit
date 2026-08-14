/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 2.0.0
// File   : UnmanagedMpmcRingBuffer.cs
// Project: RdpAudit.Service (RdpAudit.Service.Infrastructure)
// Purpose: Lock-free bounded Multi-Producer Multi-Consumer ring buffer following the
//          Vyukov algorithm. Backs the v2.0 event pipeline when multiple producers
//          (EventCollectorHostedWorker, ETW sessions, backfill workers) enqueue in
//          parallel. Payload is a fixed 4 KB slot copied by memcpy so the pipe is
//          zero managed-heap allocation and never touches System.Threading.Channels.
// Depends: NativeMemory, Interlocked, Volatile, ReadOnlySpan, Span
// Extends: When adding a new event carrier size, update SlotSize consistently across
//          UnmanagedSpscRingBuffer / UnmanagedMpmcRingBuffer and RawEventSlot. When
//          changing the DropOldest policy, update TryEvictOldest and its invariant
//          documented in the algorithm section below.

using System;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Threading;

#pragma warning disable CS0169 // Fields exist purely to pad cache lines and eliminate false sharing.
#pragma warning disable CA1823 // Same reasoning.

namespace RdpAudit.Service.Infrastructure;

/// <summary>
/// Lock-free bounded Multi-Producer Multi-Consumer ring buffer implementing Dmitry
/// Vyukov's classic algorithm on top of unmanaged memory. Correct under any number
/// of concurrent producers and consumers. Strictly FIFO under contention.
/// </summary>
/// <remarks>
/// <para>
/// Layout: each slot occupies <see cref="SlotStride"/> bytes = 64 B sequence header
/// (of which only the first 8 B carry the sequence long; remaining 56 B pad the
/// header out to a full cache line) + <see cref="SlotSize"/> B payload. Sequence
/// numbers and payloads of different slots therefore never share a cache line,
/// eliminating false sharing between concurrent producers or between a producer
/// and a consumer touching neighbouring slots.
/// </para>
/// <para>
/// State machine (Vyukov):
/// <list type="bullet">
///   <item>Cell i starts with sequence == i (empty, waiting for enqueue turn i).</item>
///   <item>Producer wins a slot with sequence == pos, writes payload, publishes
///         sequence = pos + 1 (full, waiting for dequeue turn pos + 1).</item>
///   <item>Consumer wins a slot with sequence == pos + 1, reads payload, publishes
///         sequence = pos + Capacity (empty again, ready for the next lap).</item>
///   <item>Full: producer observes sequence &lt; pos and TryWrite returns false.</item>
///   <item>Empty: consumer observes sequence &lt; pos + 1 and TryRead returns false.</item>
/// </list>
/// </para>
/// <para>
/// DropOldest is layered on top via <see cref="TryEvictOldest"/>: on a full write,
/// the producer atomically advances the consumer position (CAS) and finalises the
/// evicted slot as if a consumer had read it (sequence = pos + Capacity), then
/// retries. Only one producer wins each eviction; loser producers observe the
/// updated <c>_dequeuePos</c> and simply retry their own write on the freed slot.
/// </para>
/// </remarks>
public sealed class UnmanagedMpmcRingBuffer : IDisposable
{
	// ── Constants ────────────────────────────────────────────────────────────────

	/// <summary>Payload capacity per slot in bytes. Matches <c>UnmanagedSpscRingBuffer.SlotSize</c>
	/// so <c>RawEventSlot</c> can be memcpy'd into either backend without change.</summary>
	public const int SlotSize = 4096;

	/// <summary>Total bytes per slot including the sequence header + pad. Chosen so
	/// each slot occupies whole cache lines and the sequence never shares a cache
	/// line with a payload of a different slot.</summary>
	public const int SlotStride = 64 + SlotSize;

	private const int CacheLine = 64;

	// ── Fields (padded to eliminate false sharing between producers/consumers) ───

	// Enqueue cursor: producers Interlocked.Increment this and take the resulting
	// value minus one as their reservation.
	private long _enqueuePos;
	private long _p1_1, _p1_2, _p1_3, _p1_4, _p1_5, _p1_6, _p1_7;

	// Dequeue cursor: consumers Interlocked.Increment this and take the resulting
	// value minus one as their reservation.
	private long _dequeuePos;
	private long _p2_1, _p2_2, _p2_3, _p2_4, _p2_5, _p2_6, _p2_7;

	// Overflow counter published from the DropOldest eviction path.
	private long _overflowCount;
	private long _p3_1, _p3_2, _p3_3, _p3_4, _p3_5, _p3_6, _p3_7;

	// Immutable geometry.
	private readonly long _capacity;
	private readonly long _mask;
	private readonly nint _buffer;

	private int _disposed;

	// ── Construction ─────────────────────────────────────────────────────────────

	/// <summary>Total number of slots in the ring. Always a power of two.</summary>
	public long Capacity => _capacity;

	/// <summary>Monotonic count of DropOldest evictions. Never decreases.</summary>
	public long OverflowCount => Interlocked.Read(ref _overflowCount);

	/// <summary>Constructs a ring buffer with the specified slot count.</summary>
	/// <param name="capacity">Number of 4 KB slots. Must be a strictly positive power of two.</param>
	public UnmanagedMpmcRingBuffer(int capacity)
	{
		if (capacity <= 0 || (capacity & (capacity - 1)) != 0)
			throw new ArgumentException("Capacity must be a strictly positive power of 2.", nameof(capacity));

		_capacity = capacity;
		_mask = capacity - 1;

		nuint totalSize = (nuint)((long)capacity * SlotStride);

		unsafe
		{
			// AlignedAlloc on the cache line ensures the very first slot's sequence
			// header is cache line aligned; all subsequent slots inherit alignment
			// through SlotStride being a multiple of CacheLine.
			_buffer = (nint)NativeMemory.AlignedAlloc(totalSize, CacheLine);
			NativeMemory.Clear((void*)_buffer, totalSize);

			// Seed sequences: cell i starts with sequence == i.
			for (long i = 0; i < capacity; i++)
			{
				long* seqPtr = (long*)(_buffer + (nint)(i * SlotStride));
				*seqPtr = i;
			}
		}
	}

	// ── Public API ───────────────────────────────────────────────────────────────

	/// <summary>
	/// Attempts to enqueue the payload. Returns <see langword="true"/> when a fresh
	/// slot was available, <see langword="false"/> when the ring was full. Does NOT
	/// perform DropOldest; the caller (<c>MpmcEventChannel</c>) is responsible for
	/// invoking <see cref="TryEvictOldest"/> and retrying.
	/// </summary>
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public bool TryWrite(ReadOnlySpan<byte> payload)
	{
		if (payload.Length > SlotSize) ThrowPayloadTooLarge();

		// Bounded number of spins: under contention a producer may lose several CAS
		// races before finding a fresh slot; without a bound a runaway consumer or a
		// completely full ring would spin forever. Two full laps are enough to prove
		// the ring is genuinely full (Vyukov's original proof).
		long spinBudget = _capacity * 2L;

		while (true)
		{
			long pos = Volatile.Read(ref _enqueuePos);
			unsafe
			{
				long* seqPtr = (long*)(_buffer + (nint)((pos & _mask) * SlotStride));
				long seq = Volatile.Read(ref *seqPtr);
				long diff = seq - pos;

				if (diff == 0)
				{
					// Slot is exactly at its enqueue turn. Try to claim it.
					if (Interlocked.CompareExchange(ref _enqueuePos, pos + 1, pos) == pos)
					{
						byte* payloadPtr = (byte*)(_buffer + (nint)((pos & _mask) * SlotStride + 64));
						payload.CopyTo(new Span<byte>(payloadPtr, SlotSize));
						Volatile.Write(ref *seqPtr, pos + 1);
						return true;
					}
					// Lost the CAS: another producer took this exact slot. Re-read.
				}
				else if (diff < 0)
				{
					// Slot is still occupied by a value that has not been consumed on
					// its previous lap. Ring is full from this producer's perspective.
					return false;
				}
				// diff > 0: a faster producer already advanced past this slot; refresh
				// our view of _enqueuePos and retry.
			}

			if (--spinBudget <= 0) return false;
		}
	}

	/// <summary>
	/// Attempts to dequeue one payload into <paramref name="destination"/>. Returns
	/// <see langword="true"/> when a payload was copied out, <see langword="false"/>
	/// when the ring was empty.
	/// </summary>
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public bool TryRead(Span<byte> destination)
	{
		if (destination.Length < SlotSize) ThrowDestinationTooSmall();

		long spinBudget = _capacity * 2L;

		while (true)
		{
			long pos = Volatile.Read(ref _dequeuePos);
			unsafe
			{
				long* seqPtr = (long*)(_buffer + (nint)((pos & _mask) * SlotStride));
				long seq = Volatile.Read(ref *seqPtr);
				long diff = seq - (pos + 1);

				if (diff == 0)
				{
					// Slot is exactly at its dequeue turn. Try to claim it.
					if (Interlocked.CompareExchange(ref _dequeuePos, pos + 1, pos) == pos)
					{
						byte* payloadPtr = (byte*)(_buffer + (nint)((pos & _mask) * SlotStride + 64));
						new Span<byte>(payloadPtr, SlotSize).CopyTo(destination);
						Volatile.Write(ref *seqPtr, pos + _capacity);
						return true;
					}
				}
				else if (diff < 0)
				{
					// Producer has not published this slot's current lap yet: empty.
					return false;
				}
				// diff > 0: another consumer already advanced past this slot; refresh.
			}

			if (--spinBudget <= 0) return false;
		}
	}

	/// <summary>
	/// DropOldest primitive: atomically evict the oldest ready slot (as if a consumer
	/// had read it and discarded the payload). Returns <see langword="true"/> when an
	/// eviction actually happened, <see langword="false"/> when the ring was already
	/// empty (nothing to evict). Increments <see cref="OverflowCount"/> on success.
	/// </summary>
	/// <remarks>
	/// Callers use this to implement DropOldest at the higher <c>MpmcEventChannel</c>
	/// layer: on a full <see cref="TryWrite"/>, call <see cref="TryEvictOldest"/>
	/// then retry <see cref="TryWrite"/>. Multiple producers may race and each will
	/// evict a distinct slot; the CAS on <c>_dequeuePos</c> guarantees no double
	/// eviction of the same slot.
	/// </remarks>
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public bool TryEvictOldest()
	{
		long spinBudget = _capacity * 2L;

		while (true)
		{
			long pos = Volatile.Read(ref _dequeuePos);
			unsafe
			{
				long* seqPtr = (long*)(_buffer + (nint)((pos & _mask) * SlotStride));
				long seq = Volatile.Read(ref *seqPtr);
				long diff = seq - (pos + 1);

				if (diff == 0)
				{
					if (Interlocked.CompareExchange(ref _dequeuePos, pos + 1, pos) == pos)
					{
						// Finalise the slot as if consumed. Payload bytes are left in
						// place; the sequence transition alone is what makes the slot
						// available for the next producer lap.
						Volatile.Write(ref *seqPtr, pos + _capacity);
						Interlocked.Increment(ref _overflowCount);
						return true;
					}
				}
				else if (diff < 0)
				{
					// Nothing to evict: the ring is genuinely empty right now (a
					// concurrent consumer already drained it).
					return false;
				}
			}

			if (--spinBudget <= 0) return false;
		}
	}

	/// <summary>
	/// Approximate number of ready-to-read slots. Read under contention; the exact
	/// value may drift by O(threads) by the time the caller reads it. Intended for
	/// observability and tests, never for control flow.
	/// </summary>
	public long ApproxCount
	{
		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		get
		{
			long enq = Volatile.Read(ref _enqueuePos);
			long deq = Volatile.Read(ref _dequeuePos);
			long delta = enq - deq;
			if (delta < 0) return 0;
			if (delta > _capacity) return _capacity;
			return delta;
		}
	}

	// ── Disposal ─────────────────────────────────────────────────────────────────

	/// <summary>Frees the unmanaged buffer. Safe to call multiple times.</summary>
	public void Dispose()
	{
		if (Interlocked.Exchange(ref _disposed, 1) == 0)
		{
			if (_buffer != nint.Zero)
			{
				unsafe { NativeMemory.AlignedFree((void*)_buffer); }
			}
			GC.SuppressFinalize(this);
		}
	}

	~UnmanagedMpmcRingBuffer() => Dispose();

	// ── Error Paths ──────────────────────────────────────────────────────────────

	[MethodImpl(MethodImplOptions.NoInlining)]
	private static void ThrowPayloadTooLarge() =>
		throw new ArgumentException($"Payload exceeds {SlotSize} bytes.");

	[MethodImpl(MethodImplOptions.NoInlining)]
	private static void ThrowDestinationTooSmall() =>
		throw new ArgumentException($"Destination must be >= {SlotSize} bytes.");
}
