/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 2.0.1
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
	/// Never blocks and never allocates on the managed heap.
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

		// Full path: evict then retry. Under sustained contention several producers may
		// each evict a distinct slot before winning their own CAS; that is exactly the
		// DropOldest budget we want. The outer retry budget is generous because two
		// separate transient races (a slow producer that reserved _enqueuePos but has
		// not yet published its sequence, and a slow consumer that reserved _dequeuePos
		// but has not yet advanced the cell sequence) can each cause a spin-budget
		// exhaustion inside the ring even when the ring is not genuinely full. A short
		// SpinWait between outer retries yields the CPU so those in-flight producers
		// and consumers can make progress.
		int retries = _ringBuffer.Capacity switch
		{
			<= 0 => 0,
			var cap => (int)Math.Min(cap * 4L, 4096),
		};

		SpinWait spinner = default;
		for (int i = 0; i < retries; i++)
		{
			_ = _ringBuffer.TryEvictOldest();
			if (_ringBuffer.TryWrite(payload))
			{
				return false;
			}

			spinner.SpinOnce();
		}

		// Genuine hard drop: after 'retries' full attempts the ring still refuses the
		// payload. This is exceedingly rare in practice (it requires a producer or
		// consumer to be de-scheduled for longer than the retry budget under sustained
		// contention). Account for the lost row so the unified OverflowCount stays
		// truthful even in that pathological case.
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

	/// <summary>Frees the underlying unmanaged buffer. Safe to call multiple times.</summary>
	public void Dispose()
	{
		if (Interlocked.Exchange(ref _disposed, 1) == 0)
		{
			_ringBuffer.Dispose();
		}
	}
}
