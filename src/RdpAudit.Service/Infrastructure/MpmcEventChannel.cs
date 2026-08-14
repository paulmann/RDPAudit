/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 2.0.0
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
	private int _disposed;

	// ── Construction ─────────────────────────────────────────────────────────────

	/// <summary>Total slots. Equals the underlying ring capacity (always power of two).</summary>
	public int Capacity => (int)_ringBuffer.Capacity;

	/// <summary>DropOldest evictions since construction. Read via
	/// <see cref="Interlocked.Read(ref long)"/> semantics; never decreases.</summary>
	public long OverflowCount => _ringBuffer.OverflowCount;

	/// <summary>Builds a ring with <paramref name="capacity"/> slots. Must be a strictly
	/// positive power of two (validated by the underlying buffer).</summary>
	public MpmcEventChannel(int capacity = 1024)
	{
		_ringBuffer = new UnmanagedMpmcRingBuffer(capacity);
	}

	// ── Public API ───────────────────────────────────────────────────────────────

	/// <summary>
	/// Enqueue a DTO. Returns <see langword="true"/> on a clean write, <see langword="false"/>
	/// when the write forced a DropOldest eviction (the DTO still landed). Never blocks and
	/// never allocates on the managed heap.
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
		// DropOldest budget we want (bounded by the ring capacity per producer thanks to
		// the underlying spin budget). Bound the outer retry as well so a pathological
		// case (e.g. every eviction lost to a fresh producer race) still terminates.
		int retries = _ringBuffer.Capacity switch
		{
			<= 0 => 0,
			var cap => (int)Math.Min(cap, 64),
		};

		for (int i = 0; i < retries; i++)
		{
			_ringBuffer.TryEvictOldest();
			if (_ringBuffer.TryWrite(payload))
			{
				return false;
			}
		}

		// Genuine failure: unable to publish despite eviction attempts. This is a hard
		// drop with no counter increment (the eviction path already incremented for each
		// successful eviction along the way). Callers may treat this as a data-loss
		// warning distinct from ordinary DropOldest.
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
