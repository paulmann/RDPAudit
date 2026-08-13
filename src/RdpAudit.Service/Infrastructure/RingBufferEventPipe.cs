/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 2.0.0
// File   : RingBufferEventPipe.cs
// Project: RdpAudit.Service (RdpAudit.Service.Infrastructure)
// Purpose: v1.0-compatible IEventPipe adapter that forwards TryWrite/TryRead into the
//          existing zero-allocation UnmanagedSpscRingBuffer through the already-shipped
//          EventChannel wrapper. Introducing this thin adapter lets DI wire Collectors and
//          the Processor against IEventPipe without touching a single line of the ring-buffer
//          hot path, and lets tests plug a lightweight in-memory pipe.
// Depends: IEventPipe, EventChannel, RingBufferEventChannel, RawEventDto
// Extends: When a v2 transport ships (MPMC ring, shared-memory), add a sibling implementation
//          (e.g. MpmcRingBufferEventPipe) that satisfies IEventPipe. Do NOT extend this class
//          — it is intentionally the smallest possible bridge to today's transport.

using System.Runtime.CompilerServices;
using RdpAudit.Core.Events;

namespace RdpAudit.Service.Infrastructure;

/// <summary>
/// Zero-allocation <see cref="IEventPipe"/> adapter over the existing
/// <see cref="RingBufferEventChannel"/>. Forwarding is inlined so DI's virtual dispatch never
/// shows up on the hot path.
/// <para>
/// <see cref="WaitToReadAsync"/> uses a bounded polling loop backed by a small prefetch slot
/// so the underlying ring — which exposes only <c>TryRead</c> — can honour a "do we have
/// something?" question without consuming the event. The prefetch slot is single-reader by
/// contract (EventProcessorWorker is the only consumer), matching the ring buffer's SPSC
/// invariant. A follow-up iteration can drop the poll once the ring exposes a semaphore.
/// </para>
/// </summary>
public sealed class RingBufferEventPipe : IEventPipe
{
	// ── Fields & DI ──────────────────────────────────────────────────────────────

	private const int PollIntervalMs = 5;

	private readonly RingBufferEventChannel _ring;

	// Prefetch slot: filled by WaitToReadAsync when it needs to answer "is there data?".
	// The next TryRead returns this slot first, so the DTO is not consumed twice. Single-reader
	// contract keeps this field safe without a lock: only the consumer thread ever touches it.
	private bool _hasPrefetch;
	private RawEventDto _prefetch;

	// ── Construction ─────────────────────────────────────────────────────────────

	/// <summary>Adapt an <see cref="EventChannel"/> composition root into an
	/// <see cref="IEventPipe"/>. The <paramref name="channel"/> must already be wired to a
	/// power-of-two-sized ring — <see cref="EventChannel"/> guarantees this.</summary>
	public RingBufferEventPipe(EventChannel channel)
	{
		ArgumentNullException.ThrowIfNull(channel);
		_ring = channel.Channel;
	}

	/// <summary>Testing / advanced constructor that binds to an already-built ring.</summary>
	public RingBufferEventPipe(RingBufferEventChannel ring)
	{
		ArgumentNullException.ThrowIfNull(ring);
		_ring = ring;
	}

	// ── Public API ───────────────────────────────────────────────────────────────

	/// <inheritdoc />
	public int Capacity => _ring.Capacity;

	/// <inheritdoc />
	public long OverflowCount => _ring.OverflowCount;

	/// <inheritdoc />
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public bool TryWrite(RawEventDto dto) => _ring.TryWrite(dto);

	/// <inheritdoc />
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public bool TryRead(out RawEventDto dto)
	{
		if (_hasPrefetch)
		{
			dto = _prefetch;
			_prefetch = default!;
			_hasPrefetch = false;
			return true;
		}

		return _ring.TryRead(out dto);
	}

	/// <inheritdoc />
	public async ValueTask<bool> WaitToReadAsync(TimeSpan timeout, CancellationToken ct)
	{
		// Fast path: prefetch is loaded or the ring has data ready right now.
		if (_hasPrefetch)
		{
			return true;
		}

		if (_ring.TryRead(out RawEventDto first))
		{
			_prefetch = first;
			_hasPrefetch = true;
			return true;
		}

		// A negative timespan means "wait forever" per the interface contract; we still poll
		// so cancellation stays responsive.
		bool infinite = timeout < TimeSpan.Zero;
		long deadlineTicks = infinite
			? long.MaxValue
			: Environment.TickCount64 + (long)timeout.TotalMilliseconds;

		while (!ct.IsCancellationRequested)
		{
			if (_ring.TryRead(out RawEventDto dto))
			{
				_prefetch = dto;
				_hasPrefetch = true;
				return true;
			}

			if (!infinite && Environment.TickCount64 >= deadlineTicks)
			{
				return false;
			}

			try
			{
				await Task.Delay(PollIntervalMs, ct).ConfigureAwait(false);
			}
			catch (OperationCanceledException)
			{
				return false;
			}
		}

		return false;
	}
}
