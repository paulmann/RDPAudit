/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 2.1.0
// File   : RingBufferEventPipe.cs
// Project: RdpAudit.Service (RdpAudit.Service.Infrastructure)
// Purpose: Zero-allocation IEventPipe adapter over the existing SPSC UnmanagedSpscRingBuffer.
//          Forwards TryWrite/TryRead into RingBufferEventChannel unchanged and replaces the
//          previous 5ms polling loop in WaitToReadAsync with a SemaphoreSlim signal released
//          from TryWrite. The synchronous hot paths remain allocation-free; only the async
//          wait now piggy-backs on the semaphore, eliminating p99 latency-jitter and CPU idle
//          burn on quiet channels.
// Depends: IEventPipe, EventChannel, RingBufferEventChannel, RawEventDto, SemaphoreSlim
// Extends: When a v2 transport ships (MPMC ring, shared memory), add a sibling implementation
//          that satisfies IEventPipe. Keep the semaphore-release call co-located with the
//          concrete TryWrite success path — never leak signal-plumbing into IEventPipe callers.

using System.Runtime.CompilerServices;
using RdpAudit.Core.Events;

namespace RdpAudit.Service.Infrastructure;

/// <summary>
/// Zero-allocation <see cref="IEventPipe"/> adapter over the existing
/// <see cref="RingBufferEventChannel"/>. Forwarding is inlined so DI's virtual dispatch never
/// shows up on the hot path.
/// <para>
/// <see cref="WaitToReadAsync"/> is backed by a bounded <see cref="SemaphoreSlim"/> released on
/// every successful <see cref="TryWrite"/>. The semaphore's <c>maxCount</c> is <c>1</c> — it
/// behaves as a level-triggered "there is (or was) data" signal, which is exactly the
/// <see cref="IEventPipe.WaitToReadAsync"/> contract: the returned <see langword="true"/> is a
/// hint that a follow-up <see cref="TryRead"/> may race and lose. A prefetch slot keeps the
/// consumer's next <see cref="TryRead"/> from double-consuming the DTO the wait already saw.
/// </para>
/// <para>
/// The prefetch slot and the semaphore are both single-reader by contract (the sole consumer is
/// <c>EventProcessorWorker</c>). Producers are multi-writer for the semaphore <see cref="SemaphoreSlim.Release"/>
/// call — <see cref="SemaphoreFullException"/> is swallowed intentionally because the semaphore
/// is at cap already, i.e. the consumer has been notified and just hasn't drained it yet.
/// </para>
/// </summary>
public sealed class RingBufferEventPipe : IEventPipe, IDisposable
{
	// ── Fields & DI ──────────────────────────────────────────────────────────────

	private readonly RingBufferEventChannel _ring;

	// Bounded to 1: one pending "data available" edge is enough to unblock the consumer. Extra
	// writes past a still-unread signal are collapsed via the SemaphoreFullException swallow —
	// the signal is level-triggered by design. initialCount = 0 because a fresh pipe has no data.
	private readonly SemaphoreSlim _signal = new(initialCount: 0, maxCount: 1);

	// Prefetch slot: filled by WaitToReadAsync when it needs to answer "is there data?". The
	// next TryRead returns this slot first, so the DTO is not consumed twice. Single-reader
	// contract keeps this field safe without a lock: only the consumer thread ever touches it.
	private bool _hasPrefetch;
	// Nullable to avoid CS8618 (no ctor initialisation); the `_hasPrefetch` guard is the
	// invariant that keeps every read from observing a null slot. Assignment through
	// null-forgiveness (`!`) is safe under that invariant.
	private RawEventDto? _prefetch;

	private int _disposed;

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
	public bool TryWrite(RawEventDto dto)
	{
		// The concrete ring's contract: returns true on a clean write, false when a DropOldest
		// forced eviction. Either way the DTO landed and a signal is warranted so the consumer
		// wakes up and drains. Signal AFTER the underlying write to preserve happens-before
		// ordering: any thread that observes the semaphore released will also observe the write.
		bool clean = _ring.TryWrite(dto);
		ReleaseSignalSafe();
		return clean;
	}

	/// <inheritdoc />
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public bool TryRead(out RawEventDto dto)
	{
		if (_hasPrefetch)
		{
			dto = _prefetch!; // _hasPrefetch == true implies non-null (see field comment).
			_prefetch = null;
			_hasPrefetch = false;
			return true;
		}

		return _ring.TryRead(out dto);
	}

	/// <inheritdoc />
	public async ValueTask<bool> WaitToReadAsync(TimeSpan timeout, CancellationToken ct)
	{
		// Fast path: prefetch is already loaded — no wait needed.
		if (_hasPrefetch)
		{
			return true;
		}

		// Fast path: the ring already has data. Load a prefetch slot so a subsequent TryRead
		// returns immediately and the caller sees the DTO exactly once.
		if (_ring.TryRead(out RawEventDto first))
		{
			_prefetch = first;
			_hasPrefetch = true;

			// Drain any stale signal so the next wait doesn't spuriously return without data.
			// SemaphoreSlim.Wait(0, ct) is non-blocking; we pass CancellationToken.None on purpose
			// because a zero-millisecond wait completes synchronously and cannot observe cancellation,
			// so forwarding the caller's token here would only muddy CA2016's intent (satisfied).
			_signal.Wait(0, CancellationToken.None);
			return true;
		}

		// Slow path: await the semaphore. A negative timespan means "wait forever" per the
		// IEventPipe contract; SemaphoreSlim.WaitAsync accepts Timeout.InfiniteTimeSpan for the
		// same semantics.
		TimeSpan waitFor = timeout < TimeSpan.Zero ? Timeout.InfiniteTimeSpan : timeout;

		try
		{
			bool acquired = await _signal.WaitAsync(waitFor, ct).ConfigureAwait(false);
			if (!acquired)
			{
				return false;
			}
		}
		catch (OperationCanceledException)
		{
			return false;
		}
		catch (ObjectDisposedException)
		{
			// Pipe is being torn down while a wait was in flight. Report "no data" so the
			// caller unwinds cleanly instead of surfacing a disposal exception.
			return false;
		}

		// Re-check the ring under the signal edge — the writer that released us may have raced
		// with a concurrent reader (there is only one legitimate consumer, but we still treat
		// the semaphore as a hint per the interface contract). Load a prefetch slot when a DTO
		// is actually there so TryRead consumes it once.
		if (_ring.TryRead(out RawEventDto dto))
		{
			_prefetch = dto;
			_hasPrefetch = true;
			return true;
		}

		// The signal was released but the DTO is no longer visible (e.g. drained by a stale
		// consumer). Report "no data" — the interface allows this false-positive by design.
		return false;
	}

	// ── Internal Helpers ─────────────────────────────────────────────────────────

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private void ReleaseSignalSafe()
	{
		// Bounded semaphore: Release throws SemaphoreFullException when the count is already at
		// maxCount = 1. That means "the consumer already knows there is data and just hasn't
		// drained it yet" — collapse the extra edge. Similarly, Release on a disposed semaphore
		// throws ObjectDisposedException during shutdown — also safe to swallow.
		try
		{
			_signal.Release();
		}
		catch (SemaphoreFullException)
		{
			// Level-triggered by design — extra writes past a pending edge are coalesced.
		}
		catch (ObjectDisposedException)
		{
			// Pipe was disposed after a producer had already entered TryWrite. Nothing to do.
		}
	}

	// ── Disposal ─────────────────────────────────────────────────────────────────

	/// <summary>
	/// Disposes the internal signalling primitive. Safe to call multiple times.
	/// The underlying <see cref="RingBufferEventChannel"/> is NOT owned by the pipe —
	/// its lifetime is managed by the composition root (<c>EventChannel</c> singleton in DI).
	/// </summary>
	public void Dispose()
	{
		if (Interlocked.Exchange(ref _disposed, 1) == 0)
		{
			_signal.Dispose();
		}
	}
}
