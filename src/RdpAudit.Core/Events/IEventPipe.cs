/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 2.0.0
// File   : IEventPipe.cs
// Project: RdpAudit.Core (RdpAudit.Core.Events)
// Purpose: Zero-allocation, single-writer-or-multi-writer conduit that decouples the producer
//          (IEventSource / EventCollectorWorker) from the consumer (EventProcessorWorker).
//          Abstracting the pipe behind an interface lets v2.0 swap the underlying transport
//          — today an SPSC ring buffer, tomorrow an MPMC ring buffer with cache-line padding,
//          without touching a single Worker.
// Depends: RawEventDto
// Extends: When adding a new transport (e.g. MPMC ring, cross-process shared memory), create
//          another IEventPipe implementation; do NOT extend this interface with transport-
//          specific knobs. Keep the hot-path surface (TryWrite/TryRead/WaitToReadAsync) small
//          and allocation-free.

namespace RdpAudit.Core.Events;

/// <summary>
/// High-throughput, zero-allocation pipe carrying <see cref="RawEventDto"/> instances from one
/// or more producers to a single consumer. Implementations MUST:
/// <list type="bullet">
///   <item>expose a synchronous <see cref="TryWrite"/> hot-path with no heap allocations,</item>
///   <item>expose a synchronous <see cref="TryRead"/> hot-path with no heap allocations,</item>
///   <item>provide a bounded-timeout <see cref="WaitToReadAsync"/> that avoids CPU spin,</item>
///   <item>expose <see cref="Capacity"/> and <see cref="OverflowCount"/> for observability,</item>
///   <item>implement a bounded DropOldest policy — a burst never blocks a producer.</item>
/// </list>
/// Callers are free to keep a strongly-typed reference to a concrete implementation for
/// ultra-hot loops; this interface exists so DI composition, tests, and v2.0 transport swaps
/// remain trivial.
/// </summary>
public interface IEventPipe
{
	/// <summary>Total number of DTO slots the pipe can hold before DropOldest kicks in.</summary>
	int Capacity { get; }

	/// <summary>
	/// Monotonic count of DTOs that were dropped because the pipe was full at write time.
	/// Read with <see cref="System.Threading.Interlocked"/>.Read semantics — the
	/// value never decreases and never wraps.
	/// </summary>
	long OverflowCount { get; }

	/// <summary>
	/// Attempts to enqueue <paramref name="dto"/>. Returns <see langword="true"/> when the DTO
	/// occupied a fresh slot, <see langword="false"/> when the DTO landed but pushed out the
	/// oldest slot (<see cref="OverflowCount"/> is incremented). MUST NOT allocate on the
	/// managed heap and MUST NOT block.
	/// </summary>
	bool TryWrite(RawEventDto dto);

	/// <summary>
	/// Attempts to dequeue one DTO. Returns <see langword="true"/> and populates
	/// <paramref name="dto"/> when a slot was available, <see langword="false"/> otherwise.
	/// MUST NOT allocate on the managed heap and MUST NOT block.
	/// </summary>
	bool TryRead(out RawEventDto dto);

	/// <summary>
	/// Awaits until at least one DTO becomes available or <paramref name="timeout"/> elapses.
	/// The returned <see langword="true"/> is a hint — a follow-up <see cref="TryRead"/> may
	/// still race and lose. Implementations SHOULD use a cheap semaphore/wait-handle rather
	/// than a raw <see cref="System.Threading.Tasks.Task.Delay(int)"/> spin.
	/// </summary>
	/// <param name="timeout">Maximum time to await before giving up. A negative timespan
	/// disables the timeout entirely (wait forever).</param>
	/// <param name="ct">Cancellation token honored during the wait.</param>
	/// <returns><see langword="true"/> if the pipe is (or was) non-empty during the wait,
	/// <see langword="false"/> when the timeout elapsed with no data.</returns>
	ValueTask<bool> WaitToReadAsync(TimeSpan timeout, CancellationToken ct);
}
