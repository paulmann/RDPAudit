/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 2.0.0
// File   : IEventSource.cs
// Project: RdpAudit.Core (RdpAudit.Core.Events)
// Purpose: Transport-agnostic contract for whatever "produces" RawEventDto instances into an
//          IEventPipe. v1.x lives on EventLogWatcher (EventLogWatcherEventSource). v2.x will
//          add ETW real-time consumers, direct EVTX binary readers, and cross-boundary IPC
//          shims — all behind this one interface, so the rest of the service does not care.
// Depends: IEventPipe, EventSourceStatus, EventSourceStatusChangedEventArgs
// Extends: When adding a new transport (ETW real-time, EVTX file replay, IPC), implement this
//          interface, register it in DI as one more IEventSource instance, and let the multi-
//          source composer fan out to the same IEventPipe. Do NOT add transport-specific
//          methods here — those belong on the concrete class and are configured through DI.

namespace RdpAudit.Core.Events;

/// <summary>
/// One physical producer of Windows security events — an EventLog channel subscription,
/// an ETW real-time session, or a stored EVTX replay. Implementations own the underlying
/// OS handles and are responsible for restarting on failure, tracking bookmarks for
/// exactly-once semantics, and clamping malformed input at the boundary.
/// </summary>
/// <remarks>
/// <para>Lifecycle contract:</para>
/// <list type="number">
///   <item><see cref="StartAsync"/> is called exactly once before events flow. After it
///         returns successfully, <see cref="Status"/> transitions to
///         <see cref="EventSourceStatus.Running"/>.</item>
///   <item>The source pushes every captured event into <see cref="Pipe"/> via
///         <see cref="IEventPipe.TryWrite"/>. Pushing is best-effort — a full pipe drops
///         the oldest slot, not the producer's callback.</item>
///   <item><see cref="StopAsync"/> unhooks all callbacks, disposes handles, and waits for
///         inflight callback threads to drain (bounded by the caller's cancellation token).
///         After it returns, <see cref="Status"/> is <see cref="EventSourceStatus.Stopped"/>.</item>
///   <item><see cref="StatusChanged"/> fires on every state transition. Subscribers MUST
///         return quickly — the event is raised from the source's own dispatch thread.</item>
/// </list>
/// <para>Implementations MUST be safe to construct on non-Windows hosts and MUST refuse to
/// start with a graceful <see cref="EventSourceStatus.Unsupported"/> transition, so unit
/// tests and Linux dev boxes do not crash the host.</para>
/// </remarks>
public interface IEventSource
{
	/// <summary>Stable identifier for this source. For EventLog subscriptions this is the
	/// channel name (e.g. <c>"Security"</c>). For ETW sessions this is the trace name.</summary>
	string Name { get; }

	/// <summary>Downstream pipe every produced DTO is written to. Set at construction time
	/// and never re-bound. Callers rely on this being non-null after construction.</summary>
	IEventPipe Pipe { get; }

	/// <summary>Current lifecycle state. Read is thread-safe via
	/// <see cref="System.Threading.Volatile"/>.Read semantics.</summary>
	EventSourceStatus Status { get; }

	/// <summary>Raised on every state transition. Subscribers MUST NOT block — dispatch
	/// happens from the source's own thread.</summary>
	event EventHandler<EventSourceStatusChangedEventArgs>? StatusChanged;

	/// <summary>
	/// Begins producing events into <see cref="Pipe"/>. Idempotent when the source is already
	/// running — repeated calls return the same completed task. Throws
	/// <see cref="System.InvalidOperationException"/> when called after
	/// <see cref="StopAsync"/>.
	/// </summary>
	/// <param name="ct">Cancellation token honored during startup handshakes (auditpol
	/// verification, watcher subscription, bookmark rehydration).</param>
	Task StartAsync(CancellationToken ct);

	/// <summary>
	/// Stops the source, unhooks callbacks, disposes native handles, and drains inflight
	/// dispatch threads. Idempotent — safe to call on an already-stopped source. The
	/// implementation MUST NOT flush anything to the pipe after this task completes.
	/// </summary>
	Task StopAsync(CancellationToken ct);
}

/// <summary>Lifecycle states for <see cref="IEventSource"/>.</summary>
public enum EventSourceStatus
{
	/// <summary>Constructed but <see cref="IEventSource.StartAsync"/> has not returned.</summary>
	Idle = 0,

	/// <summary>The source is actively producing events into its pipe.</summary>
	Running = 1,

	/// <summary>The source encountered a transient failure and is preparing to restart.
	/// The pipe is unaffected — the consumer keeps draining any already-buffered DTOs.</summary>
	Restarting = 2,

	/// <summary>The source has been stopped and released its OS handles.</summary>
	Stopped = 3,

	/// <summary>The source cannot run on this OS (e.g. EventLog on Linux) and is a no-op.
	/// This state is terminal — a subsequent <see cref="IEventSource.StartAsync"/> is a
	/// no-op that keeps the source in <see cref="Unsupported"/>.</summary>
	Unsupported = 4,

	/// <summary>The source hit an unrecoverable failure and gave up. This state is terminal
	/// and requires a service restart or configuration change to recover.</summary>
	Faulted = 5,
}

/// <summary>Payload for <see cref="IEventSource.StatusChanged"/>.</summary>
public sealed class EventSourceStatusChangedEventArgs : EventArgs
{
	/// <summary>Previous state before the transition.</summary>
	public EventSourceStatus Previous { get; }

	/// <summary>New state after the transition.</summary>
	public EventSourceStatus Current { get; }

	/// <summary>Optional human-readable reason (e.g. exception summary on Faulted). Never
	/// contains sensitive data — safe to log at Information level.</summary>
	public string? Reason { get; }

	/// <summary>UTC timestamp of the transition. Recorded at construction time so subscribers
	/// see the same instant even if dispatch is deferred.</summary>
	public DateTime TimestampUtc { get; }

	public EventSourceStatusChangedEventArgs(
		EventSourceStatus previous,
		EventSourceStatus current,
		string? reason = null)
	{
		Previous = previous;
		Current = current;
		Reason = reason;
		TimestampUtc = DateTime.UtcNow;
	}
}
