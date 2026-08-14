/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 2.0.0
// File   : IRawEventBackend.cs
// Project: RdpAudit.Service (RdpAudit.Service.Infrastructure)
// Purpose: Common contract shared by RingBufferEventChannel (SPSC) and MpmcEventChannel
//          (MPMC) so RingBufferEventPipe and EventChannel can pick a backend by config
//          without duplicating the adapter code.
// Depends: RawEventDto
// Extends: When adding a new backend flavour (e.g. shared-memory ring), implement this
//          interface and register it in the EventChannel composition root.

using RdpAudit.Core.Events;

namespace RdpAudit.Service.Infrastructure;

/// <summary>
/// Backend-agnostic surface of the event pipe. Implementations MUST provide
/// zero-allocation, non-blocking <see cref="TryWrite"/> and <see cref="TryRead"/>,
/// track DropOldest via <see cref="OverflowCount"/>, and be safe to dispose.
/// </summary>
public interface IRawEventBackend : IDisposable
{
	/// <summary>Total slot count. Always a power of two.</summary>
	int Capacity { get; }

	/// <summary>Monotonic count of DropOldest evictions. Never decreases.</summary>
	long OverflowCount { get; }

	/// <summary>Enqueue one DTO. See implementation docs for DropOldest semantics.</summary>
	bool TryWrite(RawEventDto dto);

	/// <summary>Dequeue one DTO or return <see langword="false"/> when empty.</summary>
	bool TryRead(out RawEventDto dto);
}
