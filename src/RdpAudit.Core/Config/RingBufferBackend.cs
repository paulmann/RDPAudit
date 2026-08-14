/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 2.0.0
// File   : RingBufferBackend.cs
// Project: RdpAudit.Core (RdpAudit.Core.Config)
// Purpose: Selects the concurrency profile of the event pipe ring buffer.
// Depends: (none)
// Extends: Add a new backend flavour here when a new lock-free transport is introduced.

namespace RdpAudit.Core.Config;

/// <summary>
/// Chooses the concurrency contract of the event pipe ring buffer. The SPSC backend
/// is the historical v1.x transport and is safe only when exactly one producer and
/// exactly one consumer are wired. The MPMC backend is a Vyukov ring buffer safe
/// under any number of producers and consumers; it is the correct choice as soon
/// as ETW ingestion or parallel backfill workers publish events concurrently.
/// </summary>
public enum RingBufferBackend
{
	/// <summary>Single-Producer Single-Consumer. Fastest hot path when the wiring
	/// guarantees exactly one producer and exactly one consumer.</summary>
	Spsc = 0,

	/// <summary>Multi-Producer Multi-Consumer (Vyukov). Correct under any producer
	/// or consumer count. Slightly higher per-op cost than SPSC because each op
	/// runs a CAS on the shared cursor.</summary>
	Mpmc = 1,
}
