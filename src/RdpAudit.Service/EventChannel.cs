/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 2.1.0
// File   : EventChannel.cs
// Project: RdpAudit.Service (RdpAudit.Service)
// Purpose: Composition root that picks the concrete IRawEventBackend (SPSC or MPMC)
//          based on RdpAuditOptions.Monitoring.RingBufferBackend and exposes it as a
//          singleton to RingBufferEventPipe.
// Depends: IOptions<RdpAuditOptions>, RingBufferEventChannel, MpmcEventChannel
// Extends: When adding a new backend flavour, extend the switch in the constructor and
//          add a matching enum member to RingBufferBackend.

using System;
using Microsoft.Extensions.Options;
using RdpAudit.Core.Config;
using RdpAudit.Service.Infrastructure;

namespace RdpAudit.Service;

/// <summary>
/// Zero-allocation lock-free event pipe bridging every producer worker
/// (EventCollectorHostedWorker, SecurityBackfillWorker, TerminalServicesBackfillWorker,
/// and the ETW event sources in v2.0 hybrid mode) to the consumer
/// (EventProcessorWorker). The concrete backend is picked at composition time from
/// <see cref="MonitoringOptions.RingBufferBackend"/>: SPSC when a single-producer
/// deployment is guaranteed, MPMC (Vyukov) when multiple producers write concurrently.
/// The bounded ring internally enforces a DropOldest policy so a runaway log spike
/// never blocks the source callbacks.
/// </summary>
public sealed class EventChannel
{
	/// <summary>Live backend. Adapter surface for <see cref="RingBufferEventPipe"/>.</summary>
	public IRawEventBackend Backend { get; }

	/// <summary>Backwards-compatible accessor for callers still expecting the SPSC channel
	/// concretely. Throws when the configured backend is MPMC; migrate call sites to
	/// <see cref="Backend"/> when they no longer require the SPSC-only API.</summary>
	public RingBufferEventChannel Channel =>
		Backend as RingBufferEventChannel
			?? throw new InvalidOperationException(
				"Configured backend is not RingBufferEventChannel. Consume EventChannel.Backend instead.");

	public EventChannel(IOptions<RdpAuditOptions> options)
	{
		ArgumentNullException.ThrowIfNull(options);

		int requestedCapacity = Math.Max(1_000, options.Value.Monitoring.ChannelCapacity);
		int actualCapacity = GetNextPowerOfTwo(requestedCapacity);

		Backend = options.Value.Monitoring.RingBufferBackend switch
		{
			RingBufferBackend.Mpmc => new MpmcEventChannel(actualCapacity),
			_ => new RingBufferEventChannel(actualCapacity),
		};
	}

	/// <summary>
	/// Rounds up to the next power of two. The underlying ring buffers require power-of-two
	/// capacities for O(1) modulo arithmetic via bitmasking.
	/// </summary>
	private static int GetNextPowerOfTwo(int value)
	{
		if (value <= 0) return 1;
		value--;
		value |= value >> 1;
		value |= value >> 2;
		value |= value >> 4;
		value |= value >> 8;
		value |= value >> 16;
		value++;
		return value;
	}
}
