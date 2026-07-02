/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 2.0.0

// File:    src/RdpAudit.Service/EventChannel.cs
// Module:  RdpAudit.Service
// Purpose: Zero-allocation Ring Buffer bridging EventCollectorWorker writers to EventProcessorWorker reader.
// Extends: System.Object

using System;
using Microsoft.Extensions.Options;
using RdpAudit.Core.Config;
using RdpAudit.Service.Infrastructure;

namespace RdpAudit.Service;

/// <summary>
/// Zero-allocation lock-free SPSC Ring Buffer bridging the EventCollectorWorker writers to the
/// EventProcessorWorker reader. Replaces System.Threading.Channels to eliminate GC pressure.
/// Internally implements DropOldest policy so a runaway log spike never blocks the EventLogWatcher callback.
/// </summary>
public sealed class EventChannel
{
	public RingBufferEventChannel Channel { get; }

	public EventChannel(IOptions<RdpAuditOptions> options)
	{
		int requestedCapacity = Math.Max(1_000, options.Value.Monitoring.ChannelCapacity);
		
		// The UnmanagedSpscRingBuffer strictly requires a power-of-2 capacity 
		// for O(1) modulo arithmetic via bitmasking.
		int actualCapacity = GetNextPowerOfTwo(requestedCapacity);
		
		Channel = new RingBufferEventChannel(actualCapacity);
	}

	/// <summary>
	/// Calculates the next power of two greater than or equal to the specified value.
	/// Uses bitwise operations for zero-allocation, branchless calculation.
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