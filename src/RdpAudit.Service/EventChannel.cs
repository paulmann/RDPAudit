// File:    src/RdpAudit.Service/EventChannel.cs
// Module:  RdpAudit.Service
// Purpose: Bounded Channel{T} bridging EventCollectorWorker writers to EventProcessorWorker reader.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System.Threading.Channels;
using Microsoft.Extensions.Options;
using RdpAudit.Core.Config;
using RdpAudit.Core.Events;

namespace RdpAudit.Service;

/// <summary>
/// Bounded <see cref="Channel{T}"/> bridging the EventCollectorWorker writers to the
/// EventProcessorWorker reader.  Configured with <see cref="BoundedChannelFullMode.DropOldest"/>
/// so a runaway log spike never blocks the EventLogWatcher callback.
/// </summary>
public sealed class EventChannel
{
	public Channel<RawEventDto> Channel { get; }

	public EventChannel(IOptions<RdpAuditOptions> options)
	{
		int capacity = Math.Max(1_000, options.Value.Monitoring.ChannelCapacity);
		Channel = System.Threading.Channels.Channel.CreateBounded<RawEventDto>(
			new BoundedChannelOptions(capacity)
			{
				FullMode = BoundedChannelFullMode.DropOldest,
				SingleReader = true,
				SingleWriter = false,
			});
	}
}
