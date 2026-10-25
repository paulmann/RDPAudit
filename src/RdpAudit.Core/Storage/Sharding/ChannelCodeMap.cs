/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 2.0.0
// File   : ChannelCodeMap.cs
// Project: RdpAudit.Core (RdpAudit.Core.Storage.Sharding)
// Purpose: Converts canonical event channel names into compact shard channel codes.
// Depends: EventCatalog, ChannelCode
// Extends: Add a case when EventCatalog exposes a newly shardable channel.

using RdpAudit.Core.Events;

namespace RdpAudit.Core.Storage.Sharding;

/// <summary>Maps monitored Event Log channel names to their compact persisted codes.</summary>
public static class ChannelCodeMap
{
	/// <summary>Returns the persisted code for <paramref name="channel"/>, or Unknown when unsupported.</summary>
	public static ChannelCode FromChannelName(string? channel)
	{
		if (channel is null)
		{
			return ChannelCode.Unknown;
		}

		return channel switch
		{
			_ when string.Equals(channel, EventCatalog.ChannelSecurity, StringComparison.OrdinalIgnoreCase) => ChannelCode.Security,
			_ when string.Equals(channel, EventCatalog.ChannelTsLocal, StringComparison.OrdinalIgnoreCase) => ChannelCode.TsLocal,
			_ when string.Equals(channel, EventCatalog.ChannelTsRemote, StringComparison.OrdinalIgnoreCase) => ChannelCode.TsRemote,
			_ when string.Equals(channel, EventCatalog.ChannelRdpCore, StringComparison.OrdinalIgnoreCase) => ChannelCode.RdpCore,
			_ when string.Equals(channel, EventCatalog.ChannelTsGateway, StringComparison.OrdinalIgnoreCase) => ChannelCode.TsGateway,
			_ when string.Equals(channel, EventCatalog.ChannelTsClient, StringComparison.OrdinalIgnoreCase) => ChannelCode.TsClient,
			_ when string.Equals(channel, EventCatalog.ChannelSystem, StringComparison.OrdinalIgnoreCase) => ChannelCode.System,
			_ => ChannelCode.Unknown,
		};
	}
}
