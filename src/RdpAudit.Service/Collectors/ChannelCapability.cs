// File:    src/RdpAudit.Service/Collectors/ChannelCapability.cs
// Module:  RdpAudit.Service.Collectors
// Purpose: Probes an EventLog channel before arming an EventLogWatcher so an unavailable
//          or disabled channel does not produce an Invalid-Handle restart loop.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System.Diagnostics.Eventing.Reader;
using System.Runtime.Versioning;

namespace RdpAudit.Service.Collectors;

/// <summary>Result of probing a channel for availability.</summary>
public readonly record struct ChannelProbeResult(bool IsAvailable, string Reason);

/// <summary>
/// Probes an EventLog channel before arming an EventLogWatcher. Uses <see cref="EventLogSession"/>
/// to read the channel's <see cref="EventLogConfiguration"/>; a missing or disabled channel returns
/// <see cref="ChannelProbeResult.IsAvailable"/> = <c>false</c> with a human-readable reason.
/// </summary>
[SupportedOSPlatform("windows")]
public static class ChannelCapability
{
	/// <summary>
	/// Probes the named channel on the local host. Returns false if the channel does not exist,
	/// is disabled, or cannot be opened for reading. Never throws.
	/// </summary>
	public static ChannelProbeResult Probe(string channel)
	{
		ArgumentException.ThrowIfNullOrWhiteSpace(channel);

		try
		{
			using EventLogSession session = new();
			using EventLogConfiguration config = new(channel, session);
			if (!config.IsEnabled)
			{
				return new ChannelProbeResult(false, "Channel exists but is disabled");
			}

			// A channel that exists and is enabled may still be empty; that is fine. Confirm the
			// log file is materialized by issuing a one-event lookahead query — if Windows reports
			// "channel not found" or "access denied" it will throw here, not later inside the
			// EventLogWatcher callback.
			EventLogQuery query = new(channel, PathType.LogName, "*[System[EventID=0]]")
			{
				ReverseDirection = true,
			};
			using EventLogReader reader = new(query);
			_ = reader.ReadEvent(TimeSpan.FromMilliseconds(50));
			return new ChannelProbeResult(true, "Channel is enabled and readable");
		}
		catch (UnauthorizedAccessException ex)
		{
			return new ChannelProbeResult(false, "Access denied opening channel: " + ex.Message);
		}
		catch (EventLogNotFoundException ex)
		{
			return new ChannelProbeResult(false, "Channel not found: " + ex.Message);
		}
		catch (EventLogException ex)
		{
			return new ChannelProbeResult(false, "Channel probe failed: " + ex.Message);
		}
	}
}
