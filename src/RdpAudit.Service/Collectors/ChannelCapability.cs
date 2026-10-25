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
	/// <remarks>
	/// A probe that fails for a transient reason is retried once. The first minutes of a service start are
/// the busiest the host ever gets here: the store integrity check runs over a multi-gigabyte database and
	/// saturates the disk, and a 50 ms look-ahead into the channel then expires. Reporting that as a failed
	/// capability probe produced two Error records on every start for channels that arm successfully seconds
	/// later - an error an operator learns to ignore, which is worse than no record at all.
	/// </remarks>
	public static ChannelProbeResult Probe(string channel)
	{
		ArgumentException.ThrowIfNullOrWhiteSpace(channel);

		ChannelProbeResult first = ProbeOnce(channel);
		if (first.IsAvailable || !IsTransientProbeFailure(first.Reason))
		{
			return first;
		}

		Thread.Sleep(TimeSpan.FromMilliseconds(500));
		return ProbeOnce(channel);
	}

	/// <summary>True for the reasons that mean "the host was busy", not "the channel is unusable".</summary>
	private static bool IsTransientProbeFailure(string reason)
		=> reason.Contains("timeout period expired", StringComparison.OrdinalIgnoreCase)
			|| reason.Contains("RPC server is unavailable", StringComparison.OrdinalIgnoreCase);

	private static ChannelProbeResult ProbeOnce(string channel)
	{

		try
		{
			using EventLogSession session = new();
			using EventLogConfiguration config = new(channel, session);
			if (!config.IsEnabled)
			{
				return new ChannelProbeResult(false, "Channel exists but is disabled");
			}

			// A channel that exists and is enabled may still be empty; that is fine. Confirm the log file
			// is materialized by issuing a one-event lookahead query - if Windows reports "channel not
			// found" or "access denied" it will throw here, not later inside the EventLogWatcher
			// callback. The call is deliberately the timeout-less overload: with ReverseDirection it
			// answers at once with the newest record, or with null at end-of-log, whereas the timed
			// overload keeps polling for a NEW event and reports its own wait as a probe failure. On the
			// Security and System channels that produced "This operation returned because the timeout
			// period expired" at every start - a false Error about a channel that arms fine a moment
			// later.
			EventLogQuery query = new(channel, PathType.LogName, "*[System[EventID=0]]")
			{
				ReverseDirection = true,
			};
			using EventLogReader reader = new(query);
			_ = reader.ReadEvent();
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
