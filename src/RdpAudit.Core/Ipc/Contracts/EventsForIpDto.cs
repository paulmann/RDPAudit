// File:    src/RdpAudit.Core/Ipc/Contracts/EventsForIpDto.cs
// Module:  RdpAudit.Core.Ipc.Contracts
// Purpose: Response payload for GetEventsForIp. Carries bounded recent / full-for-IP RawEvents
//          plus summary metadata that the Configurator pastes into the export header.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using MessagePack;

namespace RdpAudit.Core.Ipc.Contracts;

/// <summary>Single RawEvent projection returned by <c>GetEventsForIp</c>.</summary>
[MessagePackObject(keyAsPropertyName: false)]
public sealed class IpEventEntryDto
{
	[Key(0)]
	public long Id { get; set; }

	[Key(1)]
	public DateTime TimeUtc { get; set; }

	[Key(2)]
	public int EventId { get; set; }

	[Key(3)]
	public string? Channel { get; set; }

	[Key(4)]
	public string? UserName { get; set; }

	[Key(5)]
	public string? Domain { get; set; }

	[Key(6)]
	public int? LogonType { get; set; }

	[Key(7)]
	public string? AuthPackage { get; set; }

	[Key(8)]
	public string? ProcessName { get; set; }

	[Key(9)]
	public string? Status { get; set; }
}

/// <summary>Summary metadata for the IP plus the bounded RawEvents window.</summary>
[MessagePackObject(keyAsPropertyName: false)]
public sealed class EventsForIpDto
{
	/// <summary>Controlled-result status.</summary>
	[Key(0)]
	public IpcResultStatus Status { get; set; } = IpcResultStatus.Success;

	/// <summary>Canonical IP literal echoed from the request.</summary>
	[Key(1)]
	public string Ip { get; set; } = string.Empty;

	/// <summary>UTC timestamp of the first observed RawEvent for this IP; <c>null</c> when no events exist.</summary>
	[Key(2)]
	public DateTime? FirstSeenUtc { get; set; }

	/// <summary>UTC timestamp of the most recent observed RawEvent for this IP; <c>null</c> when no events exist.</summary>
	[Key(3)]
	public DateTime? LastSeenUtc { get; set; }

	/// <summary>Failed-logon count across the full RawEvents history for this IP.</summary>
	[Key(4)]
	public long FailedCount { get; set; }

	/// <summary>Successful-logon count across the full RawEvents history for this IP.</summary>
	[Key(5)]
	public long SuccessCount { get; set; }

	/// <summary>Total RawEvents recorded for this IP (failed + successful + other).</summary>
	[Key(6)]
	public long TotalEvents { get; set; }

	/// <summary>Active-window duration in whole seconds (LastSeenUtc − FirstSeenUtc); <c>0</c> when no events exist.</summary>
	[Key(7)]
	public long DurationSeconds { get; set; }

	/// <summary>Up to 20 distinct user names attempted from this IP, most recent first.</summary>
	[Key(8)]
	public List<string> AttemptedUserNames { get; set; } = new();

	/// <summary>Attack-class label projected from <c>AttackStats</c> when available (e.g. <c>"BruteForce"</c>); empty when not classified yet.</summary>
	[Key(9)]
	public string AttackType { get; set; } = string.Empty;

	/// <summary>Threat level projected from <c>AttackStats</c> when available (<c>Green</c> / <c>Yellow</c> / <c>Red</c>); empty when not classified.</summary>
	[Key(10)]
	public string ThreatLevel { get; set; } = string.Empty;

	/// <summary>True when at least one active firewall block exists for this IP.</summary>
	[Key(11)]
	public bool IsBlocked { get; set; }

	/// <summary>Bounded RawEvents window, newest first; cap defined by the server (default 1000).</summary>
	[Key(12)]
	public List<IpEventEntryDto> Events { get; set; } = new();

	/// <summary>Operator-facing message; never carries secret material.</summary>
	[Key(13)]
	public string? Message { get; set; }

	/// <summary>UTC timestamp of the query that produced this snapshot.</summary>
	[Key(14)]
	public DateTime QueriedUtc { get; set; }
}
