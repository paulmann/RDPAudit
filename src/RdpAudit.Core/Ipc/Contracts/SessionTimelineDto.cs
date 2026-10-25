// File:    src/RdpAudit.Core/Ipc/Contracts/SessionTimelineDto.cs
// Module:  RdpAudit.Core.Ipc.Contracts
// Purpose: Request/response shapes for the Session Map timeline queries (Backlog #6).
//          GetSessionTimelineRequest selects one connection fact and its activity cap;
//          SessionTimelineDto carries the ordered lifecycle + process/file/other event nodes
//          rendered by the Configurator's Session Map tab. MessagePack keys are append-only.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using MessagePack;
using RdpAudit.Core.Sessions;

namespace RdpAudit.Core.Ipc.Contracts;

/// <summary>Request payload for <c>GetSessionTimeline</c>.</summary>
[MessagePackObject(keyAsPropertyName: false)]
public sealed class GetSessionTimelineRequest
{
	/// <summary>Surrogate row id of the RdpConnectionFact session to load.</summary>
	[Key(0)]
	public long SessionId { get; set; }

	/// <summary>Requested cap on activity event nodes; 0 means the service default
	/// (<see cref="SessionTimelineBuilder.DefaultActivityCap"/>). Clamped to 50..2000 server-side.</summary>
	[Key(1)]
	public int ActivityCap { get; set; }

	/// <summary>True to include events classified as Other (not process/file); hidden by default.</summary>
	[Key(2)]
	public bool IncludeOtherEvents { get; set; }
}

/// <summary>One ordered node of a session's timeline: lifecycle phase or an observed event.</summary>
[MessagePackObject(keyAsPropertyName: false)]
public sealed class SessionTimelineEventDto
{
	/// <summary>UTC timestamp of the node, already normalized to UTC by the builder.</summary>
	[Key(0)]
	public DateTime TimeUtc { get; set; }

	/// <summary>Kind of the node: LogonStart / Connected / Reconnected / Disconnected / Logoff /
	/// Process / File / Other.</summary>
	[Key(1)]
	public SessionTimelineEventKind Kind { get; set; }

	/// <summary>Originating Windows event id for RawEvent-derived nodes; 0 for lifecycle nodes.</summary>
	[Key(2)]
	public int EventId { get; set; }

	/// <summary>Channel (Security / TerminalServices / …) the node came from; empty for lifecycle.</summary>
	[Key(3)]
	public string Channel { get; set; } = string.Empty;

	/// <summary>How the node was attached to this session: Lifecycle, LogonId, SessionId or UserWindow.</summary>
	[Key(4)]
	public SessionTimelineCorrelationMethod CorrelationMethod { get; set; }

	/// <summary>Process name for Process nodes, else null.</summary>
	[Key(5)]
	public string? ProcessName { get; set; }

	/// <summary>Command line for Process nodes, else null.</summary>
	[Key(6)]
	public string? CommandLine { get; set; }

	/// <summary>Object name for File nodes, else null.</summary>
	[Key(7)]
	public string? ObjectName { get; set; }

	/// <summary>Access mask for File nodes, else null.</summary>
	[Key(8)]
	public string? AccessMask { get; set; }

	/// <summary>Event status code text, else null.</summary>
	[Key(9)]
	public string? Status { get; set; }

	/// <summary>Raw event detail text. Populated only when the service DEBUG mode is enabled.</summary>
	[Key(10)]
	public string? Details { get; set; }
}

/// <summary>Response payload for <c>GetSessionTimeline</c>.</summary>
[MessagePackObject(keyAsPropertyName: false)]
public sealed class SessionTimelineDto
{
	/// <summary>Outcome of the query. InvalidRequest when the session id is unknown.</summary>
	[Key(0)]
	public IpcResultStatus Status { get; set; } = IpcResultStatus.Success;

	/// <summary>UTC timestamp at which the snapshot was produced.</summary>
	[Key(1)]
	public DateTime QueriedUtc { get; set; }

	/// <summary>Surrogate row id of the session fact.</summary>
	[Key(2)]
	public long SessionId { get; set; }

	/// <summary>Source IP observed for this connection, always a parseable IPv4/IPv6.</summary>
	[Key(3)]
	public string Ip { get; set; } = string.Empty;

	/// <summary>User name observed on the fact.</summary>
	[Key(4)]
	public string? UserName { get; set; }

	/// <summary>Domain observed on the fact.</summary>
	[Key(5)]
	public string? Domain { get; set; }

	/// <summary>Windows Terminal Services session id, when known.</summary>
	[Key(6)]
	public int? WtsSessionId { get; set; }

	/// <summary>Windows TargetLogonId/SubjectLogonId, when known.</summary>
	[Key(7)]
	public string? LogonId { get; set; }

	/// <summary>Start of the session (first observed logon phase), used as the Gantt axis origin.</summary>
	[Key(8)]
	public DateTime StartUtc { get; set; }

	/// <summary>End of the session; null while the fact is still active.</summary>
	[Key(9)]
	public DateTime? EndUtc { get; set; }

	/// <summary>True when the underlying fact is still active (no logoff observed).</summary>
	[Key(10)]
	public bool IsActive { get; set; }

	/// <summary>Duration of the session in seconds (to EndUtc or to now when active).</summary>
	[Key(11)]
	public long DurationSeconds { get; set; }

	/// <summary>Ordered event nodes (chronological, stable).</summary>
	[Key(12)]
	public List<SessionTimelineEventDto> Events { get; set; } = new();

	/// <summary>Total activity rows that matched the correlation filter before the cap.</summary>
	[Key(13)]
	public int TotalMatching { get; set; }

	/// <summary>True when more rows matched than the applied cap, so the timeline is truncated.</summary>
	[Key(14)]
	public bool Truncated { get; set; }

	/// <summary>The activity cap the service actually applied (50..2000).</summary>
	[Key(15)]
	public int AppliedCap { get; set; }

	/// <summary>Operator-facing message; never carries secret material.</summary>
	[Key(16)]
	public string? Message { get; set; }
}
