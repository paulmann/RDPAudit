// File:    src/RdpAudit.Core/Sessions/SessionTimelineModels.cs
// Module:  RdpAudit.Core.Sessions
// Purpose: Pure models for the per-session timeline feature (Backlog #6): the ordered session
//          timeline itself and the lightweight RawEvent slice the builder consumes. All classes
//          are EF-free and dependency-free so the timeline build stays unit-testable.
// Extends: System.Object
// Author:  RdpAudit Team
// Site:    https://Deynekin.com

namespace RdpAudit.Core.Sessions;

/// <summary>Kind of a timeline node. Lifecycle kinds come from RdpConnectionFact phases;
/// Process / File / Other come from RawEvents correlated into the session window.</summary>
public enum SessionTimelineEventKind
{
	LogonStart = 0,
	Connected = 1,
	Reconnected = 2,
	Disconnected = 3,
	Logoff = 4,
	Process = 5,
	File = 6,
	Other = 7,
}

/// <summary>How a process/file/other node was correlated to the session. Lifecycle nodes are
/// always <see cref="Lifecycle"/> because they derive from the fact itself.</summary>
public enum SessionTimelineCorrelationMethod
{
	Lifecycle = 0,
	LogonId = 1,
	SessionId = 2,
	UserWindow = 3,
}

/// <summary>
/// Lightweight, EF-free slice of one RawEvent row consumed by <see cref="SessionTimelineBuilder"/>.
/// Carries only the fields a timeline node can surface.
/// </summary>
public sealed class SessionTimelineRawEventSlice
{
	public int EventId { get; set; }
	public string Channel { get; set; } = string.Empty;
	public DateTime TimeUtc { get; set; }
	public string? LogonId { get; set; }
	public int? SessionId { get; set; }
	public string? UserName { get; set; }
	public string? Domain { get; set; }
	public string? ProcessName { get; set; }
	public string? CommandLine { get; set; }
	public string? ObjectName { get; set; }
	public string? AccessMask { get; set; }
	public string? Status { get; set; }
	public string? Details { get; set; }
}

/// <summary>One ordered node in the session timeline.</summary>
public sealed class SessionTimelineEvent
{
	public DateTime TimeUtc { get; set; }
	public SessionTimelineEventKind Kind { get; set; }

	/// <summary>Windows event id for RawEvent-derived nodes; 0 for pure lifecycle nodes.</summary>
	public int EventId { get; set; }

	public string Channel { get; set; } = string.Empty;

	/// <summary>How this node was correlated to the session. Lifecycle nodes are Lifecycle.</summary>
	public SessionTimelineCorrelationMethod CorrelationMethod { get; set; }

	public string? ProcessName { get; set; }
	public string? CommandLine { get; set; }
	public string? ObjectName { get; set; }
	public string? AccessMask { get; set; }
	public string? Status { get; set; }

	/// <summary>Raw event detail text; surfaced only when the operator enables DEBUG detail mode.</summary>
	public string? Details { get; set; }
}

/// <summary>
/// Ordered session timeline: lifecycle phases from the connection fact plus bounded
/// process/file/other RawEvents activity, always sorted by <see cref="SessionTimelineEvent.TimeUtc"/>.
/// </summary>
public sealed class SessionTimeline
{
	/// <summary>Session start used as the Gantt axis origin. Never null; a fact with no lifecycle
	/// timestamps falls back to FirstSeenUtc.</summary>
	public DateTime StartUtc { get; set; }

	/// <summary>Session end; null while the fact is still active (no logged-off observation).</summary>
	public DateTime? EndUtc { get; set; }

	public bool IsActive { get; set; }

	public long DurationSeconds { get; set; }

	public List<SessionTimelineEvent> Events { get; set; } = new();

	/// <summary>Total activity rows that matched the correlation filter before the cap was applied.</summary>
	public int TotalMatching { get; set; }

	/// <summary>True when more activity rows matched than the applied cap.</summary>
	public bool Truncated { get; set; }
}
