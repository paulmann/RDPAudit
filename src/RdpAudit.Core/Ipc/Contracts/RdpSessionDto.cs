// File:    src/RdpAudit.Core/Ipc/Contracts/RdpSessionDto.cs
// Module:  RdpAudit.Core.Ipc.Contracts
// Purpose: DTO describing a live RDP session for the ListRdpSessions IPC command.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using MessagePack;

namespace RdpAudit.Core.Ipc.Contracts;

/// <summary>DTO describing a live RDP session.</summary>
[MessagePackObject(keyAsPropertyName: false)]
public sealed class RdpSessionDto
{
	[Key(0)]
	public int SessionId { get; set; }

	[Key(1)]
	public string UserName { get; set; } = string.Empty;

	[Key(2)]
	public string? Domain { get; set; }

	[Key(3)]
	public string? ClientName { get; set; }

	[Key(4)]
	public string? ClientAddress { get; set; }

	/// <summary>WTS session state expressed as a stable string (Active, Disconnected, Idle, ...).</summary>
	[Key(5)]
	public string State { get; set; } = string.Empty;

	[Key(6)]
	public DateTime? ConnectTimeUtc { get; set; }

	[Key(7)]
	public DateTime? LastInputTimeUtc { get; set; }

	/// <summary>Station / WinStation name reported by qwinsta (e.g. "rdp-tcp#3", "console").</summary>
	[Key(8)]
	public string? SessionName { get; set; }

	/// <summary>v1.3.8 — operator-visible "Current?" flag: true only when this session belongs to
	/// the user running the Configurator. It is decided by <c>CurrentRdpSessionMatcher</c> in the
	/// operator's interactive process (the LocalSystem service cannot know which session the
	/// operator uses), correlating the running process SessionId with the normalized current Windows
	/// identity. The mapper leaves it false; only the matcher sets it. Do NOT conflate with
	/// <see cref="IsActiveRdp"/> (any active rdp-tcp# session of any user).</summary>
	[Key(9)]
	public bool IsCurrent { get; set; }

	/// <summary>True when the session row is currently in an active connected state.</summary>
	[Key(10)]
	public bool IsActive { get; set; }

	/// <summary>True when the session is in a disconnected state and may be reconnected.</summary>
	[Key(11)]
	public bool IsDisconnected { get; set; }

	// --- Stage IP-D additions (append-only). Historical context derived from RdpConnectionFacts.
	// These never overwrite live data and are populated only when a matching fact exists.

	/// <summary>Earliest <c>FirstSeenUtc</c> across matching connection facts; null when none exist.</summary>
	[Key(12)]
	public DateTime? HistoricalFirstSeenUtc { get; set; }

	/// <summary>Latest <c>LastSeenUtc</c> across matching connection facts; null when none exist.</summary>
	[Key(13)]
	public DateTime? HistoricalLastSeenUtc { get; set; }

	/// <summary>Sum of failed logons across matching connection facts; zero when no facts exist.</summary>
	[Key(14)]
	public long HistoricalFailedLogons { get; set; }

	/// <summary>Sum of successful logons across matching connection facts; zero when no facts exist.</summary>
	[Key(15)]
	public long HistoricalSuccessfulLogons { get; set; }

	/// <summary>Comma-separated, deduplicated list of usernames attempted from this IP across matching facts. Bounded width.</summary>
	[Key(16)]
	public string? HistoricalUserNamesAttempted { get; set; }

	// --- Stage 2 additions (append-only). Per-IP historical aggregation from RdpConnectionFacts
	// keyed on the resolved session ClientAddress / SourceIp. These never overwrite the user-keyed
	// fields above; they exist so operators can see brute-force pressure originating from the
	// session's source IP regardless of which login each attempt targeted.

	/// <summary>Sum of failed logons across all RdpConnectionFacts that share this session's source IP.
	/// Null when the session has no resolved IP (distinguishes unknown from a real zero).</summary>
	[Key(17)]
	public long? HistoricalFailedLogonsByIp { get; set; }

	/// <summary>Sum of successful logons across all RdpConnectionFacts that share this session's source IP.
	/// Null when the session has no resolved IP.</summary>
	[Key(18)]
	public long? HistoricalSuccessfulLogonsByIp { get; set; }

	/// <summary>Comma-separated, deduplicated list of distinct usernames attempted from this IP across
	/// all matching facts. Bounded width. Null when the session has no resolved IP.</summary>
	[Key(19)]
	public string? HistoricalUsersAttemptedFromIp { get; set; }

	/// <summary>Earliest <c>FirstSeenUtc</c> across all RdpConnectionFacts that share this session's source IP;
	/// null when the session has no resolved IP or no matching facts exist.</summary>
	[Key(20)]
	public DateTime? HistoricalFirstSeenByIpUtc { get; set; }

	/// <summary>Latest <c>LastSeenUtc</c> across all RdpConnectionFacts that share this session's source IP;
	/// null when the session has no resolved IP or no matching facts exist.</summary>
	[Key(21)]
	public DateTime? HistoricalLastSeenByIpUtc { get; set; }

	/// <summary>v1.2.2 — raw <c>&gt;</c> marker emitted by qwinsta for the session the query was
	/// issued from. Under LocalSystem this marker can point at session 0 (services) — never use
	/// it directly for the operator-visible "Current?" column. <see cref="IsActiveRdp"/> carries the
	/// validated active-RDP semantics (Active AND rdp-tcp# AND user AND 1 &lt; SessionId &lt; 65536);
	/// <see cref="IsCurrent"/> is the narrower operator-scoped flag set by <c>CurrentRdpSessionMatcher</c>.</summary>
	[Key(22)]
	public bool IsQueryCurrent { get; set; }

	/// <summary>v1.2.2 — validated operator-visible "active RDP" flag. True when this row is the
	/// session an operator would consider the live remote RDP session — Active state, rdp-tcp#
	/// station name, non-empty user name, and a SessionId strictly greater than 1 and strictly less
	/// than 65536. Distinct from <see cref="IsCurrent"/>, which is the narrower operator-scoped
	/// flag; this one is true for any logged-in user's active RDP session.</summary>
	[Key(23)]
	public bool IsActiveRdp { get; set; }
}

/// <summary>List wrapper for <c>ListRdpSessions</c> so the response carries an operation status.</summary>
[MessagePackObject(keyAsPropertyName: false)]
public sealed class RdpSessionListDto
{
	[Key(0)]
	public IpcResultStatus Status { get; set; } = IpcResultStatus.Success;

	[Key(1)]
	public List<RdpSessionDto> Sessions { get; set; } = new();

	[Key(2)]
	public string? Message { get; set; }

	[Key(3)]
	public DateTime QueriedUtc { get; set; }
}
