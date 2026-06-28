// File:    src/RdpAudit.Core/Models/RdpConnectionFact.cs
// Module:  RdpAudit.Core.Models
// Purpose: Durable, normalized historical fact for one RDP connection — the merged timeline of
//          TS-RCM 1149, TS-LSM 21/22/24/25 and Security 4624/4625 evidence keyed by LogonId or by
//          (WtsSessionId, UserName), enriched with the resolved source IP. Drives historical
//          Remote RDP Clients and Attack Statistics views without needing to re-mine RawEvents.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

namespace RdpAudit.Core.Models;

/// <summary>
/// Durable, normalized RDP connection fact. One row per logical session evidence cluster
/// (LogonId / (WtsSessionId, UserName)). <see cref="LastSeenUtc"/> is refreshed whenever the
/// upserter observes a new event for the same key; the connection-lifecycle timestamps
/// (<see cref="ConnectedUtc"/>, <see cref="AuthenticatedUtc"/>, <see cref="DisconnectedUtc"/>,
/// <see cref="ReconnectedUtc"/>, <see cref="LoggedOffUtc"/>) carry the source-of-truth times for
/// each phase of the connection. <see cref="Ip"/> is always a parseable IPv4 or IPv6 address —
/// hostnames never reach this table.
/// </summary>
public sealed class RdpConnectionFact
{
	public long Id { get; set; }

	/// <summary>IP observed for this connection. Always a parseable IPv4 or IPv6 address.</summary>
	public string Ip { get; set; } = string.Empty;

	public string? UserName { get; set; }

	public string? Domain { get; set; }

	/// <summary>Windows Terminal Services session id, when known.</summary>
	public int? WtsSessionId { get; set; }

	/// <summary>Windows TargetLogonId/SubjectLogonId, normalised to its on-the-wire form
	/// ("0x1a2b3c" or decimal). When non-null, this is the strongest correlation key.</summary>
	public string? LogonId { get; set; }

	public DateTime FirstSeenUtc { get; set; }

	public DateTime LastSeenUtc { get; set; }

	/// <summary>UTC time the session entered an active/connected state (TS-LSM 21, TS-LSM 25 reconnect).</summary>
	public DateTime? ConnectedUtc { get; set; }

	/// <summary>UTC time the connection completed RD Gateway / NLA authentication (TS-RCM 1149, 4624).</summary>
	public DateTime? AuthenticatedUtc { get; set; }

	/// <summary>UTC time the session entered a disconnected state (TS-LSM 24, 4779).</summary>
	public DateTime? DisconnectedUtc { get; set; }

	/// <summary>UTC time the session was reconnected from disconnected state (TS-LSM 25, 4778).</summary>
	public DateTime? ReconnectedUtc { get; set; }

	/// <summary>UTC time the session was logged off or terminated (TS-LSM 23, 4634, 4647).</summary>
	public DateTime? LoggedOffUtc { get; set; }

	/// <summary>Count of failed logon attempts (Security 4625) observed for this Ip/UserName fact.</summary>
	public int FailedLogons { get; set; }

	/// <summary>Count of successful logon attempts (Security 4624 with relevant RDP/remote logon
	/// type) observed for this fact.</summary>
	public int SuccessfulLogons { get; set; }

	/// <summary>Comma-separated, deduplicated list of event ids that have contributed to this fact.
	/// Bounded width — older ids are dropped when the column would overflow.</summary>
	public string? ObservedEventIds { get; set; }

	/// <summary>Comma-separated, deduplicated list of unique usernames attempted from this Ip across
	/// the fact's lifetime. Useful for later Attack Statistics export. Bounded width.</summary>
	public string? UserNamesAttempted { get; set; }

	/// <summary>True when the fact still represents an active/connected session. False when a
	/// disconnect / logoff event has been recorded after the last connect.</summary>
	public bool IsActive { get; set; }
}
