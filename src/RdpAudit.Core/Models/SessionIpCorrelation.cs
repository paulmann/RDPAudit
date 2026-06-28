// File:    src/RdpAudit.Core/Models/SessionIpCorrelation.cs
// Module:  RdpAudit.Core.Models
// Purpose: Durable session-to-IP correlation fact. Persists the IP observed for a given
//          LogonId / (WtsSessionId, UserName) / UserName so the Remote RDP Clients view and
//          the in-memory correlation cache can resolve source IPs across service restarts
//          without re-mining 24h of RawEvents on every query.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

namespace RdpAudit.Core.Models;

/// <summary>
/// Durable session-to-IP correlation fact. One row per unique correlation key the service has
/// observed; <see cref="LastSeenUtc"/> is refreshed whenever the same key reappears so the row
/// keeps a sliding-window recency signal without growing rowcount.
/// </summary>
public sealed class SessionIpCorrelation
{
	public long Id { get; set; }

	/// <summary>Windows TargetLogonId/SubjectLogonId, normalised to its on-the-wire form
	/// ("0x1a2b3c" or decimal). May be null when no LogonId was present on the seeding event
	/// (e.g. some TS-RCM / TS-LSM channel rows expose only WtsSessionId).</summary>
	public string? LogonId { get; set; }

	/// <summary>Windows Terminal Services session id, when known.</summary>
	public int? WtsSessionId { get; set; }

	public string? UserName { get; set; }

	/// <summary>Optional account domain. Some channels (TS-LSM 21, TS-RCM 1149) do not expose a
	/// domain field; in that case the column stays null.</summary>
	public string? Domain { get; set; }

	/// <summary>The IP address observed for this correlation key. Always a parseable IPv4 or IPv6
	/// address — hostnames are rejected upstream by <c>PerEventIpResolver</c>.</summary>
	public string Ip { get; set; } = string.Empty;

	public DateTime FirstSeenUtc { get; set; }

	public DateTime LastSeenUtc { get; set; }

	/// <summary>Comma-separated, ascending, deduplicated list of source EventIds that have updated
	/// this row. Compact (≤128 chars) so the column stays cheap; rows that overflow the budget keep
	/// only the most recent ids.</summary>
	public string? ObservedEventIds { get; set; }

	/// <summary>True when at least one of the observations came from a direct-IP event (the event
	/// payload itself carried the IP). False when the row was created by a derived-IP event only.</summary>
	public bool IsDirectObservation { get; set; }
}
