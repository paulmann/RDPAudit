// File:    src/RdpAudit.Core/Ipc/Contracts/ConnectionFactDto.cs
// Module:  RdpAudit.Core.Ipc.Contracts
// Purpose: DTO projection of one RdpConnectionFact row delivered over IPC. Mirrors the normalised
//          historical connection model (IP, user, lifecycle timestamps, counters, active flag) but
//          deliberately omits raw XML payloads so a single fact-list response cannot leak event
//          bodies. MessagePack keys are append-only — never reuse a deleted ordinal.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using MessagePack;

namespace RdpAudit.Core.Ipc.Contracts;

/// <summary>Single <c>RdpConnectionFact</c> projection delivered over IPC.</summary>
[MessagePackObject(keyAsPropertyName: false)]
public sealed class ConnectionFactDto
{
	[Key(0)]
	public long Id { get; set; }

	[Key(1)]
	public string Ip { get; set; } = string.Empty;

	[Key(2)]
	public string? UserName { get; set; }

	[Key(3)]
	public string? Domain { get; set; }

	[Key(4)]
	public int? WtsSessionId { get; set; }

	[Key(5)]
	public string? LogonId { get; set; }

	[Key(6)]
	public DateTime FirstSeenUtc { get; set; }

	[Key(7)]
	public DateTime LastSeenUtc { get; set; }

	[Key(8)]
	public DateTime? ConnectedUtc { get; set; }

	[Key(9)]
	public DateTime? AuthenticatedUtc { get; set; }

	[Key(10)]
	public DateTime? DisconnectedUtc { get; set; }

	[Key(11)]
	public DateTime? ReconnectedUtc { get; set; }

	[Key(12)]
	public DateTime? LoggedOffUtc { get; set; }

	[Key(13)]
	public int FailedLogons { get; set; }

	[Key(14)]
	public int SuccessfulLogons { get; set; }

	/// <summary>Comma-separated, deduplicated list of contributing event ids. Bounded width on disk.</summary>
	[Key(15)]
	public string? ObservedEventIds { get; set; }

	/// <summary>Comma-separated, deduplicated list of usernames attempted from this IP. Bounded width.</summary>
	[Key(16)]
	public string? UserNamesAttempted { get; set; }

	[Key(17)]
	public bool IsActive { get; set; }

	// --- Stage RDP-Diag additions (append-only). Live reportability classification of the remote IP. ---

	/// <summary>Coarse reportability classification of the remote IP (Public / Private / Loopback / …).</summary>
	[Key(18)]
	public string Classification { get; set; } = string.Empty;

	/// <summary>True when the remote IP is a globally routable public address.</summary>
	[Key(19)]
	public bool IsPublic { get; set; }

	/// <summary>True when the remote IP is on the operator whitelist.</summary>
	[Key(20)]
	public bool IsWhitelisted { get; set; }

	/// <summary>True when the remote IP may be reported to AbuseIPDB (public, not whitelisted, not reserved).</summary>
	[Key(21)]
	public bool IsReportableToAbuseIPDB { get; set; }

	/// <summary>True when the remote IP is eligible for auto-block (reportable and not whitelisted).</summary>
	[Key(22)]
	public bool IsEligibleForAutoBlock { get; set; }
}
