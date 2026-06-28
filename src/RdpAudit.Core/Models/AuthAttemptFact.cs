// File:    src/RdpAudit.Core/Models/AuthAttemptFact.cs
// Module:  RdpAudit.Core.Models
// Purpose: Atomic, persisted authentication-attempt fact — the single source of truth for every
//          Total / Successful / Failed counter surfaced by Attack Statistics, IP facts, and the
//          Configurator dashboards (Detect_Attack_Strategy_v3.md, sections 8.1 and 17.14). Every
//          row is derived from exactly one Windows authentication-bearing event (Security 4624 /
//          4625 / 4648 / 4768 / 4769 / 4771 / 4776 — never from RdpCoreTS / TCP / WTS); IpFact and
//          UserIpFact counters MUST be aggregations of this table. The v3 invariant: rebuilding
//          facts from scratch always yields identical counters.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

namespace RdpAudit.Core.Models;

/// <summary>Outcome classification per v3 strategy. RdpCoreTS / TCP must never set outcome.</summary>
public enum AuthAttemptOutcome
{
	/// <summary>Default. The fact has not yet been classified — should never be persisted.</summary>
	Unknown = 0,

	/// <summary>Authoritative success: Security 4624 with an RDP-relevant LogonType, or 4768/4769
	/// Kerberos success. Never set from RdpCoreTS / TCP / WTS sources.</summary>
	Succeeded = 1,

	/// <summary>Authoritative failure: Security 4625 / 4771 / 4776 (Status != 0x0).</summary>
	Failed = 2,

	/// <summary>Authorization denied (e.g. 4825 access denied). Distinct from credential failure.</summary>
	Denied = 3,
}

/// <summary>
/// Atomic persisted authentication-attempt fact. The single source of truth per
/// Detect_Attack_Strategy_v3.md §8.1; Total / Successful / Failed counters in
/// <c>IpFact</c>, <c>UserIpFact</c>, and Attack Statistics must derive from this table only.
/// </summary>
public sealed class AuthAttemptFact
{
	/// <summary>Surrogate primary key.</summary>
	public long Id { get; set; }

	/// <summary>Event UTC timestamp from the originating Windows record.</summary>
	public DateTime TimeUtc { get; set; }

	/// <summary>Enriched source IP, when known. May be null for NLA-stripped 4625 where no RdpCoreTS
	/// 131/140 correlation candidate could be found; the row is still persisted so the failure is
	/// counted.</summary>
	public string? SourceIp { get; set; }

	/// <summary>Optional source port from the Windows event.</summary>
	public int? SourcePort { get; set; }

	/// <summary>Attempted or authenticated user name (TargetUserName / Param1).</summary>
	public string? TargetUser { get; set; }

	/// <summary>Account domain (TargetDomainName / Param2).</summary>
	public string? TargetDomain { get; set; }

	/// <summary>Canonicalised user key — lower-case, domain-stripped — used for cross-event joining.</summary>
	public string? NormalizedUserName { get; set; }

	/// <summary>Client workstation NetBIOS name when present.</summary>
	public string? WorkstationName { get; set; }

	/// <summary>Authentication package (NTLM / Kerberos / Negotiate / CredSSP).</summary>
	public string? AuthPackage { get; set; }

	/// <summary>Windows logon type (10 RemoteInteractive, 3 Network NLA-RDP, 7 Unlock, etc.).</summary>
	public int? LogonType { get; set; }

	/// <summary>LSA correlation key (TargetLogonId), when present.</summary>
	public string? LogonId { get; set; }

	/// <summary>Authoritative outcome per v3 §6.3 hierarchy.</summary>
	public AuthAttemptOutcome Outcome { get; set; } = AuthAttemptOutcome.Unknown;

	/// <summary>Raw Windows Status field (hex without the 0x prefix is also accepted).</summary>
	public string? Status { get; set; }

	/// <summary>Raw Windows SubStatus field — drives attack-classification (bad password vs no such
	/// user vs lockout).</summary>
	public string? SubStatus { get; set; }

	/// <summary>Human-readable translation of <see cref="SubStatus"/> (e.g. "Bad Password",
	/// "No Such User", "Account Locked Out").</summary>
	public string? SubStatusMeaning { get; set; }

	/// <summary>Provenance: source channel of the evidence event.</summary>
	public string? EvidenceChannel { get; set; }

	/// <summary>Provenance: source Windows event id.</summary>
	public int EvidenceEventId { get; set; }

	/// <summary>Provenance: RawEvent.Id row that this fact was derived from.</summary>
	public long EvidenceRawEventId { get; set; }

	/// <summary>True when the IP was attached by correlation rather than read directly from the
	/// originating event payload. v3 §6.3 rules: an IP recovered from RdpCoreTS 131/140 for a
	/// stripped 4625 is "derived".</summary>
	public bool IpFromCorrelation { get; set; }

	/// <summary>Free-form provenance label (e.g. "DirectXml", "RdpCoreTs131", "LogonIdChain"). Helps
	/// the UI render a confidence badge without re-parsing the original event.</summary>
	public string? EnrichmentSource { get; set; }

	/// <summary>Qualitative confidence per v3 §6.3 (High / Medium / Low / None).</summary>
	public string? EnrichmentConfidence { get; set; }

	/// <summary>True when this fact still needs cross-channel correlation (e.g. a 4625 without IP
	/// that has not yet found its RdpCoreTS pair). The watchdog inspects this flag.</summary>
	public bool NeedsCorrelation { get; set; }

	/// <summary>UTC processing timestamp — when this fact landed in the database.</summary>
	public DateTime IngestedUtc { get; set; }
}
