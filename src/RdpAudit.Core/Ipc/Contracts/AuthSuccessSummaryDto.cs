// File:    src/RdpAudit.Core/Ipc/Contracts/AuthSuccessSummaryDto.cs
// Module:  RdpAudit.Core.Ipc.Contracts
// Purpose: Response payload for GetAuthSuccessSummaryForIp. Carries a per-login (NormalizedUserName)
//          aggregation of AuthAttemptFacts for one attacker IP — the summary an incident analyst
//          needs to answer "which logins were successfully authenticated / had their passwords
//          guessed from this IP, and how long / how many failed attempts it took". It never carries
//          one row per attempt: each entry is a single rolled-up account so the report stays compact
//          even for IPs with tens of thousands of attempts.
// Extends: To add a new per-login metric, add a [Key] to AuthSuccessLoginDto and populate it in the
//          IpcDispatcher.GetAuthSuccessSummaryForIpAsync aggregation. To add a new roll-up counter
//          for the whole IP, add a [Key] to AuthSuccessSummaryDto. Keys are append-only.
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using MessagePack;

namespace RdpAudit.Core.Ipc.Contracts;

/// <summary>Per-login rolled-up authentication-success record for a single attacker IP. One row per
/// distinct <c>NormalizedUserName</c> — never one row per attempt.</summary>
[MessagePackObject(keyAsPropertyName: false)]
public sealed class AuthSuccessLoginDto
{
	/// <summary>Canonicalised join key (lower-case, domain-stripped) used to group the facts.</summary>
	[Key(0)]
	public string NormalizedUserName { get; set; } = string.Empty;

	/// <summary>Most recently observed raw <c>TargetUser</c> for this login (display form).</summary>
	[Key(1)]
	public string? DisplayUserName { get; set; }

	/// <summary>Most recently observed account domain for this login, when present.</summary>
	[Key(2)]
	public string? Domain { get; set; }

	/// <summary>Count of AuthAttemptFacts with <c>Outcome == Succeeded</c> for this login from this IP.</summary>
	[Key(3)]
	public long SuccessfulAuthCount { get; set; }

	/// <summary>Count of AuthAttemptFacts with <c>Outcome == Failed</c> for this login from this IP.</summary>
	[Key(4)]
	public long FailedAuthCount { get; set; }

	/// <summary>Count of AuthAttemptFacts with <c>Outcome == Denied</c> for this login from this IP.</summary>
	[Key(5)]
	public long DeniedAuthCount { get; set; }

	/// <summary>Total facts recorded for this login from this IP (all outcomes).</summary>
	[Key(6)]
	public long TotalAuthCount { get; set; }

	/// <summary>Count of failed (or denied) authentications recorded strictly before the first
	/// success — i.e. how many attempts the attacker needed before the password worked. Zero when the
	/// very first observed attempt already succeeded; equal to <see cref="FailedAuthCount"/> plus
	/// <see cref="DeniedAuthCount"/> when the login never succeeded.</summary>
	[Key(7)]
	public long FailedBeforeFirstSuccess { get; set; }

	/// <summary>UTC timestamp of the first observed fact (any outcome) for this login from this IP.</summary>
	[Key(8)]
	public DateTime? FirstSeenUtc { get; set; }

	/// <summary>UTC timestamp of the most recent observed fact (any outcome) for this login.</summary>
	[Key(9)]
	public DateTime? LastSeenUtc { get; set; }

	/// <summary>UTC timestamp of the first successful authentication for this login; <c>null</c> when
	/// the login never succeeded from this IP.</summary>
	[Key(10)]
	public DateTime? FirstSuccessUtc { get; set; }

	/// <summary>UTC timestamp of the most recent successful authentication for this login.</summary>
	[Key(11)]
	public DateTime? LastSuccessUtc { get; set; }

	/// <summary>Whole seconds between the first observed attempt and the first success — the wall-clock
	/// time the attacker spent guessing the password. <c>null</c> when the login never succeeded.</summary>
	[Key(12)]
	public long? SecondsToFirstSuccess { get; set; }

	/// <summary>Distinct Windows event ids that produced a <c>Succeeded</c> fact for this login (e.g.
	/// 4624 / 4768 / 4769), ascending. Empty when the login never succeeded.</summary>
	[Key(13)]
	public List<int> SuccessEventIds { get; set; } = new();

	/// <summary>Distinct logon types seen on successful facts for this login (e.g. 3 Network,
	/// 10 RemoteInteractive), ascending. Helps the analyst tell probing from real desktop logons.</summary>
	[Key(14)]
	public List<int> SuccessLogonTypes { get; set; } = new();

	/// <summary>Distinct authentication packages seen on successful facts (e.g. NTLM / Kerberos).</summary>
	[Key(15)]
	public List<string> SuccessAuthPackages { get; set; } = new();

	/// <summary>Distinct failure reasons (translated SubStatus) seen on failed facts for this login —
	/// e.g. "Bad Password", "No Such User", "Account Locked Out". Reveals whether the login exists.</summary>
	[Key(16)]
	public List<string> FailureReasons { get; set; } = new();

	/// <summary>True when at least one success was recorded — i.e. this login's password was validated
	/// from this IP (or a ticket was granted). This is the primary "compromised login" flag.</summary>
	[Key(17)]
	public bool HasSuccess { get; set; }
}

/// <summary>Aggregated authentication-success summary for one attacker IP: per-login roll-ups plus
/// IP-wide totals. Sourced entirely from AuthAttemptFacts (the v3 atomic source of truth), so its
/// counters match the "Auth Success" / "Auth Failed" columns of the RDP Activity grid.</summary>
[MessagePackObject(keyAsPropertyName: false)]
public sealed class AuthSuccessSummaryDto
{
	/// <summary>Controlled-result status.</summary>
	[Key(0)]
	public IpcResultStatus Status { get; set; } = IpcResultStatus.Success;

	/// <summary>Canonical IP literal echoed from the request.</summary>
	[Key(1)]
	public string Ip { get; set; } = string.Empty;

	/// <summary>UTC timestamp of the query that produced this snapshot.</summary>
	[Key(2)]
	public DateTime QueriedUtc { get; set; }

	/// <summary>Total AuthAttemptFacts recorded for this IP (all logins, all outcomes).</summary>
	[Key(3)]
	public long TotalAuthFacts { get; set; }

	/// <summary>Total successful AuthAttemptFacts for this IP across all logins.</summary>
	[Key(4)]
	public long TotalSuccessfulAuth { get; set; }

	/// <summary>Total failed AuthAttemptFacts for this IP across all logins.</summary>
	[Key(5)]
	public long TotalFailedAuth { get; set; }

	/// <summary>Total denied AuthAttemptFacts for this IP across all logins.</summary>
	[Key(6)]
	public long TotalDeniedAuth { get; set; }

	/// <summary>Number of distinct logins that had at least one success from this IP — the count of
	/// accounts whose credentials were validated / passwords guessed.</summary>
	[Key(7)]
	public int DistinctSucceededLogins { get; set; }

	/// <summary>Number of distinct logins observed from this IP (any outcome).</summary>
	[Key(8)]
	public int DistinctLoginsObserved { get; set; }

	/// <summary>UTC timestamp of the first observed fact for this IP; <c>null</c> when none exist.</summary>
	[Key(9)]
	public DateTime? FirstSeenUtc { get; set; }

	/// <summary>UTC timestamp of the most recent observed fact for this IP; <c>null</c> when none exist.</summary>
	[Key(10)]
	public DateTime? LastSeenUtc { get; set; }

	/// <summary>Per-login roll-ups. By default the server returns logins that had at least one success
	/// (the point of this report), ordered by <c>FirstSuccessUtc</c> ascending.</summary>
	[Key(11)]
	public List<AuthSuccessLoginDto> Logins { get; set; } = new();

	/// <summary>Operator-facing message; never carries secret material.</summary>
	[Key(12)]
	public string? Message { get; set; }

	/// <summary>True when the summary was restricted to successful logins only (default); false when
	/// every observed login is included regardless of outcome.</summary>
	[Key(13)]
	public bool SucceededLoginsOnly { get; set; } = true;
}
