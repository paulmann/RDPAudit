// File:    src/RdpAudit.Core/Ipc/Contracts/AttackStatEntryDto.cs
// Module:  RdpAudit.Core.Ipc.Contracts
// Purpose: DTO entry for a single per-IP Attack Statistics row surfaced to the Configurator.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using MessagePack;
using RdpAudit.Core.Models;

namespace RdpAudit.Core.Ipc.Contracts;

/// <summary>DTO entry for a single per-IP Attack Statistics row.</summary>
[MessagePackObject(keyAsPropertyName: false)]
public sealed class AttackStatEntryDto
{
	[Key(0)]
	public string Ip { get; set; } = string.Empty;

	[Key(1)]
	public long TotalAttempts { get; set; }

	[Key(2)]
	public long Successful { get; set; }

	[Key(3)]
	public long Failed { get; set; }

	[Key(4)]
	public DateTime FirstSeenUtc { get; set; }

	[Key(5)]
	public DateTime LastSeenUtc { get; set; }

	[Key(6)]
	public long DurationSeconds { get; set; }

	/// <summary>JSON array of strings produced by <c>AttackStatProjection.SerializeTopLogins</c>.</summary>
	[Key(7)]
	public string Top10AttemptedLogins { get; set; } = "[]";

	[Key(8)]
	public int? LastLoginType { get; set; }

	[Key(9)]
	public double ThreatScore { get; set; }

	[Key(10)]
	public AttackThreatLevel ThreatLevel { get; set; }

	[Key(11)]
	public bool IsBlocked { get; set; }

	[Key(12)]
	public DateTime LastUpdatedUtc { get; set; }

	// --- Stage IP-D fact augmentation (append-only keys). All fields are optional / nullable so a
	// row produced without matching RdpConnectionFacts data still serialises cleanly. Configurator
	// renderers should prefer the AttackStat columns where present and only fall back to the
	// fact-derived fields when AttackStat is silent.

	/// <summary>True when at least one matching <c>RdpConnectionFact</c> currently represents an active session.</summary>
	[Key(13)]
	public bool HasActiveConnectionFact { get; set; }

	/// <summary>Sum of failed logons across all <c>RdpConnectionFacts</c> for this IP, when available.</summary>
	[Key(14)]
	public long FactFailedLogons { get; set; }

	/// <summary>Sum of successful logons across all <c>RdpConnectionFacts</c> for this IP, when available.</summary>
	[Key(15)]
	public long FactSuccessfulLogons { get; set; }

	/// <summary>Most recent <c>LastSeenUtc</c> across all <c>RdpConnectionFacts</c> for this IP; null when none exist.</summary>
	[Key(16)]
	public DateTime? FactLastSeenUtc { get; set; }

	/// <summary>Earliest <c>FirstSeenUtc</c> across all <c>RdpConnectionFacts</c> for this IP; null when none exist.</summary>
	[Key(17)]
	public DateTime? FactFirstSeenUtc { get; set; }

	// --- Req 12 additions (append-only keys). Separate the unresolved-IP sentinel aggregate row from
	// real attacker IPs so the UI never presents "0.0.0.0 (unresolved)" as a genuine remote attacker.

	/// <summary>True when this row is the unresolved-IP sentinel aggregate (no real source address),
	/// not a genuine attacker. The UI must render it as a separate / excluded category.</summary>
	[Key(18)]
	public bool IsUnresolved { get; set; }

	/// <summary>Operator-facing reportability classification of the source IP
	/// (Public / Private / Loopback / Unresolved / …). Empty string when unknown.</summary>
	[Key(19)]
	public string Classification { get; set; } = string.Empty;

	/// <summary>Operator-facing display label for the source IP — the sentinel row shows
	/// <c>(unresolved)</c> instead of the raw <c>0.0.0.0</c> address.</summary>
	[Key(20)]
	public string DisplayIp { get; set; } = string.Empty;
}
