// File:    src/RdpAudit.Core/Models/AttackStat.cs
// Module:  RdpAudit.Core.Models
// Purpose: Materialised per-IP attack statistics. Acts as a denormalised summary so the future
//          Firewall stats UI can render dashboards without aggregating RawEvents on every refresh.
//          Populated by a future projection worker (Stage 3+); the entity ships in Stage 2 so
//          migrations align with the Stage 3 worker landing.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

namespace RdpAudit.Core.Models;

/// <summary>Materialised per-IP attack statistics.</summary>
/// <remarks>
/// <see cref="Top10AttemptedLogins"/> stores a JSON array of strings produced by
/// <c>AttackStatProjection.SerializeTopLogins</c>; consumers must round-trip through the helper to
/// avoid format drift between writers.
/// </remarks>
public sealed class AttackStat
{
	/// <summary>Source IP address; the primary key. IPv4 or IPv6 textual form.</summary>
	public string Ip { get; set; } = string.Empty;

	/// <summary>Total logon attempts observed (success + failure).</summary>
	public long TotalAttempts { get; set; }

	/// <summary>Successful logon attempts observed.</summary>
	public long Successful { get; set; }

	/// <summary>Failed logon attempts observed.</summary>
	public long Failed { get; set; }

	/// <summary>UTC timestamp of the first observed attempt from this IP.</summary>
	public DateTime FirstSeenUtc { get; set; }

	/// <summary>UTC timestamp of the most recent observed attempt from this IP.</summary>
	public DateTime LastSeenUtc { get; set; }

	/// <summary>Active attack window duration in whole seconds (LastSeenUtc - FirstSeenUtc).</summary>
	public long DurationSeconds { get; set; }

	/// <summary>Top 10 attempted logins serialised as a JSON array of strings, most-frequent first.</summary>
	public string Top10AttemptedLogins { get; set; } = "[]";

	/// <summary>Optional Windows logon type observed on the most recent attempt.</summary>
	public int? LastLoginType { get; set; }

	/// <summary>Computed threat score, projected from underlying Address.ThreatScore values.</summary>
	public double ThreatScore { get; set; }

	/// <summary>True when there is at least one corresponding row in <c>ActiveBlocks</c>.</summary>
	public bool IsBlocked { get; set; }

	/// <summary>UTC timestamp of the last projection refresh that wrote this row.</summary>
	public DateTime LastUpdatedUtc { get; set; }
}
