// File:    src/RdpAudit.Core/Models/ThreatIntelLookup.cs
// Module:  RdpAudit.Core.Models
// Purpose: Persistent cache row for the Backlog #5 threat-intelligence reputation lookup feature.
//          One row per IP with the most recent /api/v2/check result. The IPC request path reads
//          ONLY this cache (never HTTP); the background enrichment worker refreshes rows.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

namespace RdpAudit.Core.Models;

/// <summary>Persistent cache row for a single threat-intelligence reputation lookup.</summary>
public sealed class ThreatIntelLookup
{
	/// <summary>Normalized (canonical) IP address this row describes. Primary key so an IP has at most one cached snapshot.</summary>
	public string Ip { get; set; } = string.Empty;

	/// <summary>UTC timestamp when this snapshot was written.</summary>
	public DateTime LookedUpUtc { get; set; }

	/// <summary>Ordinal of <see cref="RdpAudit.Core.ThreatIntel.ThreatIntelLookupOutcome"/> for the last attempt.</summary>
	public int Outcome { get; set; }

	/// <summary>Provider-reported abuse confidence score clamped to 0..100; null when the outcome is not Success.</summary>
	public int? Score { get; set; }

	/// <summary>Provider-reported total report count; null when absent.</summary>
	public long? TotalReports { get; set; }

	/// <summary>Provider-reported whitelist state; null when absent or when the outcome is not Success.</summary>
	public bool? IsWhitelisted { get; set; }

	/// <summary>Provider-reported public-routability state; null when absent or when the outcome is not Success.</summary>
	public bool? IsPublic { get; set; }

	/// <summary>Provider-reported usage type; null when absent.</summary>
	public string? UsageType { get; set; }

	/// <summary>Provider-reported ISO country code; null when absent.</summary>
	public string? CountryCode { get; set; }

	/// <summary>Earliest UTC instant at which a retry is allowed after a rate limit (429). Null when no retry is pending.</summary>
	public DateTime? NextRetryUtc { get; set; }
}
