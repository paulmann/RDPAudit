// File:    src/RdpAudit.Core/Models/ThreatIntelUsageCounter.cs
// Module:  RdpAudit.Core.Models
// Purpose: Persistent daily usage counter for the Backlog #5 threat-intelligence lookup feature.
//          One row per UTC date (yyyy-MM-dd, TEXT primary key) with the number of /api/v2/check
//          calls performed that day. The counter is never reset; the daily budget comparison uses
//          clamp-checked values so it cannot overflow.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

namespace RdpAudit.Core.Models;

/// <summary>Daily usage counter for the threat-intelligence lookup feature.</summary>
public sealed class ThreatIntelUsageCounter
{
	/// <summary>UTC day key in yyyy-MM-dd form. Primary key; one row per calendar day.</summary>
	public string DayDateUtc { get; set; } = string.Empty;

	/// <summary>Number of /check lookups performed on this day.</summary>
	public int Count { get; set; }
}
