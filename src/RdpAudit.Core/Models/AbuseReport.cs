// File:    src/RdpAudit.Core/Models/AbuseReport.cs
// Module:  RdpAudit.Core.Models
// Purpose: Persistent log of reports sent to AbuseIPDB. Used by the eventual AbuseIPDB client to
//          honour the public API's rate limit (one report per IP per 15 minutes) and to surface
//          historical reports in the Configurator.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

namespace RdpAudit.Core.Models;

/// <summary>Persistent log of reports sent to AbuseIPDB.</summary>
public sealed class AbuseReport
{
	/// <summary>Auto-incremented surrogate key.</summary>
	public long Id { get; set; }

	/// <summary>Reported IP address in IPv4 or IPv6 textual form.</summary>
	public string Ip { get; set; } = string.Empty;

	/// <summary>UTC timestamp when the report was sent.</summary>
	public DateTime ReportedUtc { get; set; }

	/// <summary>AbuseIPDB category list (comma-separated integers per the AbuseIPDB v2 schema).</summary>
	public string Categories { get; set; } = string.Empty;

	/// <summary>HTTP response code from AbuseIPDB. 0 indicates the request was never sent.</summary>
	public int ResponseCode { get; set; }

	/// <summary>Optional error message; populated when the call failed or was rate-limited locally.</summary>
	public string? Error { get; set; }

	/// <summary>Optional foreign key to the <see cref="Alert"/> that triggered the report.</summary>
	public long? AlertId { get; set; }
}
