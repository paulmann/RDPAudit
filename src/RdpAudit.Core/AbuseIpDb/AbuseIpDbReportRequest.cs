// File:    src/RdpAudit.Core/AbuseIpDb/AbuseIpDbReportRequest.cs
// Module:  RdpAudit.Core.AbuseIpDb
// Purpose: Plain-data request describing a single AbuseIPDB v2 report submission. The HTTP client
//          encodes Ip + Categories + Comment into the form-urlencoded body required by the public
//          /api/v2/report endpoint.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

namespace RdpAudit.Core.AbuseIpDb;

/// <summary>Plain-data request describing a single AbuseIPDB v2 report submission.</summary>
public sealed class AbuseIpDbReportRequest
{
	/// <summary>Hostile IP address to report (IPv4 or IPv6 textual form).</summary>
	public string Ip { get; set; } = string.Empty;

	/// <summary>Comma-separated AbuseIPDB category integers (per the public v2 schema).</summary>
	public string Categories { get; set; } = string.Empty;

	/// <summary>Sanitised comment built from RdpAudit evidence; must never contain secrets.</summary>
	public string Comment { get; set; } = string.Empty;
}
