// File:    src/RdpAudit.Core/AbuseIpDb/AbuseIpDbReportResult.cs
// Module:  RdpAudit.Core.AbuseIpDb
// Purpose: Plain-data result describing the outcome of a single AbuseIPDB v2 report submission.
//          Combines HTTP status, classified outcome and an optional retry-after hint.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

namespace RdpAudit.Core.AbuseIpDb;

/// <summary>Outcome category for an AbuseIPDB report attempt.</summary>
public enum AbuseIpDbReportOutcome
{
	/// <summary>Report was accepted by AbuseIPDB (HTTP 2xx).</summary>
	Accepted = 0,

	/// <summary>The supplied request was rejected at the protocol level (HTTP 4xx) — typically a bad key or payload.</summary>
	Rejected = 1,

	/// <summary>AbuseIPDB returned 429 Too Many Requests; the worker must back off.</summary>
	RateLimited = 2,

	/// <summary>AbuseIPDB returned a 5xx server error; retry later.</summary>
	ServerError = 3,

	/// <summary>The HTTP call did not complete (network error, timeout, DNS, TLS, etc.).</summary>
	TransportError = 4,

	/// <summary>The configuration is incomplete (no API key, reporting disabled, etc.).</summary>
	NotConfigured = 5,

	/// <summary>The local dedup / rate-limit policy refused the report.</summary>
	Suppressed = 6,
}

/// <summary>Plain-data result describing the outcome of a single AbuseIPDB v2 report submission.</summary>
public sealed class AbuseIpDbReportResult
{
	/// <summary>Classified outcome of the report attempt.</summary>
	public AbuseIpDbReportOutcome Outcome { get; set; } = AbuseIpDbReportOutcome.NotConfigured;

	/// <summary>HTTP status code observed; 0 when no HTTP call was made.</summary>
	public int ResponseCode { get; set; }

	/// <summary>Sanitised human-readable description of the result. Never contains secrets.</summary>
	public string Message { get; set; } = string.Empty;

	/// <summary>When the server provided a Retry-After hint (typically on 429), the suggested delay.</summary>
	public TimeSpan? RetryAfter { get; set; }
}
