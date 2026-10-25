// File:    src/RdpAudit.Core/ThreatIntel/ThreatIntelLookupResult.cs
// Module:  RdpAudit.Core.ThreatIntel
// Purpose: Plain-data result describing the outcome of a single threat-intelligence reputation
//          lookup (Backlog #5). Combines the classified outcome, the provider-reported reputation
//          fields mapped from the AbuseIPDB /api/v2/check JSON shape (see
//          https://docs.abuseipdb.com/#check-endpoint) and an optional retry-after hint. The
//          provider response is untrusted data: the Service-side client clamps
//          AbuseConfidenceScore to 0..100 and never stores raw JSON.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

namespace RdpAudit.Core.ThreatIntel;

/// <summary>Outcome category for a threat-intelligence reputation lookup attempt.</summary>
/// <remarks>Append-only: ordinals are persisted in the ThreatIntelLookups table and must never be
/// reused or renumbered.</remarks>
public enum ThreatIntelLookupOutcome
{
	/// <summary>The provider returned a usable reputation snapshot (HTTP 2xx, parseable body).</summary>
	Success = 0,

	/// <summary>The provider refused the request because of the API key (HTTP 401/403) or a
	/// malformed request (HTTP 4xx other than 429). No reputation data.</summary>
	Rejected = 1,

	/// <summary>The provider returned 429 Too Many Requests; the worker must back off and store the
	/// retry hint.</summary>
	RateLimited = 2,

	/// <summary>The provider returned a 5xx server error; retry later.</summary>
	ServerError = 3,

	/// <summary>The HTTP call did not complete (network error, timeout, DNS, TLS, etc.).</summary>
	TransportError = 4,

	/// <summary>The integration is not configured / disabled (no key, feature off).</summary>
	NotConfigured = 5,

	/// <summary>The provider response was received but could not be parsed into a usable shape
	/// (malformed / adversarial JSON). Fail-closed - never marks High-risk.</summary>
	MalformedResponse = 6,
}

/// <summary>Plain-data result describing the outcome of a single reputation lookup.</summary>
public sealed class ThreatIntelLookupResult
{
	/// <summary>Classified outcome of the lookup attempt.</summary>
	public ThreatIntelLookupOutcome Outcome { get; set; } = ThreatIntelLookupOutcome.NotConfigured;

	/// <summary>The IP literal that was looked up (validated by the caller).</summary>
	public string Ip { get; set; } = string.Empty;

	/// <summary>HTTP status code observed; 0 when no HTTP call was made.</summary>
	public int ResponseCode { get; set; }

	/// <summary>Provider-reported abuse confidence score; clamped to 0..100 by the client.
	/// Meaningful only when <see cref="Outcome"/> is <see cref="ThreatIntelLookupOutcome.Success"/>.</summary>
	public int? AbuseConfidenceScore { get; set; }

	/// <summary>Provider-reported total report count for the IP; null when absent.</summary>
	public long? TotalReports { get; set; }

	/// <summary>Provider-reported whitelist state of the IP; null when absent.</summary>
	public bool? IsWhitelisted { get; set; }

	/// <summary>Provider-reported public-routability state of the IP; null when absent.</summary>
	public bool? IsPublic { get; set; }

	/// <summary>Provider-reported usage type (e.g. "Data Center/Web Hosting/Transit"); null when absent.</summary>
	public string? UsageType { get; set; }

	/// <summary>Provider-reported ISO country code; null when absent.</summary>
	public string? CountryCode { get; set; }

	/// <summary>When the server provided a Retry-After hint (typically on 429), the suggested delay.</summary>
	public TimeSpan? RetryAfter { get; set; }

	/// <summary>Sanitised human-readable description of the result. Never contains secrets or raw
	/// provider payloads.</summary>
	public string Message { get; set; } = string.Empty;
}
