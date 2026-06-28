// File:    src/RdpAudit.Core/MikroTik/MikroTikOperationResult.cs
// Module:  RdpAudit.Core.MikroTik
// Purpose: Classified result returned by IMikroTikClient operations. Carries an outcome
//          discriminator, the observed HTTP status code, a sanitised message free of secret
//          material, the optional Retry-After hint, and (for add operations) the resulting rule
//          id so callers can persist it into ActiveBlocks.RuleHandle.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

namespace RdpAudit.Core.MikroTik;

/// <summary>Outcome category for a MikroTik REST operation.</summary>
public enum MikroTikOutcome
{
	/// <summary>Operation succeeded.</summary>
	Accepted = 0,

	/// <summary>Router responded with 4xx (typically bad credentials or invalid arguments).</summary>
	Rejected = 1,

	/// <summary>Router returned 429 — back off.</summary>
	RateLimited = 2,

	/// <summary>Router returned 5xx — retry later.</summary>
	ServerError = 3,

	/// <summary>Transport problem (network, TLS, DNS, timeout).</summary>
	TransportError = 4,

	/// <summary>Local configuration prevented the call (no endpoint or no credentials).</summary>
	NotConfigured = 5,

	/// <summary>The rule already existed; the provider reused the existing entry instead of duplicating it.</summary>
	AlreadyExists = 6,

	/// <summary>The target rule could not be found on the router.</summary>
	NotFound = 7,
}

/// <summary>Result of a MikroTik REST operation.</summary>
public sealed class MikroTikOperationResult
{
	public MikroTikOutcome Outcome { get; set; } = MikroTikOutcome.NotConfigured;
	public int ResponseCode { get; set; }
	public string Message { get; set; } = string.Empty;
	public TimeSpan? RetryAfter { get; set; }
	public string? RuleId { get; set; }
}
