// File:    src/RdpAudit.Core/Models/AbuseIpDbReportHistory.cs
// Module:  RdpAudit.Core.Models
// Purpose: Persistent, audit-grade history of every AbuseIPDB report ATTEMPT (success or failure).
//          Drives the success-filtered report cooldown / dedupe: the worker consults the latest
//          SUCCESSFUL row for a normalized IP before submitting again. Never stores the API key.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using RdpAudit.Core.Util;

namespace RdpAudit.Core.Models;

/// <summary>Audit-grade history of a single AbuseIPDB report attempt (success or failure).</summary>
/// <remarks>
/// Distinct from <see cref="AbuseReport"/>, which is the legacy 15-minute rate-limit log. This table
/// is the source of truth for the configurable report cooldown: only rows with <see cref="Succeeded"/>
/// true gate future submissions. No secret material (API key) is ever written here.
/// </remarks>
public sealed class AbuseIpDbReportHistory
{
	/// <summary>Auto-incremented surrogate key.</summary>
	public long Id { get; set; }

	/// <summary>Normalized (canonical) IP address this attempt targeted.</summary>
	public string IpAddress { get; set; } = string.Empty;

	/// <summary>UTC timestamp when the attempt was made.</summary>
	public DateTime ReportedAtUtc { get; set; }

	/// <summary>True only when AbuseIPDB accepted the report (HTTP 2xx). Failed attempts never suppress.</summary>
	public bool Succeeded { get; set; }

	/// <summary>HTTP status code from AbuseIPDB. 0 indicates the request was never transmitted.</summary>
	public int HttpStatusCode { get; set; }

	/// <summary>Coarse outcome / result code (e.g. the AbuseIpDbReportOutcome name) for diagnostics.</summary>
	public string? ResultCode { get; set; }

	/// <summary>Sanitised error message; never contains the API key or other secret material.</summary>
	public string? ErrorMessage { get; set; }

	/// <summary>AbuseIPDB category list submitted (comma-separated integers per the v2 schema).</summary>
	public string AbuseCategories { get; set; } = string.Empty;

	/// <summary>SHA-256 hash (hex) of the submitted comment; lets us detect duplicate evidence without storing it.</summary>
	public string? CommentHash { get; set; }

	/// <summary>Optional originating rule identifier, when the report was triggered by a specific LoginRule.</summary>
	public long? RuleId { get; set; }

	/// <summary>Optional free-form source tag (e.g. "worker", "manual") for audit attribution.</summary>
	public string? Source { get; set; }

	// --- v1.2.6 report-log columns (additive; nullable / defaulted so the migration is safe). ---

	/// <summary>The operator-visible action taken for this row.</summary>
	public AbuseIpDbReportAction Action { get; set; } = AbuseIpDbReportAction.Sent;

	/// <summary>Machine-readable reason token (mirrors <c>IpReportability.Reasons</c> / suppression reason).</summary>
	public string? Reason { get; set; }

	/// <summary>Coarse reportability classification of the source IP at the time of the attempt.</summary>
	public IpReportClassification Classification { get; set; } = IpReportClassification.Public;

	/// <summary>AbuseIPDB-assigned report identifier (or null when none / not accepted).</summary>
	public string? ReportId { get; set; }

	/// <summary>UTC instant at which the dedupe cooldown for this IP expires; null when dedupe is off.</summary>
	public DateTime? CooldownExpiresUtc { get; set; }

	/// <summary>Failed-attempt count observed for the IP at report time.</summary>
	public long FailedCount { get; set; }

	/// <summary>Successful-logon count observed for the IP at report time.</summary>
	public long SuccessfulCount { get; set; }

	/// <summary>First-seen UTC for the IP at report time; null when unknown.</summary>
	public DateTime? FirstSeenUtc { get; set; }

	/// <summary>Last-seen UTC for the IP at report time; null when unknown.</summary>
	public DateTime? LastSeenUtc { get; set; }

	/// <summary>Sanitised sample (max 10) of usernames attempted; never contains secret material.</summary>
	public string? UsernamesSample { get; set; }

	/// <summary>Short, sanitised preview of the submitted report comment; never the API key.</summary>
	public string? CommentPreview { get; set; }
}

/// <summary>Operator-visible action recorded for an AbuseIPDB report-log row.</summary>
/// <remarks>Ordinals are persisted; append-only — never reorder or reuse.</remarks>
public enum AbuseIpDbReportAction
{
	/// <summary>Report was submitted to AbuseIPDB and accepted.</summary>
	Sent = 0,

	/// <summary>Report was deliberately not submitted (dedupe / non-reportable / disabled).</summary>
	Skipped = 1,

	/// <summary>Report was submitted but AbuseIPDB or the transport rejected it.</summary>
	Failed = 2,

	/// <summary>Operator copied the prepared report text to the clipboard (manual flow).</summary>
	ManualCopied = 3,

	/// <summary>Operator opened the AbuseIPDB page for the IP (manual flow).</summary>
	ManualOpened = 4,
}
