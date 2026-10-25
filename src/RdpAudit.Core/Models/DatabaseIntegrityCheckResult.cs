/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 1.0.0
// File   : DatabaseIntegrityCheckResult.cs
// Project: RdpAudit.Core (RdpAudit.Core.Models)
// Purpose: One durable record per executed integrity check, so the Database tab can show the operator the
//          outcome of the scheduled quick_check / full integrity_check / post-restore foreign_key_check
//          without anyone having to read the service log. It is a record of an observation, never a
//          repair: nothing in the product is allowed to "fix" a store based on a check result, and the
//          table is deliberately tiny and indexed by (Kind, CompletedUtc) so looking up the latest result
//          of each kind stays a single indexed read no matter how long the service has been running.
// Depends: DatabaseIntegrityCheckKind, DatabaseIntegrityOutcome
// Extends: Add a field here when a check starts reporting something the operator must see over time.

namespace RdpAudit.Core.Models;

/// <summary>Durable outcome of one executed integrity check.</summary>
public sealed class DatabaseIntegrityCheckResult
{
	/// <summary>Surrogate primary key.</summary>
	public long Id { get; set; }

	/// <summary>Which check ran.</summary>
	public DatabaseIntegrityCheckKind Kind { get; set; }

	/// <summary>When the check started. Always UTC.</summary>
	public DateTime StartedUtc { get; set; }

	/// <summary>When the check finished. Always UTC.</summary>
	public DateTime CompletedUtc { get; set; }

	/// <summary>Outcome classification. <see cref="DatabaseIntegrityOutcome.Ok"/> is only ever recorded
	/// for a check that actually returned "ok"; a check that could not run is a
	/// <see cref="DatabaseIntegrityOutcome.Warning"/>, never a silent success.</summary>
	public DatabaseIntegrityOutcome Outcome { get; set; }

	/// <summary>What the check returned, truncated to the column limit. For a failure this carries the
	/// SQLite report lines, which is what an operator needs to escalate.</summary>
	public string Detail { get; set; } = string.Empty;

	/// <summary>How long the check took, in milliseconds.</summary>
	public long DurationMs { get; set; }

	/// <summary>Who caused the check: <c>Schedule</c> for the maintenance worker, or
	/// <c>Operator:&lt;identity&gt;</c> when a person ran it.</summary>
	public string InitiatedBy { get; set; } = string.Empty;
}
