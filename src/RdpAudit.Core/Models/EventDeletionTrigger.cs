/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 2.0.0
// File   : EventDeletionTrigger.cs
// Project: RdpAudit.Core (RdpAudit.Core.Models)
// Purpose: Records which rule caused a deletion, so an operator reading EventDeletionLedger or a
//          timeline gap can name the cause instead of guessing it.
// Depends: System.Enum
// Extends: Ordinals are append-only and persisted as integers - never reuse or reorder a value. Add a
//          new member only together with the retention-policy option that produces it.

namespace RdpAudit.Core.Models;

/// <summary>Cause of an audited evidence deletion.</summary>
public enum EventDeletionTrigger
{
	/// <summary>No trigger recorded (legacy or unknown origin).</summary>
	Unknown = 0,

	/// <summary>Database file size exceeded <c>RetentionPolicy.MaxDatabaseBytes</c>.</summary>
	DatabaseBytes = 1,

	/// <summary>Raw-event row count exceeded <c>RetentionPolicy.MaxRawEventRows</c>.</summary>
	RawEventRows = 2,

	/// <summary>Free disk space fell below <c>RetentionPolicy.MinFreeDiskBytes</c>.</summary>
	FreeDiskBytes = 3,

	/// <summary>An age-based retention window removed the rows (existing retention behaviour).</summary>
	AgeWindow = 4,

	/// <summary>An operator explicitly requested the deletion (purge by subject, danger-zone action).</summary>
	OperatorRequest = 5,
}
