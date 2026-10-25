/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 2.0.0
// File   : EventDeletionLedger.cs
// Project: RdpAudit.Core (RdpAudit.Core.Models)
// Purpose: Append-only tombstone for removed raw-event evidence. One row accounts for the exact
//          number of rows deleted for one code inside one time window, why they were deleted and who
//          or what initiated it, so a timeline can never render removed evidence as absent activity.
//          Each appended row also carries a SHA-256 hash chain link (PreviousHash -> EntryHash) so a
//          later verification can prove that no row was modified, removed from the middle, or
//          reordered after it was written.
// Depends: EventDeletionScope, EventDeletionTrigger, LedgerChainHasher
// Extends: Mirror every new persistence property in EventDeletionLedgerConfiguration before
//          generating a migration. Rows are never updated in place - correction is a new row.

namespace RdpAudit.Core.Models;

/// <summary>Immutable record of one audited deletion of raw-event evidence.</summary>
public sealed class EventDeletionLedger
{
	/// <summary>Surrogate primary key.</summary>
	public long Id { get; set; }

	/// <summary>Windows event identifier the deleted rows carried.</summary>
	public int EventCode { get; set; }

	/// <summary>Whether the deletion ranged over the whole host or over one source address.</summary>
	public EventDeletionScope Scope { get; set; }

	/// <summary>Canonical 16-byte IPv6-mapped source IP when <see cref="Scope"/> is
	/// <see cref="EventDeletionScope.PerIp"/>; null for a host-wide deletion.</summary>
	public byte[]? IpBinary16 { get; set; }

	/// <summary>Oldest UTC timestamp covered by the deleted window, inclusive.</summary>
	public DateTime WindowStartUtc { get; set; }

	/// <summary>Newest UTC timestamp covered by the deleted window, inclusive.</summary>
	public DateTime WindowEndUtc { get; set; }

	/// <summary>Exact number of rows removed by this ledger entry.</summary>
	public long RowsDeleted { get; set; }

	/// <summary>Rule that caused the deletion.</summary>
	public EventDeletionTrigger Trigger { get; set; }

	/// <summary>Version of the retention rule set that produced the deletion, so a future rule change
	/// stays distinguishable from a regression in an already-shipped rule.</summary>
	public int RuleVersion { get; set; }

	/// <summary>Human-readable cause, including the channel of the affected code.</summary>
	public string Reason { get; set; } = string.Empty;

	/// <summary>Who initiated the deletion: <c>Service</c> or <c>Operator:&lt;identity&gt;</c>.</summary>
	public string InitiatedBy { get; set; } = string.Empty;

	/// <summary>When the ledger entry was written. Always UTC.</summary>
	public DateTime CreatedUtc { get; set; }

	/// <summary>SHA-256 (lower-case hex, 64 characters) of the previous chained entry, or of the chain
	/// genesis when this is the first chained row. Null on rows written before the chain existed: the
	/// chain starts after the upgrade, so an older history is reported as unverifiable rather than
	/// silently accepted.</summary>
	public string? PreviousHash { get; set; }

	/// <summary>SHA-256 (lower-case hex, 64 characters) over <see cref="PreviousHash"/> and this row's
	/// content, computed by <c>LedgerChainHasher</c> at write time. Null on pre-chain rows.</summary>
	public string? EntryHash { get; set; }
}
