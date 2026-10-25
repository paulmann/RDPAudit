/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 2.0.0
// File   : DeletionLedgerEntryDto.cs
// Project: RdpAudit.Core (RdpAudit.Core.Ipc.Contracts)
// Purpose: Projection of one EventDeletionLedger row plus the paged envelope returned by
//          GetDeletionLedger. The ledger is the answer to "was there activity, or was evidence
//          removed?" so the projection carries the covered window, the row count, the rule version,
//          the trigger and the initiator verbatim — nothing is derived or summarised away.
// Depends: MessagePack, IpcResultStatus, EventDeletionScope, EventDeletionTrigger
// Extends: Append fields only; [Key] indices are an append-only ABI.

using MessagePack;
using RdpAudit.Core.Models;

namespace RdpAudit.Core.Ipc.Contracts;

/// <summary>One audited evidence deletion.</summary>
[MessagePackObject(keyAsPropertyName: false)]
public sealed class DeletionLedgerEntryDto
{
	/// <summary>Ledger surrogate key.</summary>
	[Key(0)]
	public long Id { get; set; }

	/// <summary>Windows event identifier of the removed rows.</summary>
	[Key(1)]
	public int EventCode { get; set; }

	/// <summary>Whether the deletion covered the whole host or one source address.</summary>
	[Key(2)]
	public EventDeletionScope Scope { get; set; }

	/// <summary>Uppercase hexadecimal source address for a per-IP deletion; empty for a host-wide one.</summary>
	[Key(3)]
	public string IpHex { get; set; } = string.Empty;

	/// <summary>Oldest UTC timestamp covered by the removed window, inclusive.</summary>
	[Key(4)]
	public DateTime WindowStartUtc { get; set; }

	/// <summary>Newest UTC timestamp covered by the removed window, inclusive.</summary>
	[Key(5)]
	public DateTime WindowEndUtc { get; set; }

	/// <summary>Exact number of rows removed by this ledger entry.</summary>
	[Key(6)]
	public long RowsDeleted { get; set; }

	/// <summary>Rule that caused the deletion.</summary>
	[Key(7)]
	public EventDeletionTrigger Trigger { get; set; }

	/// <summary>Version of the retention rule set that produced the deletion.</summary>
	[Key(8)]
	public int RuleVersion { get; set; }

	/// <summary>Human-readable cause, including the affected code.</summary>
	[Key(9)]
	public string Reason { get; set; } = string.Empty;

	/// <summary>Who initiated the deletion: <c>Service</c> or <c>Operator:&lt;identity&gt;</c>.</summary>
	[Key(10)]
	public string InitiatedBy { get; set; } = string.Empty;

	/// <summary>UTC instant the ledger entry was written.</summary>
	[Key(11)]
	public DateTime CreatedUtc { get; set; }
}

/// <summary>Paged envelope returned by <c>GetDeletionLedger</c>.</summary>
[MessagePackObject(keyAsPropertyName: false)]
public sealed class DeletionLedgerPageDto
{
	/// <summary><see cref="IpcResultStatus.Unavailable"/> when the ledger could not be read.</summary>
	[Key(0)]
	public IpcResultStatus Status { get; set; } = IpcResultStatus.Success;

	/// <summary>The rows for the requested page, newest first.</summary>
	[Key(1)]
	public List<DeletionLedgerEntryDto> Items { get; set; } = new();

	/// <summary>Total rows matching the filter across all pages.</summary>
	[Key(2)]
	public long TotalMatching { get; set; }

	/// <summary>Zero-based page index that was served.</summary>
	[Key(3)]
	public int Page { get; set; }

	/// <summary>Effective page size after server clamping.</summary>
	[Key(4)]
	public int PageSize { get; set; }

	/// <summary>True when further pages exist beyond the served one.</summary>
	[Key(5)]
	public bool HasMore { get; set; }

	/// <summary>UTC instant of the query that produced this page.</summary>
	[Key(6)]
	public DateTime QueriedUtc { get; set; }

	/// <summary>Operator-facing message; never carries secret material.</summary>
	[Key(7)]
	public string? Message { get; set; }
}
