/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 2.0.0
// File   : DeletionLedgerQueryRequest.cs
// Project: RdpAudit.Core (RdpAudit.Core.Ipc.Contracts)
// Purpose: Bounded, filtered, paged request over EventDeletionLedger for the Database tab's
//          Ledger grid. Every filter is optional; the server clamps the page size and the date
//          window so a client can never ask the service to serialize the whole ledger. The date
//          filter applies to CreatedUtc — when the deletion happened — because that is the
//          operator-meaningful axis; the covered evidence window is reported per row.
// Depends: MessagePack, EventDeletionScope
// Extends: Append fields only; [Key] indices are an append-only ABI.

using MessagePack;
using RdpAudit.Core.Models;

namespace RdpAudit.Core.Ipc.Contracts;

/// <summary>Request DTO for <c>GetDeletionLedger</c> (bounded, filtered, paged).</summary>
[MessagePackObject(keyAsPropertyName: false)]
public sealed class DeletionLedgerQueryRequest
{
	/// <summary>Optional exact event-code filter; null or zero means "every code".</summary>
	[Key(0)]
	public int? EventCode { get; set; }

	/// <summary>Optional inclusive lower bound on <c>CreatedUtc</c>; null means "no lower bound".</summary>
	[Key(1)]
	public DateTime? FromUtc { get; set; }

	/// <summary>Optional inclusive upper bound on <c>CreatedUtc</c>; null means "no upper bound".</summary>
	[Key(2)]
	public DateTime? ToUtc { get; set; }

	/// <summary>Optional scope filter; null means "both scopes".</summary>
	[Key(3)]
	public EventDeletionScope? Scope { get; set; }

	/// <summary>Optional uppercase hexadecimal source address filter, matched exactly against
	/// <c>IpBinary16</c>; null or empty means "every address".</summary>
	[Key(4)]
	public string? IpHex { get; set; }

	/// <summary>Zero-based page index.</summary>
	[Key(5)]
	public int Page { get; set; }

	/// <summary>Rows per page. <c>0</c> or negative means "use the server default". The server
	/// clamps to a safe maximum.</summary>
	[Key(6)]
	public int PageSize { get; set; }
}
