/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 1.0.0
// File   : PurgeBySubjectDto.cs
// Project: RdpAudit.Core (RdpAudit.Core.Ipc.Contracts)
// Purpose: Contract for the subject purge (IpcCommand.PurgeBySubject = 94): remove every evidence row that
//          belongs to one subject - a single address, a CIDR range, a login, or a UTC time window - under a
//          typed confirmation, with a mandatory dry run and a per-table account of exactly what would go
//          and what went. The dry run is the default because this is the one command in the product that
//          can delete an anchor: the operator sees the counts before anything is removed, and applying
//          requires the exact phrase on the wire.
//          The report separates three groups so nothing is silently kept or silently removed:
//          per-table counts for the evidence tables in scope, the operator-facing reason for every table
//          excluded by design, and the preserved-system list (schema, migrations, configuration, bookmarks,
//          the append-only ledger itself) that no purge may touch.
// Depends: MessagePack, IpcResultStatus, EventDeletionScope
// Extends: Append fields only; [Key] indices are an append-only ABI.

using MessagePack;

namespace RdpAudit.Core.Ipc.Contracts;

/// <summary>The dimension a subject purge is expressed in.</summary>
public enum PurgeSubjectKind
{
	/// <summary>Not a subject: always refused rather than silently treated as "everything".</summary>
	Unknown = 0,

	/// <summary>One address, exact match.</summary>
	Ip = 1,

	/// <summary>An address range in CIDR form (<c>203.0.113.0/24</c>).</summary>
	Cidr = 2,

	/// <summary>One login name, matched case-insensitively.</summary>
	Login = 3,

	/// <summary>A UTC time window with no subject dimension.</summary>
	TimeRange = 4,
}

/// <summary>Request for <c>PurgeBySubject</c>.</summary>
[MessagePackObject(keyAsPropertyName: false)]
public sealed class PurgeBySubjectRequest
{
	/// <summary>Which dimension identifies the subject.</summary>
	[Key(0)]
	public PurgeSubjectKind Kind { get; set; }

	/// <summary>The address, CIDR range or login. Unused (and ignored) for
	/// <see cref="PurgeSubjectKind.TimeRange"/>.</summary>
	[Key(1)]
	public string? Value { get; set; }

	/// <summary>Optional UTC window lower bound, inclusive. Required - and both bounds required - for
	/// <see cref="PurgeSubjectKind.TimeRange"/>; optional narrowing for the other kinds.</summary>
	[Key(2)]
	public DateTime? WindowStartUtc { get; set; }

	/// <summary>Optional UTC window upper bound, exclusive.</summary>
	[Key(3)]
	public DateTime? WindowEndUtc { get; set; }

	/// <summary>False (the default, and what an omitted payload means) is a pure dry run: counts are
	/// computed and nothing is deleted.</summary>
	[Key(4)]
	public bool Apply { get; set; }

	/// <summary>Required for an apply pass: the exact typed confirmation phrase, re-validated on the
	/// server. A wrong or missing phrase is refused and nothing is deleted.</summary>
	[Key(5)]
	public string? ConfirmationPhrase { get; set; }
}

/// <summary>What a subject purge would do - or did - to one table.</summary>
[MessagePackObject(keyAsPropertyName: false)]
public sealed class PurgeBySubjectTableDto
{
	/// <summary>Table name.</summary>
	[Key(0)]
	public string Table { get; set; } = string.Empty;

	/// <summary>Rows the subject predicate matches. In a dry run this is exactly the number an apply pass
	/// deletes, because both use the same predicate builder.</summary>
	[Key(1)]
	public long RowsMatched { get; set; }

	/// <summary>Rows actually deleted. Always zero in a dry run.</summary>
	[Key(2)]
	public long RowsDeleted { get; set; }

	/// <summary>Oldest UTC timestamp among the deleted rows, when one was recorded.</summary>
	[Key(3)]
	public DateTime? WindowStartUtc { get; set; }

	/// <summary>Newest UTC timestamp among the deleted rows, when one was recorded.</summary>
	[Key(4)]
	public DateTime? WindowEndUtc { get; set; }

	/// <summary>A ledger row was appended for this table. False in a dry run, and false for a table whose
	/// deletion did not need one because it deleted nothing.</summary>
	[Key(5)]
	public bool LedgerWritten { get; set; }
}

/// <summary>Outcome of a subject purge (dry run or apply).</summary>
[MessagePackObject(keyAsPropertyName: false)]
public sealed class PurgeBySubjectReportDto
{
	/// <summary>Overall status.</summary>
	[Key(0)]
	public IpcResultStatus Status { get; set; } = IpcResultStatus.Success;

	/// <summary>UTC timestamp of the report.</summary>
	[Key(1)]
	public DateTime QueriedUtc { get; set; }

	/// <summary>True when nothing was deleted (a dry run, or a refusal).</summary>
	[Key(2)]
	public bool DryRun { get; set; } = true;

	/// <summary>True when the pass deleted rows.</summary>
	[Key(3)]
	public bool Applied { get; set; }

	/// <summary>Which dimension identified the subject.</summary>
	[Key(4)]
	public PurgeSubjectKind Kind { get; set; }

	/// <summary>Canonical subject text as the server resolved it (a normalized address, CIDR or login).</summary>
	[Key(5)]
	public string Subject { get; set; } = string.Empty;

	/// <summary>Effective window lower bound, inclusive.</summary>
	[Key(6)]
	public DateTime? WindowStartUtc { get; set; }

	/// <summary>Effective window upper bound, exclusive.</summary>
	[Key(7)]
	public DateTime? WindowEndUtc { get; set; }

	/// <summary>Per-table outcome, ordered by table name.</summary>
	[Key(8)]
	public List<PurgeBySubjectTableDto> Tables { get; set; } = new();

	/// <summary>Rows the subject matches across all tables.</summary>
	[Key(9)]
	public long TotalRowsMatched { get; set; }

	/// <summary>Rows deleted across all tables. Zero in a dry run.</summary>
	[Key(10)]
	public long TotalRowsDeleted { get; set; }

	/// <summary>True when a legal hold is in force. A legal hold makes an apply pass impossible; a dry run
	/// still reports the counts so the operator can see the size of what is frozen.</summary>
	[Key(11)]
	public bool LegalHold { get; set; }

	/// <summary>Ledger rows appended by this pass (one per table that lost rows).</summary>
	[Key(12)]
	public int LedgerEntriesWritten { get; set; }

	/// <summary>Hash-chain EntryHash of the last ledger row appended, so the operator can confirm the pass
	/// joined the chain.</summary>
	[Key(13)]
	public string? LedgerChainHead { get; set; }

	/// <summary>Tables and records deliberately NOT touched, with the reason. Empty is never assumed: the
	/// server always enumerates the preserved system surfaces so silence cannot hide a retention choice.</summary>
	[Key(14)]
	public List<string> Preserved { get; set; } = new();

	/// <summary>Operator-facing summary.</summary>
	[Key(15)]
	public string Message { get; set; } = string.Empty;

	/// <summary>Per-step diagnostic log.</summary>
	[Key(16)]
	public string? DebugLog { get; set; }
}
