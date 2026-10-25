/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 1.0.0
// File   : DatabaseCompactionDto.cs
// Project: RdpAudit.Core (RdpAudit.Core.Ipc.Contracts)
// Purpose: Contract for the online-compaction refusal (IpcCommand.CompactDatabase = 93) and the honest
//          forecast of what an offline compaction would reclaim. The command exists so that an operator -
//          or a client - asking the running service to compact the live store receives a deliberate,
//          explainable refusal carrying the offline procedure, instead of either a silent no-op or, far
//          worse, a full VACUUM inside the service that holds the writer lock for the whole file rewrite.
//          The reclaim forecast is read-only and derived from SQLite's own page accounting
//          (page_size x freelist_count), so it describes space the file already occupies and no longer
//          uses, and never promises a number that depends on a rewrite that has not happened.
// Depends: MessagePack, IpcResultStatus
// Extends: Append fields only; [Key] indices are an append-only ABI.

using MessagePack;

namespace RdpAudit.Core.Ipc.Contracts;

/// <summary>Request for <c>CompactDatabase</c>. Deliberately minimal: the only honest answer the running
/// service can give is a refusal, and the request carries nothing that could change that.</summary>
[MessagePackObject(keyAsPropertyName: false)]
public sealed class DatabaseCompactionRequest
{
	/// <summary>Set by a client that has already stopped the service and is asking anyway. Recorded in the
	/// report so the log shows the operator's intent; it cannot make the online path permissible, because
	/// the fact that this command is being answered proves the service is running.</summary>
	[Key(0)]
	public bool OfflineRequested { get; set; }
}

/// <summary>Read-only answer to a compaction request: the refusal, why, the exact offline procedure, and
/// the space the store is currently not using.</summary>
[MessagePackObject(keyAsPropertyName: false)]
public sealed class DatabaseCompactionDto
{
	/// <summary>Always <see cref="IpcResultStatus.Refused"/> on the online path.</summary>
	[Key(0)]
	public IpcResultStatus Status { get; set; } = IpcResultStatus.Success;

	/// <summary>UTC timestamp of the answer.</summary>
	[Key(1)]
	public DateTime QueriedUtc { get; set; }

	/// <summary>True when an online compaction was requested. Always true here, and that is the reason for
	/// the refusal: the service that answers the call is the service that would have to hold the writer
	/// lock for the whole rewrite.</summary>
	[Key(2)]
	public bool ServiceRunning { get; set; }

	/// <summary>True when the request was refused rather than performed.</summary>
	[Key(3)]
	public bool Refused { get; set; }

	/// <summary>Absolute path of the evidence store the request named.</summary>
	[Key(4)]
	public string DatabasePath { get; set; } = string.Empty;

	/// <summary>Main database file size in bytes, or -1 when it could not be read.</summary>
	[Key(5)]
	public long DatabaseBytes { get; set; } = -1;

	/// <summary>WAL sidecar size in bytes, or -1 when it does not exist / could not be read.</summary>
	[Key(6)]
	public long WalBytes { get; set; } = -1;

	/// <summary>SHM sidecar size in bytes, or -1 when it does not exist / could not be read.</summary>
	[Key(7)]
	public long ShmBytes { get; set; } = -1;

	/// <summary>SQLite page size of the store, or -1 when it could not be read.</summary>
	[Key(8)]
	public long PageSize { get; set; } = -1;

	/// <summary>Total pages in the store, or -1 when it could not be read.</summary>
	[Key(9)]
	public long PageCount { get; set; } = -1;

	/// <summary>Freelist pages: pages the store has already freed and still occupies. This is the amount an
	/// incremental vacuum can return, and the lower bound of what an offline compaction reclaims.</summary>
	[Key(10)]
	public long FreeListPages { get; set; } = -1;

	/// <summary>Bytes currently allocated to freed pages (page size x freelist pages), or -1 when either
	/// figure is unknown. Lower bound, not a promise: a compaction also re-packs partially filled pages.</summary>
	[Key(11)]
	public long ReclaimableBytes { get; set; } = -1;

	/// <summary>The exact offline procedure, one step per entry, for display verbatim.</summary>
	[Key(12)]
	public List<string> Procedure { get; set; } = new();

	/// <summary>Operator-facing explanation of the refusal.</summary>
	[Key(13)]
	public string Message { get; set; } = string.Empty;

	/// <summary>Policy note: what the online path does instead of a VACUUM, and where the policy is
	/// documented.</summary>
	[Key(14)]
	public string PolicyNote { get; set; } = string.Empty;

	/// <summary>The store's <c>PRAGMA auto_vacuum</c> mode (0 NONE, 1 FULL, 2 INCREMENTAL), or -1 when it
	/// could not be read. Reported with the page accounting because it decides whether an offline pass is
	/// merely worth stopping the service for, or the only way this store will ever release free pages: in
	/// any mode other than INCREMENTAL the bounded online incremental vacuum is a documented no-op (B27),
	/// and the Configurator's compaction also rewrites the store into INCREMENTAL mode.</summary>
	[Key(15)]
	public long AutoVacuumMode { get; set; } = -1;
}
