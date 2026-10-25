/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 2.0.0
// File   : CollectShardGarbageRequest.cs
// Project: RdpAudit.Core (RdpAudit.Core.Ipc.Contracts)
// Purpose: Request and report contracts of CollectShardGarbage. A dry run returns the candidate list
//          and deletes nothing; an apply pass re-validates every candidate against the live summary
//          table, the live writer pool and the orphan grace period, and reports exactly which files it
//          removed and which it refused, each with the reason. The report names every path it touched,
//          so an operator never has to infer a deletion from a count.
// Depends: MessagePack, IpcResultStatus
// Extends: Append fields only; [Key] indices are an append-only ABI.

using MessagePack;

namespace RdpAudit.Core.Ipc.Contracts;

/// <summary>Request of <c>CollectShardGarbage</c>.</summary>
[MessagePackObject(keyAsPropertyName: false)]
public sealed class CollectShardGarbageRequest
{
	/// <summary>When true the command returns the candidate list and deletes nothing. This is the only
	/// safe way to see what an apply pass would remove; the service never treats an omitted payload as
	/// an apply.</summary>
	[Key(0)]
	public bool DryRun { get; set; } = true;
}

/// <summary>Why one orphan candidate was or was not collected.</summary>
public enum ShardGarbageDisposition
{
	/// <summary>The file may be collected: unreferenced, untouched for at least the grace period and
	/// not open in any writer.</summary>
	Eligible = 0,

	/// <summary>An <c>IpEventSummary</c> row still names this file, so it is live evidence.</summary>
	ReferencedBySummary = 1,

	/// <summary>The sink currently holds an open writer for this file.</summary>
	OpenInWriter = 2,

	/// <summary>The file's last write is newer than the configured grace period.</summary>
	YoungerThanGracePeriod = 3,

	/// <summary>The file resolves outside the configured actions root, so it is never deleted.</summary>
	OutsideActionsRoot = 4,

	/// <summary>The candidate was eligible but the per-run deletion budget was already spent; the next
	/// run collects it.</summary>
	DeletionBudgetSpent = 5,

	/// <summary>The delete failed (a sharing violation or an access denial). Nothing was removed.</summary>
	DeletionFailed = 6,

	/// <summary>The file disappeared between the inventory walk and the delete, so there was nothing to
	/// remove. Reported rather than counted as a success.</summary>
	VanishedBeforeDeletion = 7,

	/// <summary>The file's last-write time could not be read, so its age is unknown. An unknown age is
	/// never treated as old enough: nothing is deleted on a guess.</summary>
	LastActivityUnknown = 8,

	/// <summary>The file became referenced by an <c>IpEventSummary</c> row between the inventory walk
	/// and the delete, so the re-validation stopped the removal.</summary>
	BecameReferenced = 9,
}

/// <summary>One orphan shard file considered by a collection pass.</summary>
[MessagePackObject(keyAsPropertyName: false)]
public sealed class ShardGarbageCandidateDto
{
	/// <summary>Path relative to the actions root, forward slashes.</summary>
	[Key(0)]
	public string RelativePath { get; set; } = string.Empty;

	/// <summary>Absolute path the pass resolved, or empty when the path could not be resolved.</summary>
	[Key(1)]
	public string AbsolutePath { get; set; } = string.Empty;

	/// <summary>Canonical textual address derived from the file name; empty when the name is not a
	/// valid shard name.</summary>
	[Key(2)]
	public string IpText { get; set; } = string.Empty;

	/// <summary>True when the file name carries the subnet-aggregate suffix.</summary>
	[Key(3)]
	public bool IsSubnetAggregate { get; set; }

	/// <summary>On-disk length in bytes; <c>-1</c> when it could not be measured.</summary>
	[Key(4)]
	public long Bytes { get; set; } = -1;

	/// <summary>Live records the shard ring retains; <c>-1</c> when the header could not be read.</summary>
	[Key(5)]
	public long Records { get; set; } = -1;

	/// <summary>Records the ring has evicted; <c>-1</c> when unknown.</summary>
	[Key(6)]
	public long Evicted { get; set; } = -1;

	/// <summary>UTC instant of the file's last write - the only per-file activity timestamp the service
	/// can observe without inventing one; null when it could not be read.</summary>
	[Key(7)]
	public DateTime? LastWriteUtc { get; set; }

	/// <summary>Age in days derived from <see cref="LastWriteUtc"/>; null when the timestamp is unknown
	/// (the candidate is then never eligible).</summary>
	[Key(8)]
	public double? AgeDays { get; set; }

	/// <summary>Outcome of this pass for this candidate.</summary>
	[Key(9)]
	public ShardGarbageDisposition Disposition { get; set; }

	/// <summary>Operator-facing explanation; null when the disposition needs none.</summary>
	[Key(10)]
	public string? Note { get; set; }
}

/// <summary>Report of <c>CollectShardGarbage</c>.</summary>
[MessagePackObject(keyAsPropertyName: false)]
public sealed class ShardGarbageCollectionReportDto
{
	/// <summary><see cref="IpcResultStatus.Success"/> for a completed pass (including a dry run that
	/// found nothing), <see cref="IpcResultStatus.InvalidRequest"/> for a rejected request and
	/// <see cref="IpcResultStatus.Unavailable"/> when the shard tree could not be examined at all.</summary>
	[Key(0)]
	public IpcResultStatus Status { get; set; } = IpcResultStatus.Success;

	/// <summary>UTC instant this pass describes.</summary>
	[Key(1)]
	public DateTime QueriedUtc { get; set; }

	/// <summary>True when this pass deleted nothing.</summary>
	[Key(2)]
	public bool DryRun { get; set; } = true;

	/// <summary>Absolute actions root the pass resolved.</summary>
	[Key(3)]
	public string ActionsRoot { get; set; } = string.Empty;

	/// <summary>Effective orphan grace period in days this pass applied.</summary>
	[Key(4)]
	public int OrphanGraceDays { get; set; }

	/// <summary>Every orphan candidate the pass considered, with its disposition.</summary>
	[Key(5)]
	public List<ShardGarbageCandidateDto> Candidates { get; set; } = new();

	/// <summary>Paths of the files this pass removed, relative to the actions root, in deletion order.
	/// Empty on a dry run.</summary>
	[Key(6)]
	public List<string> DeletedPaths { get; set; } = new();

	/// <summary>Number of files removed. Equals <see cref="DeletedPaths"/>.Count.</summary>
	[Key(7)]
	public int DeletedFileCount { get; set; }

	/// <summary>Total bytes removed.</summary>
	[Key(8)]
	public long DeletedBytes { get; set; }

	/// <summary>Records that lived in the removed shards, summed over the shards whose header was
	/// readable; <c>-1</c> contributions are skipped, so this is a stated lower bound when any header
	/// was unreadable.</summary>
	[Key(9)]
	public long DeletedRecords { get; set; }

	/// <summary>True when eligible candidates remained only because the per-run deletion budget was
	/// spent.</summary>
	[Key(10)]
	public bool DeletionBudgetReached { get; set; }

	/// <summary>True when the inventory walk was truncated, so orphan candidates past the cap were not
	/// considered at all.</summary>
	[Key(11)]
	public bool CandidateListTruncated { get; set; }

	/// <summary>One line per degraded part of the pass, for direct display.</summary>
	[Key(12)]
	public List<string> Warnings { get; set; } = new();

	/// <summary>Operator-facing summary; never carries secret material.</summary>
	[Key(13)]
	public string? Message { get; set; }
}
