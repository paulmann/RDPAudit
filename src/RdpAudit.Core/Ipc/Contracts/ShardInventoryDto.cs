/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 2.0.0
// File   : ShardInventoryDto.cs
// Project: RdpAudit.Core (RdpAudit.Core.Ipc.Contracts)
// Purpose: Read-only shard-tree inventory for the Database tab's Shards section (IPC ordinal 88).
//          One entry per .rdpshard file, sourced from IpEventSummary for referenced shards and from
//          the bounded filesystem walk for files no summary row points at (orphans). The summary
//          carries the tree aggregate so an operator can see the footprint without a grid. Strictly
//          a projection: the command never writes, moves, quarantines or deletes a shard file -
//          capacity governance and orphan GC are later stages.
// Depends: MessagePack, IpcResultStatus
// Extends: Append fields only; [Key] indices are an append-only ABI.

using MessagePack;

namespace RdpAudit.Core.Ipc.Contracts;

/// <summary>One .rdpshard file as seen by the inventory.</summary>
[MessagePackObject(keyAsPropertyName: false)]
public sealed class ShardInventoryEntryDto
{
	/// <summary>Path of the shard file relative to the actions root, forward slashes, matching the
	/// form <see cref="RdpAudit.Core.Models.IpEventSummary.ShardRelativePath"/> is written in.</summary>
	[Key(0)]
	public string RelativePath { get; set; } = string.Empty;

	/// <summary>Canonical textual IP of the owning summary row; empty for an orphan file whose
	/// owner is unknown.</summary>
	[Key(1)]
	public string IpText { get; set; } = string.Empty;

	/// <summary>Uppercase hexadecimal source address derived from the shard file name; empty when
	/// the file name is not a valid shard name.</summary>
	[Key(2)]
	public string IpHex { get; set; } = string.Empty;

	/// <summary>Live records the shard ring retains; <c>-1</c> when unknown (the summary row is
	/// missing or the header could not be read).</summary>
	[Key(3)]
	public long Records { get; set; } = -1;

	/// <summary>On-disk length of the shard file in bytes; <c>-1</c> when it could not be measured.</summary>
	[Key(4)]
	public long Bytes { get; set; } = -1;

	/// <summary>Binary format version from the summary row or the shard header; <c>-1</c> when unknown.</summary>
	[Key(5)]
	public int FormatVersion { get; set; } = -1;

	/// <summary>Records the ring has evicted so far; <c>-1</c> when unknown.</summary>
	[Key(6)]
	public long Evicted { get; set; } = -1;

	/// <summary>UTC instant of the oldest record the shard retains; null when unknown.</summary>
	[Key(7)]
	public DateTime? OldestRetainedUtc { get; set; }

	/// <summary>True when no <c>IpEventSummary</c> row references this file. The inventory only
	/// reports orphans; collecting them is the shard-governance stage's job.</summary>
	[Key(8)]
	public bool IsOrphan { get; set; }

	/// <summary>True when the owning summary row is a subnet aggregate rather than one host.</summary>
	[Key(9)]
	public bool IsSubnetAggregate { get; set; }

	/// <summary>Operator-facing note for a degraded read (for example an unreadable header); null
	/// when the entry was read cleanly.</summary>
	[Key(10)]
	public string? Note { get; set; }

	/// <summary>UTC instant of the file's last write, which is the only per-file activity timestamp the
	/// service can observe without inventing one; null when it could not be read.</summary>
	[Key(11)]
	public DateTime? LastWriteUtc { get; set; }

	/// <summary>How many <c>IpEventSummary</c> rows name this file. Greater than one means a subnet
	/// aggregate shared by several sources; zero never appears here, because a file no row names is an
	/// orphan entry instead.</summary>
	[Key(12)]
	public int SharedBySourceCount { get; set; } = 1;
}

/// <summary>Tree-wide aggregate of the inventory, so an operator can see the shard footprint
/// without paging through the grid.</summary>
[MessagePackObject(keyAsPropertyName: false)]
public sealed class ShardInventorySummaryDto
{
	/// <summary>Number of .rdpshard files seen during the bounded walk.</summary>
	[Key(0)]
	public long ShardFiles { get; set; }

	/// <summary>Number of shard files no summary row references.</summary>
	[Key(1)]
	public long OrphanFiles { get; set; }

	/// <summary>Total bytes of the orphan files.</summary>
	[Key(2)]
	public long OrphanBytes { get; set; }

	/// <summary>Total bytes of every shard file seen (orphans included).</summary>
	[Key(3)]
	public long TotalShardBytes { get; set; }

	/// <summary>Sum of live records across shards whose count is known; <c>-1</c> when no count
	/// could be read at all.</summary>
	[Key(4)]
	public long TotalRecords { get; set; }

	/// <summary>Sum of evicted counts across shards whose header is known.</summary>
	[Key(5)]
	public long TotalEvicted { get; set; }

	/// <summary>Total number of files the walk saw (shard and non-shard), so a truncated walk is
	/// visible as a lower bound.</summary>
	[Key(6)]
	public long ScannedFileCount { get; set; }

	/// <summary>True when the walk stopped before the whole tree was enumerated, so every count
	/// above is a lower bound.</summary>
	[Key(7)]
	public bool Truncated { get; set; }

	/// <summary>Number of entries the response carries after the bounded cut. Equals
	/// <see cref="ShardInventoryDto.Entries"/>.Count.</summary>
	[Key(8)]
	public int EntriesReturned { get; set; }
}

/// <summary>Response of <c>GetShardInventory</c>: the shard tree cross-referenced with the
/// per-IP summaries.</summary>
[MessagePackObject(keyAsPropertyName: false)]
public sealed class ShardInventoryDto
{
	/// <summary><see cref="IpcResultStatus.Unavailable"/> when neither the store nor the tree
	/// could be examined; <see cref="IpcResultStatus.Success"/> otherwise, even when truncated.</summary>
	[Key(0)]
	public IpcResultStatus Status { get; set; } = IpcResultStatus.Success;

	/// <summary>UTC instant this inventory describes. Every field is "as of" this stamp.</summary>
	[Key(1)]
	public DateTime QueriedUtc { get; set; }

	/// <summary>Absolute actions root the walk started from.</summary>
	[Key(2)]
	public string ActionsRoot { get; set; } = string.Empty;

	/// <summary>True when per-IP shard writing is enabled; shards can still exist when disabled.</summary>
	[Key(3)]
	public bool ShardingEnabled { get; set; }

	/// <summary>Inventory entries: referenced shards first (by relative path), then orphans.</summary>
	[Key(4)]
	public List<ShardInventoryEntryDto> Entries { get; set; } = new();

	/// <summary>Tree-wide aggregate.</summary>
	[Key(5)]
	public ShardInventorySummaryDto Summary { get; set; } = new();

	/// <summary>One line per degraded part of the walk, for direct display.</summary>
	[Key(6)]
	public List<string> Warnings { get; set; } = new();

	/// <summary>Operator-facing summary; never carries secret material.</summary>
	[Key(7)]
	public string? Message { get; set; }

	/// <summary>The effective sharding policy and its bounds. The policy is read here rather than from a
	/// separate command, so a client that polls the inventory always sees the policy the service is
	/// actually enforcing.</summary>
	[Key(8)]
	public ShardingPolicyDto? Policy { get; set; }

	/// <summary>Live capacity state of the running sink: why it is refusing new files, for how long and
	/// how many sources that affected, whether the byte budget or the disk floor is breached, and
	/// whether the cardinality guard is engaged.</summary>
	[Key(9)]
	public ShardCapacityStatusDto? CapacityStatus { get; set; }
}
