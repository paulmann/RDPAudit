/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 2.0.0
// File   : ShardingPolicyMutationRequest.cs
// Project: RdpAudit.Core (RdpAudit.Core.Ipc.Contracts)
// Purpose: Write contract of SaveShardingPolicy. Carries the complete sharding policy, so a save is
//          a replacement and never a partial update, and the service can validate the whole document
//          before it writes anything. Structural faults (a negative ceiling, an unusable actions root)
//          are refused with no write at all; a value above a supported maximum is clamped and the
//          clamped value is reported back, exactly like the retention-policy save.
// Depends: MessagePack
// Extends: Append fields only; [Key] indices are an append-only ABI.

using MessagePack;

namespace RdpAudit.Core.Ipc.Contracts;

/// <summary>Subnet-aggregation thresholds carried by a sharding-policy save.</summary>
[MessagePackObject(keyAsPropertyName: false)]
public sealed class SubnetAggregationMutationDto
{
	/// <summary>True when the cardinality guard may route new sources into a subnet aggregate.</summary>
	[Key(0)]
	public bool Enabled { get; set; }

	/// <summary>Shard-file count above which the guard engages.</summary>
	[Key(1)]
	public int TotalFileThreshold { get; set; } = 4096;

	/// <summary>New shard files one interval may create before the guard engages.</summary>
	[Key(2)]
	public int NewFilesPerIntervalLimit { get; set; } = 64;

	/// <summary>Length of the rate window in seconds.</summary>
	[Key(3)]
	public int IntervalSeconds { get; set; } = 60;

	/// <summary>Per-source row count below which a source counts as low volume.</summary>
	[Key(4)]
	public int MinSourceRowsPerInterval { get; set; } = 8;
}

/// <summary>Request of <c>SaveShardingPolicy</c>: the complete desired sharding policy.</summary>
[MessagePackObject(keyAsPropertyName: false)]
public sealed class ShardingPolicyMutationRequest
{
	/// <summary>Desired state of per-IP shard writing.</summary>
	[Key(0)]
	public bool Enabled { get; set; }

	/// <summary>Absolute actions root, or empty for the ProgramData default. A non-empty value must be
	/// an absolute path that is not a drive root.</summary>
	[Key(1)]
	public string ActionsRoot { get; set; } = string.Empty;

	/// <summary>Ring capacity per shard, in records. Must not be negative.</summary>
	[Key(2)]
	public int ShardCapacityRecords { get; set; } = 1024;

	/// <summary>Maximum cached open shard writers. Must not be negative.</summary>
	[Key(3)]
	public int MaxOpenWriters { get; set; } = 128;

	/// <summary>Maximum number of shard files this service instance may create. Must not be negative;
	/// zero refuses every new file.</summary>
	[Key(4)]
	public int MaxShardFiles { get; set; } = 4096;

	/// <summary>Per-shard byte ceiling; zero disables it. Must not be negative.</summary>
	[Key(5)]
	public long MaxShardBytes { get; set; }

	/// <summary>Whole-tree byte budget for <c>actions\</c>; zero disables it. Must not be negative.</summary>
	[Key(6)]
	public long MaxTotalShardBytes { get; set; }

	/// <summary>Free-space floor of the shard volume in bytes; zero disables it. Must not be negative.</summary>
	[Key(7)]
	public long MinFreeDiskBytes { get; set; }

	/// <summary>Orphan grace period in days. Must not be negative.</summary>
	[Key(8)]
	public int OrphanGraceDays { get; set; } = 14;

	/// <summary>Cardinality-guard thresholds.</summary>
	[Key(9)]
	public SubnetAggregationMutationDto SubnetAggregation { get; set; } = new();
}
