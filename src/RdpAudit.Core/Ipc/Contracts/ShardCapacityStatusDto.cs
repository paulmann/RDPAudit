/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 2.0.0
// File   : ShardCapacityStatusDto.cs
// Project: RdpAudit.Core (RdpAudit.Core.Ipc.Contracts)
// Purpose: Why the shard sink is currently refusing to create new files, and how much it refused.
//          Reaching a ceiling must never quietly stop sharding: this contract is what feeds the red
//          banner in the Database tab's Shards section, and every field states a fact the sink
//          actually observed. A fact the sink cannot know is null (or the documented -1), never a
//          guessed zero.
// Depends: MessagePack
// Extends: Append fields only; [Key] indices are an append-only ABI.

using MessagePack;

namespace RdpAudit.Core.Ipc.Contracts;

/// <summary>Which ceiling refused the most recent new-shard attempt.</summary>
public enum ShardRefusalReason
{
	/// <summary>Nothing has been refused since the service started.</summary>
	None = 0,

	/// <summary>The configured <c>MaxShardFiles</c> count was already reached.</summary>
	FileBudget = 1,

	/// <summary>The whole-tree byte budget <c>MaxTotalShardBytes</c> was already reached.</summary>
	ByteBudget = 2,

	/// <summary>Free space on the shard volume is at or below <c>MinFreeDiskBytes</c>.</summary>
	DiskFloor = 3,
}

/// <summary>Live shard-capacity state of the running service instance.</summary>
[MessagePackObject(keyAsPropertyName: false)]
public sealed class ShardCapacityStatusDto
{
	/// <summary>True while the last new-shard attempt was refused. Cleared only by a successful file
	/// creation, so the banner disappears exactly when sharding works again.</summary>
	[Key(0)]
	public bool RefusalActive { get; set; }

	/// <summary>Reason of the most recent refusal; <see cref="ShardRefusalReason.None"/> when the
	/// service has refused nothing since it started.</summary>
	[Key(1)]
	public ShardRefusalReason LastRefusalReason { get; set; }

	/// <summary>UTC instant of the most recent refusal; null when there has been none.</summary>
	[Key(2)]
	public DateTime? LastRefusalUtc { get; set; }

	/// <summary>UTC instant of the first refusal of the current run of refusals; null when none.</summary>
	[Key(3)]
	public DateTime? RefusalSinceUtc { get; set; }

	/// <summary>Number of distinct sources whose events could not be sharded because a ceiling refused
	/// a new file. Bounded set: once its cap is reached the value is a stated lower bound and
	/// <see cref="RefusedSourceCountIsLowerBound"/> is true.</summary>
	[Key(4)]
	public long RefusedSourceCount { get; set; }

	/// <summary>True when <see cref="RefusedSourceCount"/> stopped growing because the tracking set hit
	/// its cap, so the reported figure is a lower bound.</summary>
	[Key(5)]
	public bool RefusedSourceCountIsLowerBound { get; set; }

	/// <summary>Number of append attempts that were refused, counting repeats from the same source.</summary>
	[Key(6)]
	public long RefusedWriteAttempts { get; set; }

	/// <summary>True when the last new-file check found the shard-file count at or above
	/// <c>MaxShardFiles</c>. Evaluated at the last check, not continuously.</summary>
	[Key(7)]
	public bool FileBudgetExceeded { get; set; }

	/// <summary>True when the last new-file check found the tree at or above
	/// <c>MaxTotalShardBytes</c>.</summary>
	[Key(8)]
	public bool ByteBudgetExceeded { get; set; }

	/// <summary>True when the last new-file check found free space at or below
	/// <c>MinFreeDiskBytes</c>.</summary>
	[Key(9)]
	public bool DiskFloorBreached { get; set; }

	/// <summary>Shard-tree bytes the sink accounted for at its last check; <c>-1</c> when the budget is
	/// disabled and the sink therefore never walks the tree.</summary>
	[Key(10)]
	public long TotalShardBytes { get; set; } = -1;

	/// <summary>Effective whole-tree byte budget; <c>0</c> when disabled.</summary>
	[Key(11)]
	public long MaxTotalShardBytes { get; set; }

	/// <summary>Effective free-space floor; <c>0</c> when disabled.</summary>
	[Key(12)]
	public long MinFreeDiskBytes { get; set; }

	/// <summary>Free bytes on the shard volume at the last check; null when the volume could not be
	/// inspected (the sink then never refuses for this reason and says so instead of inventing a
	/// number).</summary>
	[Key(13)]
	public long? ActionsVolumeFreeBytes { get; set; }

	/// <summary>True when the cardinality guard is configured on.</summary>
	[Key(14)]
	public bool CardinalityGuardEnabled { get; set; }

	/// <summary>True when either guard ceiling is currently breached, so new low-volume sources are
	/// being routed into subnet aggregates.</summary>
	[Key(15)]
	public bool CardinalityGuardActive { get; set; }

	/// <summary>Number of new-source decisions that were routed into a subnet aggregate since the
	/// service started. Tracked per distinct source, bounded by the same cap as the refused-source set.</summary>
	[Key(16)]
	public long AggregatedSourceCount { get; set; }

	/// <summary>True when <see cref="AggregatedSourceCount"/> stopped growing because its tracking set
	/// hit its cap, so the reported figure is a lower bound.</summary>
	[Key(18)]
	public bool AggregatedSourceCountIsLowerBound { get; set; }

	/// <summary>One operator-facing sentence naming the refusal and the number of affected sources;
	/// null when nothing is refused.</summary>
	[Key(17)]
	public string? Message { get; set; }
}
