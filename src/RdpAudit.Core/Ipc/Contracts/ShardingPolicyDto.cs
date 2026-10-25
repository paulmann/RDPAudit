/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 2.0.0
// File   : ShardingPolicyDto.cs
// Project: RdpAudit.Core (RdpAudit.Core.Ipc.Contracts)
// Purpose: Read contract for the Database tab's Shards policy editor: every ShardingOptions field,
//          the SubnetAggregation thresholds, the derived ring capacity a NEW shard would be allocated
//          with, and the supported bounds - so a client never has to invent a limit. Values are
//          reported, never interpreted: the Resolve* clamps stay the single source of truth in
//          ShardingOptions and SubnetAggregationOptions, and FromOptions is the only producer.
// Depends: MessagePack, ShardingOptions, SubnetAggregationOptions
// Extends: Append fields only; [Key] indices are an append-only ABI. Every new clampsable sharding
//          option must appear here as Configured + Effective.

using MessagePack;
using RdpAudit.Core.Config;

namespace RdpAudit.Core.Ipc.Contracts;

/// <summary>Supported ranges of the clampsable sharding options. A one-sided bound is reported as a
/// minimum plus a documented "no upper bound" instead of an invented maximum.</summary>
[MessagePackObject(keyAsPropertyName: false)]
public sealed class ShardingPolicyBoundsDto
{
	/// <summary><c>ShardCapacityRecords</c> floor. There is no upper bound.</summary>
	[Key(0)]
	public int MinShardCapacityRecords { get; set; } = ShardingOptions.MinShardCapacityRecords;

	/// <summary><c>MaxOpenWriters</c> floor. There is no upper bound.</summary>
	[Key(1)]
	public int MinMaxOpenWriters { get; set; } = 1;

	/// <summary><c>MaxShardFiles</c> floor; <c>0</c> is accepted and refuses every new file.</summary>
	[Key(2)]
	public int MinMaxShardFiles { get; set; }

	/// <summary><c>OrphanGraceDays</c> lower bound.</summary>
	[Key(3)]
	public int MinOrphanGraceDays { get; set; } = ShardingOptions.MinOrphanGraceDays;

	/// <summary><c>OrphanGraceDays</c> upper bound.</summary>
	[Key(4)]
	public int MaxOrphanGraceDays { get; set; } = ShardingOptions.MaxOrphanGraceDays;

	/// <summary><c>SubnetAggregation.TotalFileThreshold</c> lower bound.</summary>
	[Key(5)]
	public int MinSubnetTotalFileThreshold { get; set; } = SubnetAggregationOptions.MinTotalFileThreshold;

	/// <summary><c>SubnetAggregation.TotalFileThreshold</c> upper bound.</summary>
	[Key(6)]
	public int MaxSubnetTotalFileThreshold { get; set; } = SubnetAggregationOptions.MaxTotalFileThreshold;

	/// <summary><c>SubnetAggregation.NewFilesPerIntervalLimit</c> lower bound.</summary>
	[Key(7)]
	public int MinSubnetNewFilesPerIntervalLimit { get; set; } = SubnetAggregationOptions.MinNewFilesPerIntervalLimit;

	/// <summary><c>SubnetAggregation.NewFilesPerIntervalLimit</c> upper bound.</summary>
	[Key(8)]
	public int MaxSubnetNewFilesPerIntervalLimit { get; set; } = SubnetAggregationOptions.MaxNewFilesPerIntervalLimit;

	/// <summary><c>SubnetAggregation.IntervalSeconds</c> lower bound.</summary>
	[Key(9)]
	public int MinSubnetIntervalSeconds { get; set; } = SubnetAggregationOptions.MinIntervalSeconds;

	/// <summary><c>SubnetAggregation.IntervalSeconds</c> upper bound.</summary>
	[Key(10)]
	public int MaxSubnetIntervalSeconds { get; set; } = SubnetAggregationOptions.MaxIntervalSeconds;

	/// <summary><c>SubnetAggregation.MinSourceRowsPerInterval</c> upper bound. Its floor is <c>0</c>,
	/// which means "every new source is low volume".</summary>
	[Key(11)]
	public int MaxSubnetMinSourceRowsPerInterval { get; set; } = SubnetAggregationOptions.MaxMinSourceRowsPerInterval;
}

/// <summary>
/// Every sharding option as configured and as effective. A field with a <c>Resolve*</c> clamp carries
/// both values; a field without one carries only the configured value, already normalised to its
/// documented floor by <see cref="FromOptions"/> (so a negative <c>MaxShardBytes</c> is reported as 0,
/// never as a negative ceiling).
/// </summary>
[MessagePackObject(keyAsPropertyName: false)]
public sealed class ShardingPolicyValuesDto
{
	// ── Master switch and root ──────────────────────────────────────────────────

	/// <summary>True when per-IP shard writing is enabled.</summary>
	[Key(0)]
	public bool Enabled { get; set; }

	/// <summary>Configured absolute actions root; empty means the ProgramData default is used.</summary>
	[Key(1)]
	public string ActionsRoot { get; set; } = string.Empty;

	// ── Ring geometry ───────────────────────────────────────────────────────────

	/// <summary>Configured <c>ShardCapacityRecords</c>.</summary>
	[Key(2)]
	public int ShardCapacityRecords { get; set; }

	/// <summary><c>ShardCapacityRecords</c> after its floor of one record.</summary>
	[Key(3)]
	public int EffectiveShardCapacityRecords { get; set; }

	/// <summary>Ring capacity a newly created shard is actually allocated with: the effective capacity
	/// capped by the per-shard byte ceiling, converted to records by integer division.</summary>
	[Key(4)]
	public int EffectiveRingCapacityRecords { get; set; }

	/// <summary>On-disk length a new shard of <see cref="EffectiveRingCapacityRecords"/> occupies:
	/// the 128-byte header region plus <c>capacity * 128</c> bytes of record ring.</summary>
	[Key(5)]
	public long EffectiveShardFileBytes { get; set; }

	// ── Writer pool and file budget ─────────────────────────────────────────────

	/// <summary>Configured <c>MaxOpenWriters</c>.</summary>
	[Key(6)]
	public int MaxOpenWriters { get; set; }

	/// <summary><c>MaxOpenWriters</c> after its floor of one writer.</summary>
	[Key(7)]
	public int EffectiveMaxOpenWriters { get; set; }

	/// <summary>Configured <c>MaxShardFiles</c>.</summary>
	[Key(8)]
	public int MaxShardFiles { get; set; }

	/// <summary><c>MaxShardFiles</c> after its floor of zero.</summary>
	[Key(9)]
	public int EffectiveMaxShardFiles { get; set; }

	// ── Byte and disk ceilings ──────────────────────────────────────────────────

	/// <summary>Per-shard byte ceiling; <c>0</c> disables it.</summary>
	[Key(10)]
	public long MaxShardBytes { get; set; }

	/// <summary>Whole-tree byte budget for <c>actions\</c>; <c>0</c> disables it.</summary>
	[Key(11)]
	public long MaxTotalShardBytes { get; set; }

	/// <summary>Free-space floor of the shard volume in bytes; <c>0</c> disables it.</summary>
	[Key(12)]
	public long MinFreeDiskBytes { get; set; }

	/// <summary>Configured orphan grace period in days.</summary>
	[Key(13)]
	public int OrphanGraceDays { get; set; }

	/// <summary><c>OrphanGraceDays</c> after its supported range.</summary>
	[Key(14)]
	public int EffectiveOrphanGraceDays { get; set; }

	// ── Cardinality guard ───────────────────────────────────────────────────────

	/// <summary>True when the shard-cardinality guard may route new sources into a subnet aggregate.</summary>
	[Key(15)]
	public bool SubnetAggregationEnabled { get; set; }

	/// <summary>Configured shard-file count above which the guard engages.</summary>
	[Key(16)]
	public int SubnetAggregationTotalFileThreshold { get; set; }

	/// <summary>Effective shard-file count above which the guard engages.</summary>
	[Key(17)]
	public int EffectiveSubnetAggregationTotalFileThreshold { get; set; }

	/// <summary>Configured new-files-per-interval ceiling.</summary>
	[Key(18)]
	public int SubnetAggregationNewFilesPerIntervalLimit { get; set; }

	/// <summary>Effective new-files-per-interval ceiling.</summary>
	[Key(19)]
	public int EffectiveSubnetAggregationNewFilesPerIntervalLimit { get; set; }

	/// <summary>Configured rate-window length in seconds.</summary>
	[Key(20)]
	public int SubnetAggregationIntervalSeconds { get; set; }

	/// <summary>Effective rate-window length in seconds.</summary>
	[Key(21)]
	public int EffectiveSubnetAggregationIntervalSeconds { get; set; }

	/// <summary>Configured per-source low-volume row threshold.</summary>
	[Key(22)]
	public int SubnetAggregationMinSourceRowsPerInterval { get; set; }

	/// <summary>Effective per-source low-volume row threshold.</summary>
	[Key(23)]
	public int EffectiveSubnetAggregationMinSourceRowsPerInterval { get; set; }

	// ── Projection ──────────────────────────────────────────────────────────────

	/// <summary>The values the service would enforce for <paramref name="options"/>, produced by the
	/// same <c>Resolve*</c> helpers the sink uses. The only producer of this contract, so a client
	/// cannot display a value the service would not apply.</summary>
	public static ShardingPolicyValuesDto FromOptions(ShardingOptions options)
	{
		ArgumentNullException.ThrowIfNull(options);
		int effectiveCapacity = options.ResolveShardCapacityRecords();
		int ringCapacity = options.ResolveRingCapacityRecords();
		return new ShardingPolicyValuesDto
		{
			Enabled = options.Enabled,
			ActionsRoot = options.ActionsRoot,
			ShardCapacityRecords = options.ShardCapacityRecords,
			EffectiveShardCapacityRecords = effectiveCapacity,
			EffectiveRingCapacityRecords = ringCapacity,
			EffectiveShardFileBytes = ShardingOptions.ExpectedShardFileBytes(ringCapacity),
			MaxOpenWriters = options.MaxOpenWriters,
			EffectiveMaxOpenWriters = options.ResolveMaxOpenWriters(),
			MaxShardFiles = options.MaxShardFiles,
			EffectiveMaxShardFiles = options.ResolveMaxShardFiles(),
			MaxShardBytes = options.ResolveMaxShardBytes(),
			MaxTotalShardBytes = options.ResolveMaxTotalShardBytes(),
			MinFreeDiskBytes = options.ResolveMinFreeDiskBytes(),
			OrphanGraceDays = options.OrphanGraceDays,
			EffectiveOrphanGraceDays = options.ResolveOrphanGraceDays(),
			SubnetAggregationEnabled = options.SubnetAggregation.Enabled,
			SubnetAggregationTotalFileThreshold = options.SubnetAggregation.TotalFileThreshold,
			EffectiveSubnetAggregationTotalFileThreshold = options.SubnetAggregation.ResolveTotalFileThreshold(),
			SubnetAggregationNewFilesPerIntervalLimit = options.SubnetAggregation.NewFilesPerIntervalLimit,
			EffectiveSubnetAggregationNewFilesPerIntervalLimit = options.SubnetAggregation.ResolveNewFilesPerIntervalLimit(),
			SubnetAggregationIntervalSeconds = options.SubnetAggregation.IntervalSeconds,
			EffectiveSubnetAggregationIntervalSeconds = options.SubnetAggregation.ResolveIntervalSeconds(),
			SubnetAggregationMinSourceRowsPerInterval = options.SubnetAggregation.MinSourceRowsPerInterval,
			EffectiveSubnetAggregationMinSourceRowsPerInterval = options.SubnetAggregation.ResolveMinSourceRowsPerInterval(),
		};
	}
}

/// <summary>Response of <c>SaveShardingPolicy</c> and the policy section of the shard inventory: the
/// effective shard policy plus the bounds a client may offer.</summary>
[MessagePackObject(keyAsPropertyName: false)]
public sealed class ShardingPolicyDto
{
	/// <summary><see cref="IpcResultStatus.Success"/> when the policy was read or written;
	/// <see cref="IpcResultStatus.InvalidRequest"/> and <see cref="IpcResultStatus.Refused"/> are used
	/// by the save path and always mean nothing was written.</summary>
	[Key(0)]
	public IpcResultStatus Status { get; set; } = IpcResultStatus.Success;

	/// <summary>UTC instant this policy describes.</summary>
	[Key(1)]
	public DateTime QueriedUtc { get; set; }

	/// <summary>Effective values, as the service enforces them.</summary>
	[Key(2)]
	public ShardingPolicyValuesDto Policy { get; set; } = new();

	/// <summary>Supported bounds, so the editor offers exactly what the service accepts.</summary>
	[Key(3)]
	public ShardingPolicyBoundsDto Bounds { get; set; } = new();

	/// <summary>Absolute path of the settings document the save path writes.</summary>
	[Key(4)]
	public string SettingsPath { get; set; } = string.Empty;

	/// <summary>True when the write path re-reads the document through the live options monitor, so the
	/// change is in force without a service restart. Always true for this command; reported so a client
	/// never has to assume it.</summary>
	[Key(5)]
	public bool HotReloaded { get; set; }

	/// <summary>Operator-facing summary; never carries secret material.</summary>
	[Key(6)]
	public string? Message { get; set; }
}
