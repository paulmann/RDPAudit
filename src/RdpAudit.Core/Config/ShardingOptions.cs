/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 2.1.0
// File   : ShardingOptions.cs
// Project: RdpAudit.Core (RdpAudit.Core.Config)
// Purpose: Configures optional durable per-IP forensic shard files, their capacity ceilings
//          (per-file bytes, whole-tree bytes, free-disk floor) and the orphan-collection grace
//          period. Every bound resolves through a clamped Resolve* helper so a hand-edited
//          appsettings.json cannot widen a limit beyond the supported range. The byte ceilings are
//          honest about the fixed shard format: a shard file is pre-allocated to its full ring
//          capacity, so MaxShardBytes can only select the ring capacity of files created after it is
//          set - it never shrinks a file that already exists on disk.
// Depends: System.Environment, ShardPath, ShardHeader, ShardRecord, SubnetAggregationOptions
// Extends: Add a new ceiling here together with its Resolve* clamp, its metric and its profile in
//          docs/86-shard-ingestion.md.

using RdpAudit.Core.Storage.Sharding;
using RdpAudit.Core.Util;

namespace RdpAudit.Core.Config;

/// <summary>Settings for optional per-IP forensic shard storage.</summary>
public sealed class ShardingOptions
{
	// ── Supported bounds ─────────────────────────────────────────────────────────

	/// <summary>Smallest effective ring capacity. A shard must be able to hold at least one record, so
	/// a byte ceiling smaller than one record resolves to this instead of to zero.</summary>
	public const int MinShardCapacityRecords = 1;

	/// <summary>Smallest effective orphan grace period in days. Zero would let a collection pass
	/// delete a shard written moments ago, so it is refused in favour of one day.</summary>
	public const int MinOrphanGraceDays = 1;

	/// <summary>Largest effective orphan grace period in days (ten years).</summary>
	public const int MaxOrphanGraceDays = 3_650;

	// ── Settings ─────────────────────────────────────────────────────────────────

	/// <summary>
	/// Gets or sets whether shard writing is enabled. Defaults to false deliberately: until a
	/// cardinality guard aggregates distributed source addresses, enabling it is safe only for
	/// environments with a bounded, trusted source-IP population and adequate disk monitoring.
	/// </summary>
	public bool Enabled { get; set; }

	/// <summary>Configured absolute actions root, or empty to use ProgramData.</summary>
	public string ActionsRoot { get; set; } = string.Empty;

	/// <summary>Maximum number of fixed-size records retained by one shard ring.</summary>
	public int ShardCapacityRecords { get; set; } = 1024;

	/// <summary>Maximum number of cached open shard writers after a batch commit.</summary>
	public int MaxOpenWriters { get; set; } = 128;

	/// <summary>Maximum number of shard files that may be created by this service instance.</summary>
	public int MaxShardFiles { get; set; } = 4096;

	/// <summary>Gets or sets the per-shard byte ceiling; <c>0</c> disables it (the default, so the
	/// system behaves exactly as before). Because a shard file is pre-allocated to its full ring
	/// capacity, this ceiling selects the ring capacity of files created from now on:
	/// <c>min(ShardCapacityRecords, MaxShardBytes / 128)</c>. It never truncates a file that already
	/// exists - an existing shard keeps the capacity declared in its own header.</summary>
	public long MaxShardBytes { get; set; }

	/// <summary>Gets or sets the whole-tree byte budget for <c>actions\</c>; <c>0</c> disables it.
	/// Once the tree reaches it, new shard files are refused. Open shards keep being written, so a
	/// refusal never loses an event and never corrupts an existing shard.</summary>
	public long MaxTotalShardBytes { get; set; }

	/// <summary>Gets or sets the free-space floor of the volume holding <c>actions\</c>; <c>0</c>
	/// disables it. Once the volume's free space drops to or below it, new shard files are refused so
	/// the evidence store and the event log can never be starved of disk by the shard tree.</summary>
	public long MinFreeDiskBytes { get; set; }

	/// <summary>Gets or sets how long a shard file must have been untouched by the service before it
	/// counts as an orphan eligible for collection. Defaults to 14 days.</summary>
	public int OrphanGraceDays { get; set; } = 14;

	/// <summary>Gets or sets the shard-cardinality guard thresholds. Disabled by default.</summary>
	public SubnetAggregationOptions SubnetAggregation { get; set; } = new();

	// ── Clamped resolution ───────────────────────────────────────────────────────

	/// <summary>Returns the configured actions root or the default ProgramData location.</summary>
	public string ResolveActionsRoot()
	{
		if (!string.IsNullOrWhiteSpace(ActionsRoot))
		{
			return ActionsRoot;
		}

		return RdpAuditPaths.Default.ActionsRootDirectory;
	}

	/// <summary>Returns <see cref="ShardCapacityRecords"/> with the historical one-sided floor applied
	/// (a ring must hold at least one record). Kept one-sided so a configuration that was valid before
	/// the byte ceilings existed stays byte-for-byte identical.</summary>
	public int ResolveShardCapacityRecords() => Math.Max(MinShardCapacityRecords, ShardCapacityRecords);

	/// <summary>Returns <see cref="MaxOpenWriters"/> clamped to at least one writer.</summary>
	public int ResolveMaxOpenWriters() => Math.Max(1, MaxOpenWriters);

	/// <summary>Returns <see cref="MaxShardFiles"/> clamped to at least zero (zero refuses every new
	/// file, which is a legitimate lockdown setting).</summary>
	public int ResolveMaxShardFiles() => Math.Max(0, MaxShardFiles);

	/// <summary>Returns <see cref="MaxShardBytes"/> clamped to at least zero; zero means disabled.</summary>
	public long ResolveMaxShardBytes() => Math.Max(0L, MaxShardBytes);

	/// <summary>Returns <see cref="MaxTotalShardBytes"/> clamped to at least zero; zero means disabled.</summary>
	public long ResolveMaxTotalShardBytes() => Math.Max(0L, MaxTotalShardBytes);

	/// <summary>Returns <see cref="MinFreeDiskBytes"/> clamped to at least zero; zero means disabled.</summary>
	public long ResolveMinFreeDiskBytes() => Math.Max(0L, MinFreeDiskBytes);

	/// <summary>Returns <see cref="OrphanGraceDays"/> clamped to the supported range.</summary>
	public int ResolveOrphanGraceDays()
		=> Math.Clamp(OrphanGraceDays, MinOrphanGraceDays, MaxOrphanGraceDays);

	/// <summary>
	/// Returns the ring capacity a <em>newly created</em> shard is allocated with: the configured
	/// <see cref="ShardCapacityRecords"/>, capped by the per-shard byte ceiling when one is set.
	/// <para>
	/// Honest limitations of a byte ceiling against the fixed shard format:
	/// (1) the record region is <c>capacity * 128</c> bytes, so the ceiling is converted to records by
	/// integer division and the file's real length is
	/// <c>HeaderRegionBytes + capacity * 128</c> - up to 128 bytes above the ceiling, never rounded up;
	/// (2) a shard already on disk keeps its own declared capacity, because re-shaping it would mean
	/// rewriting evidence;
	/// (3) the ring still evicts its oldest record in O(1) at the resolved capacity, so a small ceiling
	/// shortens retention rather than breaking the format.
	/// </para>
	/// </summary>
	public int ResolveRingCapacityRecords()
	{
		int capacity = ResolveShardCapacityRecords();
		long maximumBytes = ResolveMaxShardBytes();
		if (maximumBytes <= 0)
		{
			return capacity;
		}

		long capacityByBytes = maximumBytes / ShardRecord.SizeBytes;
		if (capacityByBytes < MinShardCapacityRecords)
		{
			return MinShardCapacityRecords;
		}

		return (int)Math.Min((long)capacity, capacityByBytes);
	}

	/// <summary>Returns the on-disk length a shard of <paramref name="capacity"/> records occupies:
	/// the two-copy header region plus the fixed-size record ring.</summary>
	public static long ExpectedShardFileBytes(int capacity)
		=> ShardHeader.HeaderRegionBytes + ((long)Math.Max(MinShardCapacityRecords, capacity) * ShardRecord.SizeBytes);
}
