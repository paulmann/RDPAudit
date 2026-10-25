/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 2.0.0
// File   : ShardingOptionsTests.cs
// Project: RdpAudit.Core.Tests
// Purpose: Locks the shard capacity ceilings: every new option defaults to the pre-Stage-4 behaviour,
//          a hand-edited appsettings.json cannot widen a bound, and the per-shard byte ceiling is
//          converted to a ring capacity honestly - integer division over the fixed 128-byte record,
//          never rounded up, never below one record.
// Depends: ShardingOptions, SubnetAggregationOptions, ShardRecord, ShardHeader
// Extends: System.Object

using RdpAudit.Core.Config;
using RdpAudit.Core.Storage.Sharding;
using Xunit;

namespace RdpAudit.Core.Tests;

public sealed class ShardingOptionsTests
{
	/// <summary>Given a configuration written before the capacity ceilings existed, when the options
	/// are resolved, then every ceiling is disabled and the ring geometry is exactly what it was: the
	/// default configuration cannot change the system's behaviour.</summary>
	[Fact]
	public void Defaults_LeaveEveryCeilingDisabledAndTheRingUnchanged()
	{
		ShardingOptions options = new();

		Assert.False(options.Enabled);
		Assert.Equal(1024, options.ShardCapacityRecords);
		Assert.Equal(1024, options.ResolveShardCapacityRecords());
		Assert.Equal(1024, options.ResolveRingCapacityRecords());
		Assert.Equal(0L, options.ResolveMaxShardBytes());
		Assert.Equal(0L, options.ResolveMaxTotalShardBytes());
		Assert.Equal(0L, options.ResolveMinFreeDiskBytes());
		Assert.Equal(14, options.ResolveOrphanGraceDays());
		Assert.Equal(4096, options.ResolveMaxShardFiles());
		Assert.Equal(128, options.ResolveMaxOpenWriters());
		Assert.False(options.SubnetAggregation.Enabled);
	}

	/// <summary>Given a per-shard byte ceiling, when the ring capacity is resolved, then the ceiling is
	/// converted by integer division over the fixed record size and capped by ShardCapacityRecords.</summary>
	[Theory]
	[InlineData(1024, 16_384, 128)]
	[InlineData(1024, 1_024, 8)]
	[InlineData(8, 16_384, 8)]
	[InlineData(1024, 1_023, 7)]
	[InlineData(1024, 1, 1)]
	public void ByteCeiling_SelectsTheRingCapacityByIntegerDivision(int configuredRecords, long maxShardBytes, int expected)
	{
		ShardingOptions options = new() { ShardCapacityRecords = configuredRecords, MaxShardBytes = maxShardBytes };

		Assert.Equal(expected, options.ResolveRingCapacityRecords());
	}

	/// <summary>Given a byte ceiling below one record, when the ring is resolved, then the capacity is
	/// never zero: a shard that cannot hold a record is not a shard, and ShardWriter refuses a
	/// non-positive capacity outright.</summary>
	[Fact]
	public void ByteCeilingBelowOneRecord_StillResolvesToOneRecord()
	{
		ShardingOptions options = new() { MaxShardBytes = 1 };

		Assert.Equal(ShardingOptions.MinShardCapacityRecords, options.ResolveRingCapacityRecords());
		Assert.True(options.ResolveRingCapacityRecords() > 0);
	}

	/// <summary>Given a resolved ring capacity, when the expected file length is computed, then it is
	/// the two-copy header region plus the fixed-size record ring - the value the sink accounts in its
	/// byte budget and the length ShardWriter pre-allocates.</summary>
	[Fact]
	public void ExpectedFileBytes_IsHeaderRegionPlusRing()
	{
		Assert.Equal(
			ShardHeader.HeaderRegionBytes + (128L * ShardRecord.SizeBytes),
			ShardingOptions.ExpectedShardFileBytes(128));
		Assert.Equal(
			ShardHeader.HeaderRegionBytes + ShardRecord.SizeBytes,
			ShardingOptions.ExpectedShardFileBytes(0));
	}

	/// <summary>Given a hand-edited document with negatives and out-of-range values, when the options
	/// are resolved, then every ceiling is clamped to a value the sink can enforce.</summary>
	[Fact]
	public void HandEditedDocument_CannotWidenABound()
	{
		ShardingOptions options = new()
		{
			ShardCapacityRecords = 0,
			MaxOpenWriters = -5,
			MaxShardFiles = -1,
			MaxShardBytes = -1,
			MaxTotalShardBytes = -1,
			MinFreeDiskBytes = -1,
			OrphanGraceDays = 0,
		};

		Assert.Equal(1, options.ResolveShardCapacityRecords());
		Assert.Equal(1, options.ResolveMaxOpenWriters());
		Assert.Equal(0, options.ResolveMaxShardFiles());
		Assert.Equal(0L, options.ResolveMaxShardBytes());
		Assert.Equal(0L, options.ResolveMaxTotalShardBytes());
		Assert.Equal(0L, options.ResolveMinFreeDiskBytes());
		Assert.Equal(ShardingOptions.MinOrphanGraceDays, options.ResolveOrphanGraceDays());

		options.OrphanGraceDays = int.MaxValue;
		Assert.Equal(ShardingOptions.MaxOrphanGraceDays, options.ResolveOrphanGraceDays());
	}

	/// <summary>Given a configured actions root, when it is resolved, then the configured value wins and
	/// an empty one falls back to the ProgramData default.</summary>
	[Fact]
	public void ActionsRoot_ResolvesConfiguredValueOrDefault()
	{
		ShardingOptions options = new();
		Assert.Equal(RdpAudit.Core.Util.RdpAuditPaths.Default.ActionsRootDirectory, options.ResolveActionsRoot());

		options.ActionsRoot = @"D:\shards";
		Assert.Equal(@"D:\shards", options.ResolveActionsRoot());
	}
}
