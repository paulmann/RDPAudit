/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 2.0.0
// File   : ShardCardinalityGuardTests.cs
// Project: RdpAudit.Core.Tests (RdpAudit.Core.Tests.Sharding)
// Purpose: Verifies the cardinality-guard decision in isolation: with the guard off no decision ever
//          aggregates and nothing is tracked; with it on the two ceilings engage it, a proven
//          high-volume source keeps its own file, the rate window rolls over on its own and the tracked
//          source table stays bounded under a spray.
// Depends: ShardCardinalityGuard, SubnetAggregationOptions
// Extends: System.Object

using RdpAudit.Core.Config;
using RdpAudit.Core.Storage.Sharding;
using Xunit;

namespace RdpAudit.Core.Tests.Sharding;

public sealed class ShardCardinalityGuardTests
{
	/// <summary>Given the guard is disabled, when events are observed and a decision is asked for under
	/// breached thresholds, then nothing aggregates and nothing is tracked: the disabled guard is
	/// indistinguishable from the pre-Stage-4 sink.</summary>
	[Fact]
	public void DisabledGuard_NeverAggregatesAndTracksNothing()
	{
		ShardCardinalityGuard guard = new();
		SubnetAggregationOptions options = new() { Enabled = false, TotalFileThreshold = 1, NewFilesPerIntervalLimit = 1 };
		long now = DateTime.UtcNow.Ticks;

		Assert.Equal(0, guard.Observe(options, now, "source"));
		Assert.False(guard.IsThresholdBreached(options, shardFileCount: 1_000_000));

		ShardAggregationDecision decision = guard.Decide(options, shardFileCount: 1_000_000, sourceRowsInInterval: 0);
		Assert.False(decision.Aggregate);
		Assert.Equal(ShardAggregationTrigger.None, decision.Trigger);
		Assert.False(decision.GuardEnabled);
		Assert.Equal(0, guard.TrackedSourceCount);
		Assert.Equal(0, guard.NewFilesInInterval);
	}

	/// <summary>Given the guard is on and neither ceiling is breached, when a new source is decided,
	/// then it keeps its own shard file.</summary>
	[Fact]
	public void BelowBothCeilings_KeepsThePerIpFile()
	{
		ShardCardinalityGuard guard = new();
		SubnetAggregationOptions options = new() { Enabled = true, TotalFileThreshold = 10, NewFilesPerIntervalLimit = 10 };
		long now = DateTime.UtcNow.Ticks;

		guard.Observe(options, now, "source");
		ShardAggregationDecision decision = guard.Decide(options, shardFileCount: 10, sourceRowsInInterval: 0);

		Assert.False(decision.Aggregate);
		Assert.True(decision.GuardEnabled);
	}

	/// <summary>Given the tree already holds more files than the threshold, when a new low-volume source
	/// is decided, then it is routed into a subnet aggregate and the trigger names the file count.</summary>
	[Fact]
	public void FileCountAboveThreshold_AggregatesALowVolumeSource()
	{
		ShardCardinalityGuard guard = new();
		SubnetAggregationOptions options = new()
		{
			Enabled = true,
			TotalFileThreshold = 4,
			NewFilesPerIntervalLimit = 1000,
			MinSourceRowsPerInterval = 8,
		};
		long now = DateTime.UtcNow.Ticks;
		int priorRows = guard.Observe(options, now, "source");

		ShardAggregationDecision decision = guard.Decide(options, shardFileCount: 5, sourceRowsInInterval: priorRows);

		Assert.True(decision.Aggregate);
		Assert.Equal(ShardAggregationTrigger.FileCount, decision.Trigger);
		Assert.Equal(5, decision.ShardFileCount);
		Assert.Equal(0, decision.SourceRowsInInterval);
	}

	/// <summary>Given this process already created the configured number of files in the interval, when
	/// another new source is decided, then the rate ceiling routes it into an aggregate.</summary>
	[Fact]
	public void NewFileRateAtItsLimit_AggregatesALowVolumeSource()
	{
		ShardCardinalityGuard guard = new();
		SubnetAggregationOptions options = new()
		{
			Enabled = true,
			TotalFileThreshold = 1_000_000,
			NewFilesPerIntervalLimit = 2,
			MinSourceRowsPerInterval = 8,
		};
		long now = DateTime.UtcNow.Ticks;
		guard.NoteNewShardFile(options, now);
		guard.NoteNewShardFile(options, now);

		ShardAggregationDecision decision = guard.Decide(options, shardFileCount: 1, sourceRowsInInterval: 0);

		Assert.Equal(2, guard.NewFilesInInterval);
		Assert.True(decision.Aggregate);
		Assert.Equal(ShardAggregationTrigger.NewFileRate, decision.Trigger);
	}

	/// <summary>Given a source has already produced at least the configured number of rows in the
	/// interval, when a ceiling is breached, then it is not aggregated: a source that has proved its
	/// volume keeps its own shard file.</summary>
	[Fact]
	public void ProvenHighVolumeSource_KeepsItsOwnFileEvenWhenABreachIsActive()
	{
		ShardCardinalityGuard guard = new();
		SubnetAggregationOptions options = new()
		{
			Enabled = true,
			TotalFileThreshold = 1,
			NewFilesPerIntervalLimit = 1,
			MinSourceRowsPerInterval = 3,
		};
		long now = DateTime.UtcNow.Ticks;

		// Observe returns the count before the current event, so the fourth event sees three prior rows.
		Assert.Equal(0, guard.Observe(options, now, "heavy"));
		Assert.Equal(1, guard.Observe(options, now, "heavy"));
		Assert.Equal(2, guard.Observe(options, now, "heavy"));
		int priorRows = guard.Observe(options, now, "heavy");

		Assert.Equal(3, priorRows);
		ShardAggregationDecision decision = guard.Decide(options, shardFileCount: 2, sourceRowsInInterval: priorRows);
		Assert.False(decision.Aggregate);
	}

	/// <summary>Given a rate window has elapsed, when the next event is observed, then the window rolls
	/// over on its own: the new-file counter and the per-source row counts both restart, so a spray that
	/// pauses is not punished forever.</summary>
	[Fact]
	public void ElapsedInterval_RollsTheWindowOver()
	{
		ShardCardinalityGuard guard = new();
		SubnetAggregationOptions options = new()
		{
			Enabled = true,
			TotalFileThreshold = 1_000_000,
			NewFilesPerIntervalLimit = 1,
			IntervalSeconds = 60,
			MinSourceRowsPerInterval = 8,
		};
		long start = DateTime.UtcNow.Ticks;
		guard.NoteNewShardFile(options, start);
		guard.Observe(options, start, "source");
		Assert.Equal(1, guard.NewFilesInInterval);

		long later = start + TimeSpan.FromSeconds(61).Ticks;
		int priorRows = guard.Observe(options, later, "source");

		Assert.Equal(0, priorRows);
		Assert.Equal(0, guard.NewFilesInInterval);
		Assert.False(guard.IsThresholdBreached(options, shardFileCount: 1));
	}

	/// <summary>Given a guard facing an unbounded spray, when hundreds of thousands of distinct sources
	/// are observed, then the tracked table stops growing at its cap and every untracked source reads as
	/// low volume - the guard can never become the memory exhaustion it exists to prevent.</summary>
	[Fact]
	public void SprayBeyondTheCap_KeepsTheTableBounded()
	{
		ShardCardinalityGuard guard = new();
		SubnetAggregationOptions options = new() { Enabled = true, TotalFileThreshold = 1, NewFilesPerIntervalLimit = 1 };
		long now = DateTime.UtcNow.Ticks;

		for (int index = 0; index < ShardCardinalityGuard.MaxTrackedSources + 1000; index++)
		{
			guard.Observe(options, now, "source-" + index.ToString(System.Globalization.CultureInfo.InvariantCulture));
		}

		Assert.Equal(ShardCardinalityGuard.MaxTrackedSources, guard.TrackedSourceCount);
		Assert.Equal(0, guard.Observe(options, now, "never-seen-before"));
	}

	/// <summary>Given the guard is enabled, when an aggregate path is asked for, then the prefix length
	/// is the one the path scheme accepts for the address family and nothing else.</summary>
	[Theory]
	[InlineData(System.Net.Sockets.AddressFamily.InterNetwork, 24)]
	[InlineData(System.Net.Sockets.AddressFamily.InterNetworkV6, 64)]
	public void AggregatePrefixLength_ComesFromThePathScheme(System.Net.Sockets.AddressFamily family, int expected)
	{
		Assert.True(ShardPath.TryGetAggregatePrefixLengthBits(family, out int prefixLenBits));
		Assert.Equal(expected, prefixLenBits);
	}

	/// <summary>Given an address family with no aggregate prefix, when one is asked for, then the call
	/// answers false instead of inventing a prefix.</summary>
	[Fact]
	public void AggregatePrefixLength_IsUnavailableForOtherFamilies()
	{
		Assert.False(ShardPath.TryGetAggregatePrefixLengthBits(System.Net.Sockets.AddressFamily.Unix, out int prefixLenBits));
		Assert.Equal(0, prefixLenBits);
	}
}
