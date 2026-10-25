/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 2.0.0
// File   : ShardCapacityGovernanceTests.cs
// Project: RdpAudit.Service.Tests (RdpAudit.Service.Tests.Storage)
// Purpose: Verifies the Stage 4 shard capacity governance on a real filesystem and a real
//          IpEventSummary: the per-shard byte ceiling selects the ring capacity of a new shard and
//          keeps eviction O(1) and exact, the whole-tree byte budget and the free-disk floor refuse new
//          files while already-open shards keep being written, every refusal is visible in the metric
//          and in the live capacity state, and the cardinality guard routes low-volume new sources into
//          an IPv4 /24 aggregate bucket whose summary rows are flagged truthfully.
// Depends: ShardIngestionSink, ShardReader, ShardPath, AuditDbContext, SqliteConnection
// Extends: Add a case here for every new ceiling or guard trigger; never assert on a value the sink
//          could not observe.

using System.Net;
using System.Net.Sockets;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using RdpAudit.Core.Config;
using RdpAudit.Core.Data;
using RdpAudit.Core.Ipc.Contracts;
using RdpAudit.Core.Models;
using RdpAudit.Core.Storage.Sharding;
using RdpAudit.Service.Storage;
using Xunit;

namespace RdpAudit.Service.Tests.Storage;

public sealed class ShardCapacityGovernanceTests : IDisposable
{
	private readonly string _directory = Path.Combine(Path.GetTempPath(), Path.GetRandomFileName());
	private readonly SqliteConnection _connection = new("DataSource=:memory:");

	public ShardCapacityGovernanceTests()
	{
		Directory.CreateDirectory(_directory);
		_connection.Open();
		DbContextOptions<AuditDbContext> options = new DbContextOptionsBuilder<AuditDbContext>().UseSqlite(_connection).Options;
		using AuditDbContext context = new(options);
		context.Database.EnsureCreated();
	}

	public void Dispose()
	{
		_connection.Dispose();
		SqliteConnection.ClearAllPools();
		try { Directory.Delete(_directory, recursive: true); }
		catch (IOException) { }
		catch (UnauthorizedAccessException) { }
	}

	// ── Per-shard byte ceiling ───────────────────────────────────────────────────

	/// <summary>Given a per-shard byte ceiling, when a new shard is created, then its ring is sized by
	/// the ceiling (integer division over the fixed 128-byte record), eviction stays an exact O(1)
	/// ring-head advance and the reported record count is the ring's live count, not the event count.</summary>
	[Fact]
	public async Task ByteCeiling_SelectsTheRingCapacityAndKeepsEvictionExact()
	{
		const string ip = "203.0.113.40";
		// 512 bytes / 128 bytes per record = 4 records, well below the configured 1024.
		using ShardIngestionSink sink = CreateSink(options => options.MaxShardBytes = 512);
		for (int index = 1; index <= 6; index++)
		{
			RawEvent rawEvent = CreateEvent(ip, index);
			await AddSummaryAsync(rawEvent);
			sink.Append(rawEvent);
		}
		await CommitAsync(sink);

		ShardColumns columns = ReadColumns(ip);
		Assert.Equal(4, columns.RecordCount);
		Assert.Equal(2, columns.EvictedCount);
		Assert.True(columns.IsSubnetAggregate.HasValue);
		Assert.False(columns.IsSubnetAggregate!.Value);

		// Once the ring has evicted, the sink cannot know which record is oldest, so it reports NULL
		// instead of inventing the current time or keeping a stale value.
		Assert.Null(columns.OldestRetainedUtc);

		string shardPath = Path.Combine(_directory, columns.RelativePath!.Replace('/', Path.DirectorySeparatorChar));
		Assert.Equal(
			ShardingOptions.ExpectedShardFileBytes(4),
			new FileInfo(shardPath).Length);
		using ShardReader reader = Assert.IsType<ShardReader>(ShardReader.Open(shardPath));
		Assert.Equal(4u, reader.Snapshot.Capacity);
		Assert.Equal(2UL, reader.Snapshot.TotalEvicted);
		Assert.Equal(new long[] { 3L, 4L, 5L, 6L }, reader.ReadAll().Select(record => record.Sequence));
	}

	/// <summary>Given a shard that was created before the byte ceiling was set, when the sink reopens it,
	/// then the file keeps its own ring capacity: a ceiling never re-shapes evidence that is already on
	/// disk, so the shard's records and its eviction total survive.</summary>
	[Fact]
	public async Task ByteCeiling_DoesNotReshapeAnExistingShard()
	{
		const string ip = "203.0.113.41";
		using (ShardIngestionSink wide = CreateSink(_ => { }))
		{
			RawEvent rawEvent = CreateEvent(ip, 1);
			await AddSummaryAsync(rawEvent);
			wide.Append(rawEvent);
			await CommitAsync(wide);
		}

		ShardColumns before = ReadColumns(ip);
		string shardPath = Path.Combine(_directory, before.RelativePath!.Replace('/', Path.DirectorySeparatorChar));
		long lengthBefore = new FileInfo(shardPath).Length;

		using (ShardIngestionSink narrow = CreateSink(options => options.MaxShardBytes = 512))
		{
			RawEvent second = CreateEvent(ip, 2);
			await AddSummaryAsync(second);
			narrow.Append(second);
			await CommitAsync(narrow);
		}

		ShardColumns after = ReadColumns(ip);
		Assert.Equal(2, after.RecordCount);
		Assert.Equal(0, after.EvictedCount);
		Assert.Equal(lengthBefore, new FileInfo(shardPath).Length);
	}

	// ── Whole-tree byte budget ───────────────────────────────────────────────────

	/// <summary>Given the tree reaches the byte budget, when another source needs a new shard, then the
	/// file is refused, the refusal is counted and named, and the shard that is already open keeps being
	/// written - a ceiling never stops evidence collection.</summary>
	[Fact]
	public async Task ByteBudget_RefusesNewFilesAndKeepsExistingShardsWritable()
	{
		const string first = "203.0.113.50";
		const string second = "203.0.113.51";
		ServiceMetrics metrics = new();
		// Exactly one shard of the configured 4-record ring fits in the budget.
		long oneShard = ShardingOptions.ExpectedShardFileBytes(4);
		using ShardIngestionSink sink = CreateSink(
			options =>
			{
				options.MaxTotalShardBytes = oneShard;
				options.ShardCapacityRecords = 4;
			},
			metrics);

		RawEvent firstEvent = CreateEvent(first, 1);
		await AddSummaryAsync(firstEvent);
		sink.Append(firstEvent);

		RawEvent secondEvent = CreateEvent(second, 2);
		await AddSummaryAsync(secondEvent);
		sink.Append(secondEvent);

		// The budget is now reached; the first shard must keep accepting records.
		for (int index = 3; index <= 6; index++)
		{
			RawEvent more = CreateEvent(first, index);
			await AddSummaryAsync(more);
			sink.Append(more);
		}

		await CommitAsync(sink);

		Assert.Equal(1, CountShardFiles());
		Assert.Null(ReadColumns(second).RelativePath);
		Assert.True(metrics.ShardByteBudgetRefusals > 0);
		Assert.Equal(0, metrics.ShardBudgetRefusals);
		ShardColumns columns = ReadColumns(first);
		Assert.Equal(4, columns.RecordCount);
		Assert.Equal(1, columns.EvictedCount);

		ShardCapacityStatusDto status = sink.GetCapacityStatus();
		Assert.True(status.RefusalActive);
		Assert.Equal(ShardRefusalReason.ByteBudget, status.LastRefusalReason);
		Assert.NotNull(status.LastRefusalUtc);
		Assert.NotNull(status.RefusalSinceUtc);
		Assert.Equal(1, status.RefusedSourceCount);
		Assert.True(status.ByteBudgetExceeded);
		Assert.False(status.DiskFloorBreached);
		Assert.Equal(oneShard, status.TotalShardBytes);
		Assert.Contains("byte budget", status.Message ?? string.Empty, StringComparison.Ordinal);
	}

	/// <summary>Given the tree is exactly one file below the byte budget, when the last file that fits
	/// is created, then creation still succeeds: the ceiling refuses the file that would exceed it, not
	/// the one that reaches it.</summary>
	[Fact]
	public async Task ByteBudget_AllowsTheFileThatFits()
	{
		long oneShard = ShardingOptions.ExpectedShardFileBytes(2);
		using ShardIngestionSink sink = CreateSink(options =>
		{
			options.MaxTotalShardBytes = oneShard * 2;
			options.ShardCapacityRecords = 2;
		});
		for (int index = 0; index < 2; index++)
		{
			RawEvent rawEvent = CreateEvent("203.0.113." + (60 + index).ToString(System.Globalization.CultureInfo.InvariantCulture), index + 1);
			await AddSummaryAsync(rawEvent);
			sink.Append(rawEvent);
		}
		await CommitAsync(sink);

		Assert.Equal(2, CountShardFiles());
		Assert.False(sink.GetCapacityStatus().RefusalActive);
	}

	// ── Free-disk floor ─────────────────────────────────────────────────────────

	/// <summary>Given an unreachable free-disk floor, when a new shard is needed, then the sink refuses
	/// it instead of writing, reports the refusal with the disk reason, and does not throw.</summary>
	[Fact]
	public async Task DiskFloor_RefusesNewFilesAndNamesTheReason()
	{
		ServiceMetrics metrics = new();
		using ShardIngestionSink sink = CreateSink(options => options.MinFreeDiskBytes = long.MaxValue, metrics);
		RawEvent rawEvent = CreateEvent("203.0.113.70", 1);
		await AddSummaryAsync(rawEvent);

		sink.Append(rawEvent);
		await CommitAsync(sink);

		Assert.Equal(0, CountShardFiles());
		Assert.Null(ReadColumns(rawEvent.SourceIp!).RelativePath);
		Assert.True(metrics.ShardDiskFloorRefusals > 0);
		ShardCapacityStatusDto status = sink.GetCapacityStatus();
		Assert.True(status.RefusalActive);
		Assert.Equal(ShardRefusalReason.DiskFloor, status.LastRefusalReason);
		Assert.True(status.DiskFloorBreached);
		Assert.NotNull(status.ActionsVolumeFreeBytes);
		Assert.False(status.ByteBudgetExceeded);
		Assert.Contains("floor", status.Message ?? string.Empty, StringComparison.Ordinal);
	}

	/// <summary>Given the configured actions root is not a directory at all, when an event is appended,
	/// then the sink degrades without throwing and refuses to write anywhere.</summary>
	[Fact]
	public async Task UnusableActionsRoot_RefusesWithoutThrowing()
	{
		string rootFile = Path.Combine(_directory, "not-a-directory");
		File.WriteAllText(rootFile, "x");
		RawEvent rawEvent = CreateEvent("203.0.113.71", 1);
		await AddSummaryAsync(rawEvent);
		RdpAuditOptions options = new()
		{
			Sharding = new ShardingOptions { Enabled = true, ActionsRoot = rootFile, MinFreeDiskBytes = long.MaxValue },
		};
		using ShardIngestionSink sink = new(
			new StaticOptionsMonitor<RdpAuditOptions>(options),
			NullLogger<ShardIngestionSink>.Instance,
			new ServiceMetrics());

		sink.Append(rawEvent);
		await CommitAsync(sink);

		Assert.Null(ReadColumns(rawEvent.SourceIp!).RelativePath);
	}

	// ── File budget keeps its own reason ────────────────────────────────────────

	/// <summary>Given both a file budget and a byte budget, when the file budget is the ceiling that
	/// refuses, then the refusal is reported as the file budget: the three ceilings stay distinguishable
	/// in the metric and in the state.</summary>
	[Fact]
	public async Task FileBudget_KeepsItsOwnReasonAndMetric()
	{
		ServiceMetrics metrics = new();
		using ShardIngestionSink sink = CreateSink(
			options =>
			{
				options.MaxShardFiles = 1;
				options.MaxTotalShardBytes = long.MaxValue / 2;
			},
			metrics);

		for (int index = 0; index < 2; index++)
		{
			RawEvent rawEvent = CreateEvent("203.0.113." + (80 + index).ToString(System.Globalization.CultureInfo.InvariantCulture), index + 1);
			await AddSummaryAsync(rawEvent);
			sink.Append(rawEvent);
		}
		await CommitAsync(sink);

		ShardCapacityStatusDto status = sink.GetCapacityStatus();
		Assert.Equal(ShardRefusalReason.FileBudget, status.LastRefusalReason);
		Assert.True(status.RefusalActive);
		Assert.True(metrics.ShardBudgetRefusals > 0);
		Assert.Equal(0, metrics.ShardByteBudgetRefusals);
		Assert.Equal(0, metrics.ShardDiskFloorRefusals);
		Assert.True(status.FileBudgetExceeded);
	}

	// ── Cardinality guard ───────────────────────────────────────────────────────

	/// <summary>Given the guard is engaged by the new-file rate, when a second low-volume source appears
	/// in the same /24, then its records go into the /24 aggregate bucket, the aggregate path carries the
	/// documented suffix with the masked network in its name, the summary row is flagged as a subnet
	/// aggregate, and the shard records themselves carry the aggregate bit.</summary>
	[Fact]
	public async Task CardinalityGuard_RoutesALowVolumeSourceIntoTheSubnetBucket()
	{
		ServiceMetrics metrics = new();
		using ShardIngestionSink sink = CreateSink(
			options =>
			{
				options.ShardCapacityRecords = 8;
				options.SubnetAggregation.Enabled = true;
				options.SubnetAggregation.TotalFileThreshold = 1_000_000;
				options.SubnetAggregation.NewFilesPerIntervalLimit = 1;
				options.SubnetAggregation.IntervalSeconds = 3600;
				options.SubnetAggregation.MinSourceRowsPerInterval = 8;
			},
			metrics);

		RawEvent owner = CreateEvent("203.0.113.90", 1);
		await AddSummaryAsync(owner);
		sink.Append(owner);

		// The rate ceiling is now spent, so this brand-new source is low volume by definition.
		RawEvent sprayed = CreateEvent("203.0.113.91", 2);
		await AddSummaryAsync(sprayed);
		sink.Append(sprayed);
		await CommitAsync(sink);

		ShardColumns columns = ReadColumns(sprayed.SourceIp!);
		Assert.NotNull(columns.RelativePath);
		Assert.EndsWith(ShardPath.AggregateSuffix + ShardPath.ShardExtension, columns.RelativePath!, StringComparison.Ordinal);
		Assert.Equal(
			ShardPath.ActionsRootFolder + "/cb/00/cb007100" + ShardPath.AggregateSuffix + ShardPath.ShardExtension,
			columns.RelativePath);
		Assert.True(columns.IsSubnetAggregate);
		Assert.Equal(1, columns.RecordCount);

		// The first source keeps its own per-IP file, untouched by the guard.
		ShardColumns owned = ReadColumns(owner.SourceIp!);
		Assert.EndsWith("cb00715a" + ShardPath.ShardExtension, owned.RelativePath!, StringComparison.Ordinal);
		Assert.False(owned.IsSubnetAggregate);

		string aggregatePath = Path.Combine(_directory, columns.RelativePath!.Replace('/', Path.DirectorySeparatorChar));
		using ShardReader reader = Assert.IsType<ShardReader>(ShardReader.Open(aggregatePath));
		ShardRecord record = Assert.Single(reader.ReadAll());
		Assert.Equal(4u, record.Flags & 4u);

		Assert.True(metrics.ShardAggregations > 0);
		ShardCapacityStatusDto status = sink.GetCapacityStatus();
		Assert.True(status.CardinalityGuardEnabled);
		Assert.True(status.CardinalityGuardActive);
		Assert.Equal(1, status.AggregatedSourceCount);
	}

	/// <summary>Given two sources share an aggregate bucket, when the batch commits, then both summary
	/// rows name the same file and both are flagged as subnet aggregates - the metadata contract stays
	/// truthful for every source the bucket carries.</summary>
	[Fact]
	public async Task CardinalityGuard_FlagsEverySourceSharingTheBucket()
	{
		using ShardIngestionSink sink = CreateSink(options =>
		{
			options.ShardCapacityRecords = 8;
			options.SubnetAggregation.Enabled = true;
			options.SubnetAggregation.TotalFileThreshold = 1_000_000;
			options.SubnetAggregation.NewFilesPerIntervalLimit = 1;
			options.SubnetAggregation.IntervalSeconds = 3600;
		});

		RawEvent owner = CreateEvent("198.51.100.10", 1);
		await AddSummaryAsync(owner);
		sink.Append(owner);

		RawEvent first = CreateEvent("198.51.100.11", 2);
		RawEvent second = CreateEvent("198.51.100.12", 3);
		await AddSummaryAsync(first);
		await AddSummaryAsync(second);
		sink.Append(first);
		sink.Append(second);
		await CommitAsync(sink);

		ShardColumns firstColumns = ReadColumns(first.SourceIp!);
		ShardColumns secondColumns = ReadColumns(second.SourceIp!);
		Assert.Equal(firstColumns.RelativePath, secondColumns.RelativePath);
		Assert.EndsWith(ShardPath.AggregateSuffix + ShardPath.ShardExtension, secondColumns.RelativePath!, StringComparison.Ordinal);
		Assert.True(firstColumns.IsSubnetAggregate);
		Assert.True(secondColumns.IsSubnetAggregate);
		Assert.Equal(2, secondColumns.RecordCount);
	}

	/// <summary>Given a source in an aggregate bucket reaches the low-volume threshold, when it is
	/// decided again, then it leaves the bucket: its summary row names its own shard from then on, and
	/// the bucket keeps the records it already holds. Evidence is never moved.</summary>
	[Fact]
	public async Task CardinalityGuard_ProvenSourceLeavesTheBucket()
	{
		using ShardIngestionSink sink = CreateSink(options =>
		{
			options.ShardCapacityRecords = 8;
			options.SubnetAggregation.Enabled = true;
			options.SubnetAggregation.TotalFileThreshold = 1_000_000;
			options.SubnetAggregation.NewFilesPerIntervalLimit = 1;
			options.SubnetAggregation.IntervalSeconds = 3600;
			options.SubnetAggregation.MinSourceRowsPerInterval = 2;
		});

		RawEvent owner = CreateEvent("198.51.100.20", 1);
		await AddSummaryAsync(owner);
		sink.Append(owner);

		// Prior row counts for the new source are 0 and 1: both below the threshold of 2, so the first
		// two events go into the bucket and the third (prior count 2) gets its own file.
		for (int index = 2; index <= 4; index++)
		{
			RawEvent rawEvent = CreateEvent("198.51.100.21", index);
			await AddSummaryAsync(rawEvent);
			sink.Append(rawEvent);
		}
		await CommitAsync(sink);

		ShardColumns columns = ReadColumns("198.51.100.21");
		Assert.NotNull(columns.RelativePath);
		Assert.DoesNotContain(ShardPath.AggregateSuffix, columns.RelativePath!, StringComparison.Ordinal);
		Assert.False(columns.IsSubnetAggregate);
		Assert.Equal(1, columns.RecordCount);
	}

	/// <summary>Given the guard is disabled, when a spray of sources in one /24 appears, then every
	/// source keeps its own file: the default configuration behaves exactly as it did before the guard
	/// existed.</summary>
	[Fact]
	public async Task CardinalityGuardDisabled_KeepsOneFilePerSource()
	{
		ServiceMetrics metrics = new();
		using ShardIngestionSink sink = CreateSink(
			options =>
			{
				options.ShardCapacityRecords = 4;
				options.SubnetAggregation.Enabled = false;
				options.SubnetAggregation.NewFilesPerIntervalLimit = 1;
			},
			metrics);

		for (int index = 0; index < 3; index++)
		{
			RawEvent rawEvent = CreateEvent("198.51.100." + (30 + index).ToString(System.Globalization.CultureInfo.InvariantCulture), index + 1);
			await AddSummaryAsync(rawEvent);
			sink.Append(rawEvent);
		}
		await CommitAsync(sink);

		Assert.Equal(3, CountShardFiles());
		Assert.Equal(0, metrics.ShardAggregations);
		ShardCapacityStatusDto status = sink.GetCapacityStatus();
		Assert.False(status.CardinalityGuardEnabled);
		Assert.False(status.CardinalityGuardActive);
		Assert.Equal(0, status.AggregatedSourceCount);
	}

	/// <summary>Given the guard engages, when the first source is routed into a bucket, then the
	/// activation is an operator-visible event: one audit row naming the trigger and the thresholds that
	/// engaged it, plus the metric the diagnostics surface reads.</summary>
	[Fact]
	public async Task CardinalityGuard_ActivationIsAuditedAndCounted()
	{
		RecordingOperationLogWriter audit = new();
		ServiceMetrics metrics = new();
		using ShardIngestionSink sink = CreateSink(
			options =>
			{
				options.ShardCapacityRecords = 4;
				options.SubnetAggregation.Enabled = true;
				options.SubnetAggregation.TotalFileThreshold = 1_000_000;
				options.SubnetAggregation.NewFilesPerIntervalLimit = 1;
				options.SubnetAggregation.IntervalSeconds = 3600;
			},
			metrics,
			audit);

		RawEvent owner = CreateEvent("203.0.113.210", 1);
		await AddSummaryAsync(owner);
		sink.Append(owner);

		// Nothing is aggregated yet, so nothing may be reported as such.
		Assert.Empty(audit.Entries);

		RawEvent sprayed = CreateEvent("203.0.113.211", 2);
		await AddSummaryAsync(sprayed);
		sink.Append(sprayed);
		await CommitAsync(sink);

		OperationLogEntry entry = Assert.Single(audit.Entries);
		Assert.Equal("Sharding", entry.Source);
		Assert.Equal("ShardCardinalityGuard.Engaged", entry.Operation);
		Assert.Contains("NewFileRate", entry.Message, StringComparison.Ordinal);
		Assert.Contains("minSourceRows=8", entry.Message, StringComparison.Ordinal);
		Assert.True(metrics.ShardAggregations > 0);
	}

	/// <summary>Given a refusal, when the first one happens, then it is audited once with the reason
	/// named - the operator learns from the operation log, not only from a counter.</summary>
	[Fact]
	public async Task ByteBudgetRefusal_IsAuditedOnceWithItsReason()
	{
		RecordingOperationLogWriter audit = new();
		using ShardIngestionSink sink = CreateSink(
			options =>
			{
				options.ShardCapacityRecords = 2;
				options.MaxTotalShardBytes = ShardingOptions.ExpectedShardFileBytes(2);
			},
			metrics: null,
			audit);

		for (int index = 0; index < 3; index++)
		{
			RawEvent rawEvent = CreateEvent("203.0.113." + (220 + index).ToString(System.Globalization.CultureInfo.InvariantCulture), index + 1);
			await AddSummaryAsync(rawEvent);
			sink.Append(rawEvent);
		}
		await CommitAsync(sink);

		OperationLogEntry entry = Assert.Single(audit.Entries);
		Assert.Equal("Sharding", entry.Source);
		Assert.Equal("ShardCapacity.Refused", entry.Operation);
		Assert.Contains("byte budget of 384 bytes is reached", entry.Message, StringComparison.Ordinal);
		Assert.Equal("ByteBudget", entry.DetailsJson);
	}

	// ── Capacity state ──────────────────────────────────────────────────────────

	/// <summary>Given every ceiling is disabled, when the capacity state is read, then it reports an
	/// honest absence: no refusal, no byte total (the sink never walks the tree without a reason) and no
	/// guard. Nothing is presented as healthy zero that was never measured.</summary>
	[Fact]
	public void CapacityStatus_WithEveryCeilingDisabled_ReportsAbsence()
	{
		using ShardIngestionSink sink = CreateSink(_ => { });

		ShardCapacityStatusDto status = sink.GetCapacityStatus();

		Assert.False(status.RefusalActive);
		Assert.Equal(ShardRefusalReason.None, status.LastRefusalReason);
		Assert.Null(status.LastRefusalUtc);
		Assert.Null(status.RefusalSinceUtc);
		Assert.Equal(0, status.RefusedSourceCount);
		Assert.False(status.FileBudgetExceeded);
		Assert.False(status.ByteBudgetExceeded);
		Assert.False(status.DiskFloorBreached);
		Assert.Equal(-1, status.TotalShardBytes);
		Assert.Equal(0, status.MaxTotalShardBytes);
		Assert.Equal(0, status.MinFreeDiskBytes);
		Assert.Null(status.Message);
	}

	/// <summary>Given the sink holds an open writer, when the collector asks whether that shard is open,
	/// then the answer is yes for exactly that path - and no for any other, including a file that exists
	/// on disk but has no writer.</summary>
	[Fact]
	public async Task IsShardOpen_AnswersForTheLiveWriterPool()
	{
		const string ip = "203.0.113.99";
		using ShardIngestionSink sink = CreateSink(_ => { });
		RawEvent rawEvent = CreateEvent(ip, 1);
		await AddSummaryAsync(rawEvent);
		sink.Append(rawEvent);

		// The writer pool is consulted before any commit, so the path is composed the same way the sink
		// composes it rather than read back from metadata that has not been written yet.
		char[] relative = new char[64];
		Assert.True(ShardPath.TryComposeShardPath(IPAddress.Parse(ip), relative, out int length));
		string absolute = Path.GetFullPath(Path.Combine(
			_directory,
			new string(relative, 0, length).Replace('/', Path.DirectorySeparatorChar)));

		Assert.True(sink.IsShardOpen(absolute));
		Assert.False(sink.IsShardOpen(absolute + ".other"));
		Assert.False(sink.IsShardOpen(string.Empty));
	}

	// ── Helpers ─────────────────────────────────────────────────────────────────

	private ShardIngestionSink CreateSink(
		Action<ShardingOptions> configure,
		ServiceMetrics? metrics = null,
		IOperationLogWriter? audit = null)
	{
		ShardingOptions sharding = new()
		{
			Enabled = true,
			ActionsRoot = Path.Combine(_directory, ShardPath.ActionsRootFolder),
			ShardCapacityRecords = 1024,
			MaxOpenWriters = 64,
			MaxShardFiles = 4096,
		};
		configure(sharding);
		RdpAuditOptions options = new() { Sharding = sharding };
		return new ShardIngestionSink(
			new StaticOptionsMonitor<RdpAuditOptions>(options),
			NullLogger<ShardIngestionSink>.Instance,
			metrics ?? new ServiceMetrics(),
			audit);
	}

	private int CountShardFiles()
	{
		string root = Path.Combine(_directory, ShardPath.ActionsRootFolder);
		return Directory.Exists(root)
			? Directory.EnumerateFiles(root, "*" + ShardPath.ShardExtension, SearchOption.AllDirectories).Count()
			: 0;
	}

	/// <summary>Given a Service (5) / Batch (4) 4624, when the record is written, then bit0 stays clear —
	/// the forensic record must not claim an RDP success for a logon Windows created locally.</summary>
	[Fact]
	public async Task RecordFlags_NonRdpLogonType_DoesNotSetTheSuccessBit()
	{
		string ip = "203.0.113.44";
		RawEvent serviceLogon = CreateEvent(ip, 1);
		serviceLogon.EventId = 4624;
		serviceLogon.LogonType = 5;

		RawEvent rdpLogon = CreateEvent(ip, 2);
		rdpLogon.EventId = 4624;
		rdpLogon.LogonType = 10;

		using ShardIngestionSink sink = CreateSink(static options => { });
		await AddSummaryAsync(serviceLogon);
		await AddSummaryAsync(rdpLogon);
		sink.Append(serviceLogon);
		sink.Append(rdpLogon);
		await CommitAsync(sink);

		ShardColumns columns = ReadColumns(ip);
		string shardPath = Path.Combine(_directory, columns.RelativePath!.Replace('/', Path.DirectorySeparatorChar));
		using ShardReader reader = Assert.IsType<ShardReader>(ShardReader.Open(shardPath));
		List<ShardRecord> records = [.. reader.ReadAll()];

		Assert.Equal(2, records.Count);
		Assert.Equal(0u, records[0].Flags & 1u);
		Assert.Equal(1u, records[1].Flags & 1u);
	}

	private static RawEvent CreateEvent(string ip, long sequence) => new()
	{
		EventId = 4625,
		Channel = "Security",
		TimeUtc = new DateTime(2026, 8, 14, 1, 0, 0, DateTimeKind.Utc).AddSeconds(sequence),
		IngestionSequence = sequence,
		SourceIp = ip,
		Status = "0xC000006D",
		LogonType = 10,
	};

	private async Task AddSummaryAsync(RawEvent rawEvent)
	{
		IpEventSummaryUpserter upserter = new();
		await using SqliteTransaction transaction = (SqliteTransaction)await _connection.BeginTransactionAsync();
		await upserter.UpsertBatchAsync(_connection, transaction, [rawEvent], CancellationToken.None);
		await transaction.CommitAsync();
	}

	private async Task CommitAsync(ShardIngestionSink sink)
	{
		await using SqliteTransaction transaction = (SqliteTransaction)await _connection.BeginTransactionAsync();
		await sink.CommitAsync(_connection, transaction, CancellationToken.None);
		await transaction.CommitAsync();
	}

	/// <summary>Turns the inventory of one shard file into its column set, keyed by the canonical
	/// textual address the upserter writes.</summary>
	private ShardColumns ReadColumns(string ip)
	{
		IPAddress parsed = IPAddress.Parse(ip);
		string canonical = (parsed.AddressFamily == AddressFamily.InterNetwork ? parsed.MapToIPv6() : parsed).ToString();
		using SqliteCommand command = _connection.CreateCommand();
		command.CommandText = """
SELECT ShardRelativePath, ShardRecordCount, ShardEvictedCount, IsSubnetAggregate, ShardOldestRetainedUtc
FROM IpEventSummary WHERE IpText = $ip;
""";
		command.Parameters.AddWithValue("$ip", canonical);
		using SqliteDataReader reader = command.ExecuteReader();
		Assert.True(reader.Read());
		return new(
			reader.IsDBNull(0) ? null : reader.GetString(0),
			reader.IsDBNull(1) ? null : reader.GetInt64(1),
			reader.IsDBNull(2) ? null : reader.GetInt64(2),
			reader.IsDBNull(3) ? null : reader.GetBoolean(3),
			reader.IsDBNull(4) ? null : reader.GetInt64(4));
	}

	private readonly record struct ShardColumns(
		string? RelativePath,
		long? RecordCount,
		long? EvictedCount,
		bool? IsSubnetAggregate,
		long? OldestRetainedUtc);

	private sealed class StaticOptionsMonitor<T>(T value) : IOptionsMonitor<T>
		where T : class
	{
		public T CurrentValue => value;
		public T Get(string? name) => value;
		public IDisposable? OnChange(Action<T, string?> listener) => null;
	}

	/// <summary>Captures the shard-capacity audit rows. The sink writes them fire-and-forget, but a
	/// completed task records synchronously, so the assertions are deterministic.</summary>
	private sealed class RecordingOperationLogWriter : IOperationLogWriter
	{
		public List<OperationLogEntry> Entries { get; } = new();

		public bool IsDebugEnabled => false;

		public Task WriteAsync(OperationLogEntry entry, CancellationToken ct = default)
		{
			Entries.Add(entry);
			return Task.CompletedTask;
		}

		public Task InfoAsync(string source, string operation, string message, CancellationToken ct = default)
			=> WriteAsync(new OperationLogEntry { Severity = OperationLogSeverity.Information, Source = source, Operation = operation, Message = message }, ct);

		public Task WarnAsync(string source, string operation, string message, string? detailsJson = null, CancellationToken ct = default)
			=> WriteAsync(new OperationLogEntry { Severity = OperationLogSeverity.Warning, Source = source, Operation = operation, Message = message, DetailsJson = detailsJson }, ct);

		public Task ErrorAsync(string source, string operation, string message, Exception? exception, OperationLogSeverity severity = OperationLogSeverity.Error, CancellationToken ct = default)
			=> WriteAsync(new OperationLogEntry { Severity = severity, Source = source, Operation = operation, Message = message, Exception = exception }, ct);

		public Task DebugAsync(string source, string operation, string message, Func<string?>? detailsBuilder = null, string? correlationId = null, CancellationToken ct = default)
			=> Task.CompletedTask;
	}
}
