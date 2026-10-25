/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 2.2.0
// File   : ShardIngestionSink.cs
// Project: RdpAudit.Service (RdpAudit.Service.Storage)
// Purpose: Writes committed event evidence into bounded per-IP forensic shard files.
//          v2.1.0: CommitAsync() is a true durability boundary for the shard batch.
//          v2.2.0 (Stage 4 - shard capacity governance): before a NEW shard file is created the sink
//          now enforces three operator-configured ceilings - the per-shard byte ceiling (which selects
//          the ring capacity of the new file), the whole-tree byte budget and the shard volume's
//          free-space floor - and, when the cardinality guard is on, routes low-volume new sources
//          into an IPv4 /24 (IPv6 /64) aggregate bucket instead of a per-IP file. A refusal never
//          crashes, never writes outside actions\, never touches an already-open shard, and is always
//          visible: a per-reason metric, a rate-limited log line, an OperationLog row on the edge and
//          a live refusal state the Database tab reports. No existing shard is rewritten, moved or
//          deleted by this sink.
// Depends: RdpAuditOptions, ShardWriter, RawEvent, ServiceMetrics, SqliteConnection, ShardCardinalityGuard
// Extends: Add a new ceiling as a ShardRefusalReason member plus its metric, its refusal state and its
//          sentence in docs/86-shard-ingestion.md; never let a refusal reopen or rewrite a live shard.

using System.Globalization;
using System.Net;
using System.Net.Sockets;
using Microsoft.Data.Sqlite;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using RdpAudit.Core.Config;
using RdpAudit.Core.Data;
using RdpAudit.Core.Ipc.Contracts;
using RdpAudit.Core.Models;
using RdpAudit.Core.Storage.Sharding;

namespace RdpAudit.Service.Storage;

/// <summary>
/// Minimal writer seam used by tests and by <see cref="ShardFileWriterAdapter"/>.
/// Kept internal so the public <see cref="ShardIngestionSink"/> contract is unchanged.
/// </summary>
internal interface IShardFileWriter : IDisposable
{
	uint Count { get; }
	ulong TotalEvicted { get; }
	void Append(in ShardRecord record, out bool evictedOne);
	void Commit();
}

/// <summary>Best-effort, single-consumer sink for per-IP forensic shards.</summary>
public sealed class ShardIngestionSink : IDisposable
{
	private const string UpdateSql = """
UPDATE IpEventSummary SET
	ShardRelativePath = $path,
	ShardRecordCount = $count,
	ShardBytes = $bytes,
	ShardFormatVersion = $version,
	ShardEvictedCount = $evicted,
	ShardOldestRetainedUtc = $oldest,
	IsSubnetAggregate = $isAgg
WHERE IpBinary16 = $ip;
""";

	/// <summary>Upper bound on the number of distinct refused sources tracked for the operator banner.
	/// Past it the reported count is a stated lower bound instead of an unbounded set.</summary>
	internal const int MaxTrackedRefusedSources = 8192;

	/// <summary>Upper bound on <c>IpEventSummary</c> rows one aggregate shard may carry. Past it the
	/// shard keeps receiving records (they are still in <c>RawEvents</c> with full attribution) but the
	/// later sources' rows are no longer re-pointed at it, so the set stays memory-bounded.</summary>
	internal const int MaxAggregateMemberSources = 1024;

	// ── Fields & DI ──────────────────────────────────────────────────────────────

	private readonly IOptionsMonitor<RdpAuditOptions> _options;
	private readonly ILogger<ShardIngestionSink> _logger;
	private readonly ServiceMetrics _metrics;
	private readonly IOperationLogWriter? _operationLog;
	private readonly Func<string, int, IShardFileWriter> _writerFactory;
	private readonly Dictionary<string, Entry> _writers = new(StringComparer.OrdinalIgnoreCase);
	private readonly List<Entry> _touched = [];
	private readonly ShardCardinalityGuard _guard = new();

	/// <summary>Guards the writer pool and the refusal state, so the inventory and the garbage collector
	/// - which run on other threads - can ask whether a shard is currently open without racing an
	/// append. The append path takes it once per event and never while doing file I/O.</summary>
	private readonly object _stateGate = new();

	private readonly HashSet<string> _refusedSources = new(StringComparer.OrdinalIgnoreCase);
	private readonly HashSet<string> _aggregatedSourceKeys = new(StringComparer.OrdinalIgnoreCase);
	private long _tick;
	private long _knownShardFiles = -1;
	private long _knownShardBytes = -1;
	private long _refusedWriteAttempts;
	private long _lastRefusalTicks;
	private long _refusalSinceTicks;
	private ShardRefusalReason _lastRefusalReason;
	private ShardRefusalReason _alertedRefusalReason;
	private bool _refusalActive;
	private bool _refusedSourceCountIsLowerBound;
	private bool _aggregatedSourceCountIsLowerBound;
	private bool _guardAlerted;
	private bool _budgetRefusalLogged;
	private bool _byteBudgetRefusalLogged;
	private bool _diskFloorRefusalLogged;
	private bool _disposed;

	// ── Construction ─────────────────────────────────────────────────────────────

	/// <summary>Production constructor. Creates real <see cref="ShardWriter"/> instances.</summary>
	public ShardIngestionSink(
		IOptionsMonitor<RdpAuditOptions> options,
		ILogger<ShardIngestionSink> logger,
		ServiceMetrics metrics,
		IOperationLogWriter? operationLog = null)
		: this(options, logger, metrics, null, operationLog)
	{
	}

	/// <summary>Internal test seam. <paramref name="writerFactory"/> replaces writer creation.</summary>
	internal ShardIngestionSink(
		IOptionsMonitor<RdpAuditOptions> options,
		ILogger<ShardIngestionSink> logger,
		ServiceMetrics metrics,
		Func<string, int, IShardFileWriter>? writerFactory,
		IOperationLogWriter? operationLog = null)
	{
		ArgumentNullException.ThrowIfNull(options);
		ArgumentNullException.ThrowIfNull(logger);
		ArgumentNullException.ThrowIfNull(metrics);
		_options = options;
		_logger = logger;
		_metrics = metrics;
		_writerFactory = writerFactory ?? CreateProductionWriter;
		_operationLog = operationLog;
	}

	// ── Public API ───────────────────────────────────────────────────────────────

	/// <summary>Gets whether the current configuration permits shard writing.</summary>
	public bool IsEnabled => !_disposed && _options.CurrentValue.Sharding.Enabled;

	/// <summary>Gets whether this sink currently holds an open writer for an absolute shard path. Used
	/// by the orphan collector, which must never delete a shard a live writer is still mapping.</summary>
	public bool IsShardOpen(string absolutePath)
	{
		if (string.IsNullOrWhiteSpace(absolutePath))
		{
			return false;
		}

		lock (_stateGate)
		{
			return _writers.ContainsKey(absolutePath);
		}
	}

	/// <summary>Snapshots the live shard capacity state. Every field is a fact this sink observed; a
	/// figure it cannot know is null or the documented <c>-1</c>, never a guessed zero.</summary>
	public ShardCapacityStatusDto GetCapacityStatus()
	{
		ShardingOptions options = _options.CurrentValue.Sharding;
		long maximumBytes = options.ResolveMaxTotalShardBytes();
		long minFreeBytes = options.ResolveMinFreeDiskBytes();
		long? freeBytes = TryGetVolumeFreeBytes(options.ResolveActionsRoot());

		long refusedSources;
		long refusedAttempts;
		long knownFiles;
		long knownBytes;
		long aggregated;
		ShardRefusalReason lastReason;
		DateTime? lastUtc;
		DateTime? sinceUtc;
		bool refusalActive;
		bool lowerBound;
		bool aggregatedLowerBound;
		lock (_stateGate)
		{
			refusedSources = _refusedSources.Count;
			refusedAttempts = _refusedWriteAttempts;
			knownFiles = _knownShardFiles;
			knownBytes = _knownShardBytes;
			aggregated = _aggregatedSourceKeys.Count;
			lastReason = _lastRefusalReason;
			lastUtc = _lastRefusalTicks == 0 ? null : new DateTime(_lastRefusalTicks, DateTimeKind.Utc);
			sinceUtc = _refusalSinceTicks == 0 ? null : new DateTime(_refusalSinceTicks, DateTimeKind.Utc);
			refusalActive = _refusalActive;
			lowerBound = _refusedSourceCountIsLowerBound;
			aggregatedLowerBound = _aggregatedSourceCountIsLowerBound;
		}

		bool fileBudgetExceeded = knownFiles >= 0 && knownFiles >= options.ResolveMaxShardFiles();
		bool byteBudgetExceeded = maximumBytes > 0 && knownBytes >= 0 && knownBytes >= maximumBytes;
		bool diskFloorBreached = minFreeBytes > 0 && freeBytes is long free && free <= minFreeBytes;
		bool guardEnabled = options.SubnetAggregation.Enabled;
		bool guardActive = guardEnabled
			&& _guard.IsThresholdBreached(options.SubnetAggregation, knownFiles < 0 ? 0 : knownFiles);

		ShardCapacityStatusDto status = new()
		{
			RefusalActive = refusalActive,
			LastRefusalReason = lastReason,
			LastRefusalUtc = lastUtc,
			RefusalSinceUtc = sinceUtc,
			RefusedSourceCount = refusedSources,
			RefusedSourceCountIsLowerBound = lowerBound,
			RefusedWriteAttempts = refusedAttempts,
			FileBudgetExceeded = fileBudgetExceeded,
			ByteBudgetExceeded = byteBudgetExceeded,
			DiskFloorBreached = diskFloorBreached,
			TotalShardBytes = maximumBytes > 0 ? knownBytes : -1,
			MaxTotalShardBytes = maximumBytes,
			MinFreeDiskBytes = minFreeBytes,
			ActionsVolumeFreeBytes = freeBytes,
			CardinalityGuardEnabled = guardEnabled,
			CardinalityGuardActive = guardActive,
			AggregatedSourceCount = aggregated,
			AggregatedSourceCountIsLowerBound = aggregatedLowerBound,
		};

		status.Message = DescribeCapacityStatus(status);
		return status;
	}

	/// <summary>Stages one normalized event in its IP shard. Failures are intentionally non-fatal.</summary>
	public void Append(RawEvent rawEvent)
	{
		if (!IsEnabled || rawEvent is null)
		{
			return;
		}

		try
		{
			if (!TryResolveAddress(rawEvent, out IPAddress address, out byte[] ipBinary16))
			{
				return;
			}

			ShardingOptions options = _options.CurrentValue.Sharding;
			Span<char> relativeBuffer = stackalloc char[64];
			if (!ShardPath.TryComposeShardPath(address, relativeBuffer, out int relativeLength))
			{
				// Never drop evidence silently: the caller cannot observe this path.
				_logger.LogWarning("Could not compose a shard path for an event source address");
				_metrics.IncrementShardWriteFailures();
				return;
			}

			string relativePath = new(relativeBuffer.Slice(0, relativeLength));
			string actionsRoot = Path.GetFullPath(options.ResolveActionsRoot());
			ReadOnlySpan<char> relativeUnderActions = relativePath.AsSpan(ShardPath.ActionsRootFolder.Length + 1);
			string absolutePath = Path.GetFullPath(Path.Combine(actionsRoot, relativeUnderActions.ToString()));
			if (!ShardPath.IsContainedUnder(actionsRoot, absolutePath))
			{
				_logger.LogWarning("Rejected shard path outside actions root {ActionsRoot}", actionsRoot);
				_metrics.IncrementShardWriteFailures();
				return;
			}

			long nowTicks = DateTime.UtcNow.Ticks;

			// The guard only observes anything when it is enabled, so with the default configuration the
			// append path performs exactly the work it performed before the guard existed.
			int sourceRowsInInterval = _guard.Observe(options.SubnetAggregation, nowTicks, absolutePath);

			Entry? entry = GetOrOpenWriter(address, absolutePath, relativePath, ipBinary16, actionsRoot, options, sourceRowsInInterval, nowTicks);
			if (entry is null)
			{
				return;
			}

			ShardRecord record = CreateRecord(rawEvent, entry.IsSubnetAggregate);
			entry.Writer.Append(in record, out bool evicted);
			entry.LastUsedTick = ++_tick;
			if (evicted)
			{
				entry.OldestRetainedUtc = null;
				_metrics.IncrementShardEvictions();
			}
			else if (entry.CanReportOldest)
			{
				if (entry.OldestRetainedUtc is null || rawEvent.TimeUtc.Ticks < entry.OldestRetainedUtc.Value)
				{
					entry.OldestRetainedUtc = rawEvent.TimeUtc.Ticks;
				}
			}

			if (!entry.Touched)
			{
				entry.Touched = true;
				_touched.Add(entry);
			}

			_metrics.IncrementShardRecordsAppended();
		}
		catch (Exception ex)
		{
			_logger.LogWarning(ex, "Failed to append forensic shard record for event {EventId}", rawEvent.EventId);
			_metrics.IncrementShardWriteFailures();
		}
	}

	/// <summary>Commits touched shard headers and updates truthful metadata in the supplied
	/// transaction. On any per-record failure the exception is rethrown and the touched queue
	/// is left intact; only a fully successful batch clears it.</summary>
	public async Task CommitAsync(SqliteConnection connection, SqliteTransaction transaction, CancellationToken ct)
	{
		if (_touched.Count == 0)
		{
			return;
		}

		await using SqliteCommand command = CreateUpdateCommand(connection, transaction);
		await command.PrepareAsync(ct).ConfigureAwait(false);
		for (int index = 0; index < _touched.Count; index++)
		{
			ct.ThrowIfCancellationRequested();
			Entry entry = _touched[index];

			// A failure here aborts the whole batch: do NOT close/remove the writer, because
			// the pending queue must survive for the next flush. Rethrow so the caller can
			// classify SQLITE_BUSY/LOCKED and retry the same queue.
			entry.Writer.Commit();
			FileInfo file = new(entry.AbsolutePath);
			if (!file.Exists)
			{
				throw new IOException("Shard file disappeared before metadata update.");
			}

			if (entry.Sources.Count == 0)
			{
				// Every source that shared this aggregate has moved to a shard of its own, so no
				// IpEventSummary row names this file any more. The header is still committed - the records
				// it already holds stay readable - but there is no row to describe.
				continue;
			}

			BindUpdate(command, entry, file.Length);
			await command.ExecuteNonQueryAsync(ct).ConfigureAwait(false);
			// One row per referencing source: a per-IP shard has exactly one, a subnet aggregate has one
			// per source that shares it. Every one of them gets the same truthful file facts.
			for (int source = 1; source < entry.Sources.Count; source++)
			{
				ct.ThrowIfCancellationRequested();
				command.Parameters["$ip"].Value = entry.Sources[source];
				await command.ExecuteNonQueryAsync(ct).ConfigureAwait(false);
			}
		}

		// The queue must not be cleared before this point. Only a fully successful batch
		// flushes the touched flag, clears the queue and trims the writer pool.
		for (int index = 0; index < _touched.Count; index++)
		{
			_touched[index].Touched = false;
		}
		_touched.Clear();
		TrimOpenWriters();
	}

	/// <summary>Discards uncommitted writer state after the source database transaction rolls back.</summary>
	public void DiscardPending()
	{
		for (int index = 0; index < _touched.Count; index++)
		{
			Entry entry = _touched[index];
			entry.Touched = false;
			lock (_stateGate)
			{
				_writers.Remove(entry.AbsolutePath);
			}
			try
			{
				// Dispose without Commit: staged records stay unreachable behind the old header.
				entry.Writer.Dispose();
			}
			catch (Exception ex)
			{
				_logger.LogWarning(ex, "Failed to discard uncommitted forensic shard {ShardPath}", entry.RelativePath);
				_metrics.IncrementShardWriteFailures();
			}
		}
		_touched.Clear();
		_metrics.SetShardsOpen(OpenWriterCount());
	}

	// ── Core Logic ───────────────────────────────────────────────────────────────

	private Entry? GetOrOpenWriter(
		IPAddress address,
		string perIpAbsolutePath,
		string perIpRelativePath,
		byte[] ipBinary16,
		string actionsRoot,
		ShardingOptions options,
		int sourceRowsInInterval,
		long nowTicks)
	{
		lock (_stateGate)
		{
			if (_writers.TryGetValue(perIpAbsolutePath, out Entry? existing))
			{
				existing.LastUsedTick = ++_tick;
				return existing;
			}
		}

		bool exists = File.Exists(perIpAbsolutePath);
		string absolutePath = perIpAbsolutePath;
		string relativePath = perIpRelativePath;
		bool isSubnetAggregate = false;

		if (!exists)
		{
			if (NeedsTreeAccounting(options))
			{
				EnsureTreeAccounting(actionsRoot);
			}

			ShardAggregationDecision decision = _guard.Decide(
				options.SubnetAggregation,
				KnownShardFileCount(),
				sourceRowsInInterval);

			if (decision.Aggregate
				&& TryComposeAggregatePath(address, actionsRoot, out string aggregateAbsolute, out string aggregateRelative))
			{
				isSubnetAggregate = true;
				absolutePath = aggregateAbsolute;
				relativePath = aggregateRelative;
				exists = File.Exists(aggregateAbsolute);
				ReportAggregation(options, decision, perIpRelativePath);

				lock (_stateGate)
				{
					if (_writers.TryGetValue(aggregateAbsolute, out Entry? openAggregate))
					{
						openAggregate.LastUsedTick = ++_tick;
						AddAggregateSource(openAggregate, ipBinary16);
						return openAggregate;
					}
				}
			}
			else
			{
				// A source that has proved its volume leaves the aggregate it was sharing, so its row names
				// its own shard from now on instead of being re-pointed at the bucket every commit. With the
				// guard disabled this is a no-op scan of a pool that holds no aggregate at all.
				RemoveSourceFromAggregates(ipBinary16);
				if (!_guard.IsThresholdBreached(options.SubnetAggregation, KnownShardFileCount()))
				{
					// The guard is no longer engaged, so a later engagement is a new event worth reporting.
					_guardAlerted = false;
				}
			}

			if (!exists && !TryReserveShardFile(actionsRoot, options, out ShardRefusalReason refusal))
			{
				RecordRefusal(refusal, perIpRelativePath, nowTicks);
				return null;
			}
		}

		bool isNewFile = !exists;
		string? directory = Path.GetDirectoryName(absolutePath);
		if (directory is null)
		{
			return null;
		}

		Directory.CreateDirectory(directory);
		// An existing shard keeps the ring capacity its own header declares (ShardWriter enforces that);
		// a new file is allocated with the configured capacity capped by the per-shard byte ceiling.
		IShardFileWriter writer = _writerFactory(absolutePath, options.ResolveRingCapacityRecords());
		Entry created = new(absolutePath, relativePath, ipBinary16, writer, isSubnetAggregate)
		{
			LastUsedTick = ++_tick,
			CanReportOldest = writer.Count == 0 && writer.TotalEvicted == 0,
		};

		long createdBytes = -1;
		if (isNewFile)
		{
			try
			{
				createdBytes = new FileInfo(absolutePath).Length;
			}
			catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
			{
				// A file whose length cannot be read still counts as a file; its size stays unknown.
			}
		}

		lock (_stateGate)
		{
			_writers[absolutePath] = created;
			if (_knownShardBytes >= 0 && createdBytes >= 0)
			{
				// The walk's total plus the real on-disk length of every file created since it.
				_knownShardBytes += createdBytes;
			}
			_refusalActive = false;
			_alertedRefusalReason = ShardRefusalReason.None;
		}

		// The rate ceiling counts files, and it counts exactly the files this process created.
		_guard.NoteNewShardFile(options.SubnetAggregation, nowTicks);
		_metrics.SetShardsOpen(OpenWriterCount());
		return created;
	}

	/// <summary>Composes the canonical subnet-aggregate path for an address (IPv4 /24, IPv6 /64) and
	/// confirms it stays under the actions root.</summary>
	private static bool TryComposeAggregatePath(
		IPAddress address,
		string actionsRoot,
		out string absolutePath,
		out string relativePath)
	{
		absolutePath = string.Empty;
		relativePath = string.Empty;
		if (!ShardPath.TryGetAggregatePrefixLengthBits(address.AddressFamily, out int prefixLenBits))
		{
			return false;
		}

		Span<char> relativeBuffer = stackalloc char[80];
		if (!ShardPath.TryComposeSubnetShardPath(address, prefixLenBits, relativeBuffer, out int relativeLength))
		{
			return false;
		}

		relativePath = new string(relativeBuffer.Slice(0, relativeLength));
		ReadOnlySpan<char> relativeUnderActions = relativePath.AsSpan(ShardPath.ActionsRootFolder.Length + 1);
		absolutePath = Path.GetFullPath(Path.Combine(actionsRoot, relativeUnderActions.ToString()));
		return ShardPath.IsContainedUnder(actionsRoot, absolutePath);
	}

	/// <summary>True when the tree has to be accounted for before a new file may be created: a file
	/// budget, a byte budget or the cardinality guard needs the current counts.</summary>
	private static bool NeedsTreeAccounting(ShardingOptions options)
		=> options.ResolveMaxShardFiles() > 0
			|| options.ResolveMaxTotalShardBytes() > 0
			|| options.SubnetAggregation.Enabled;

	private long KnownShardFileCount()
	{
		lock (_stateGate)
		{
			return _knownShardFiles;
		}
	}

	/// <summary>Walks the shard tree once and caches the file count and byte total. Exactly the walk the
	/// file budget always performed; the byte budget and the guard reuse it instead of adding a second
	/// enumeration. The cache is a snapshot: a file an operator adds or removes out of band is not
	/// re-counted, which is the same, documented behaviour the file budget already had.</summary>
	private void EnsureTreeAccounting(string actionsRoot)
	{
		lock (_stateGate)
		{
			if (_knownShardFiles >= 0)
			{
				return;
			}
		}

		long files = 0;
		long bytes = 0;
		if (Directory.Exists(actionsRoot))
		{
			EnumerationOptions enumerationOptions = new()
			{
				RecurseSubdirectories = true,
				IgnoreInaccessible = true,
				AttributesToSkip = FileAttributes.ReparsePoint,
			};
			foreach (string file in Directory.EnumerateFiles(actionsRoot, "*" + ShardPath.ShardExtension, enumerationOptions))
			{
				files++;
				try
				{
					bytes += new FileInfo(file).Length;
				}
				catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
				{
					// An unreadable file still counts as a file; its size stays unknown rather than guessed.
				}
			}
		}

		lock (_stateGate)
		{
			if (_knownShardFiles < 0)
			{
				_knownShardFiles = files;
				_knownShardBytes = bytes;
			}
		}
	}

	private bool TryReserveShardFile(string actionsRoot, ShardingOptions options, out ShardRefusalReason refusal)
	{
		refusal = ShardRefusalReason.None;
		EnsureTreeAccounting(actionsRoot);

		long maximum = options.ResolveMaxShardFiles();
		lock (_stateGate)
		{
			if (_knownShardFiles >= maximum)
			{
				_metrics.IncrementShardBudgetRefusals();
				if (!_budgetRefusalLogged)
				{
					_budgetRefusalLogged = true;
					_logger.LogWarning("Shard file budget reached at {ShardFileCount} files; new shards are refused", _knownShardFiles);
				}
				refusal = ShardRefusalReason.FileBudget;
				return false;
			}
		}

		long maximumBytes = options.ResolveMaxTotalShardBytes();
		if (maximumBytes > 0)
		{
			bool exceeded;
			long knownBytes;
			lock (_stateGate)
			{
				knownBytes = _knownShardBytes;
				exceeded = knownBytes >= maximumBytes;
			}
			if (exceeded)
			{
				_metrics.IncrementShardByteBudgetRefusals();
				if (!_byteBudgetRefusalLogged)
				{
					_byteBudgetRefusalLogged = true;
					_logger.LogWarning(
						"Shard byte budget reached at {ShardBytes} of {MaxBytes} bytes; new shards are refused (existing shards keep being written)",
						knownBytes,
						maximumBytes);
				}
				refusal = ShardRefusalReason.ByteBudget;
				return false;
			}
		}

		long minimumFree = options.ResolveMinFreeDiskBytes();
		if (minimumFree > 0)
		{
			long? free = TryGetVolumeFreeBytes(actionsRoot);
			if (free is long freeBytes && freeBytes <= minimumFree)
			{
				_metrics.IncrementShardDiskFloorRefusals();
				if (!_diskFloorRefusalLogged)
				{
					_diskFloorRefusalLogged = true;
					_logger.LogWarning(
						"Shard volume free space is down to {FreeBytes} bytes, at or below the {MinFreeBytes}-byte floor; new shards are refused",
						freeBytes,
						minimumFree);
				}
				refusal = ShardRefusalReason.DiskFloor;
				return false;
			}
		}

		// Reserved, not yet created: the next append will not reserve the same slot twice even if the
		// writer factory fails, exactly like the file budget behaved before the byte ceilings existed.
		// The byte total is corrected with the real file length once the writer exists.
		lock (_stateGate)
		{
			_knownShardFiles++;
		}

		return true;
	}

	/// <summary>Reads the free space of the volume that holds the actions root. Returns null when the
	/// volume cannot be inspected, in which case the disk floor cannot be evaluated and the sink says so
	/// instead of refusing on a guessed number.</summary>
	private static long? TryGetVolumeFreeBytes(string actionsRoot)
	{
		try
		{
			string full = Path.GetFullPath(actionsRoot);
			string? root = Path.GetPathRoot(full);
			if (string.IsNullOrWhiteSpace(root))
			{
				return null;
			}

			DriveInfo drive = new(root);
			return drive.IsReady ? drive.AvailableFreeSpace : null;
		}
		catch (Exception ex) when (ex is ArgumentException or IOException or UnauthorizedAccessException or NotSupportedException)
		{
			return null;
		}
	}

	private int OpenWriterCount()
	{
		lock (_stateGate)
		{
			return _writers.Count;
		}
	}

	/// <summary>Registers one more source sharing an aggregate shard, up to the documented cap.</summary>
	private void AddAggregateSource(Entry entry, byte[] ipBinary16)
	{
		foreach (byte[] existing in entry.Sources)
		{
			if (existing.AsSpan().SequenceEqual(ipBinary16))
			{
				return;
			}
		}

		if (entry.Sources.Count >= MaxAggregateMemberSources)
		{
			_logger.LogWarning(
				"Aggregate shard {ShardPath} already carries {MemberCount} source rows; later sources are still written to it but their rows are not re-pointed",
				entry.RelativePath,
				entry.Sources.Count);
			return;
		}

		entry.Sources.Add(ipBinary16);
	}

	/// <summary>Drops a source from every open aggregate entry, so a source that has proved its volume is
	/// no longer re-pointed at the bucket by a later commit.</summary>
	private void RemoveSourceFromAggregates(byte[] ipBinary16)
	{
		lock (_stateGate)
		{
			foreach (Entry entry in _writers.Values)
			{
				if (!entry.IsSubnetAggregate)
				{
					continue;
				}

				for (int index = 0; index < entry.Sources.Count; index++)
				{
					if (entry.Sources[index].AsSpan().SequenceEqual(ipBinary16))
					{
						entry.Sources.RemoveAt(index);
						break;
					}
				}
			}
		}
	}

	/// <summary>Records a refusal: the metric for the reason, the operator-visible state and - on the
	/// edge only - one audit row naming the reason and the ceiling that refused.</summary>
	private void RecordRefusal(ShardRefusalReason reason, string sourceKey, long nowTicks)
	{
		bool isNewReason;
		lock (_stateGate)
		{
			isNewReason = _lastRefusalReason != reason;
			_lastRefusalReason = reason;
			_lastRefusalTicks = nowTicks;
			if (!_refusalActive || isNewReason)
			{
				_refusalSinceTicks = nowTicks;
			}
			_refusalActive = true;
			_refusedWriteAttempts++;
			if (_refusedSources.Contains(sourceKey))
			{
				// A repeated refusal from a source that is already counted is not a new source.
			}
			else if (_refusedSources.Count < MaxTrackedRefusedSources)
			{
				_refusedSources.Add(sourceKey);
			}
			else
			{
				// Past the cap the set stops growing, so the reported count is a stated lower bound instead
				// of an unbounded table - a spray must not turn the refusal bookkeeping into a leak.
				_refusedSourceCountIsLowerBound = true;
			}
		}

		if (isNewReason && _alertedRefusalReason != reason)
		{
			_alertedRefusalReason = reason;
			ShardingOptions options = _options.CurrentValue.Sharding;
			string message = reason switch
			{
				ShardRefusalReason.FileBudget =>
					string.Format(
						CultureInfo.InvariantCulture,
						"Shard file budget of {0} files is reached; new shards are refused and the operator must review the shard policy.",
						options.ResolveMaxShardFiles()),
				ShardRefusalReason.ByteBudget =>
					string.Format(
						CultureInfo.InvariantCulture,
						"Shard tree byte budget of {0} bytes is reached; new shards are refused and the operator must review the shard policy.",
						options.ResolveMaxTotalShardBytes()),
				ShardRefusalReason.DiskFloor =>
					string.Format(
						CultureInfo.InvariantCulture,
						"Free space on the shard volume is at or below the {0}-byte floor; new shards are refused so the evidence store is not starved of disk.",
						options.ResolveMinFreeDiskBytes()),
				_ => "New shards are refused.",
			};

			_logger.LogWarning("Forensic sharding degraded ({Reason}): {Message}", reason, message);
			WriteAuditSafelyAsync("ShardCapacity.Refused", message, reason.ToString());
		}
	}

	/// <summary>Reports that one source was routed into a subnet aggregate: the metric and the tracked
	/// source set move once per source, while the operator visible audit row and log line are written on
	/// the activation edge only, so a spray cannot flood either. The tracked set is capped like the
	/// refusal set, so the count is a stated lower bound under a large spray rather than a leak.</summary>
	private void ReportAggregation(ShardingOptions options, in ShardAggregationDecision decision, string sourceKey)
	{
		bool firstForSource = false;
		lock (_stateGate)
		{
			if (_aggregatedSourceKeys.Contains(sourceKey))
			{
				// Already counted once for this source.
			}
			else if (_aggregatedSourceKeys.Count < MaxTrackedRefusedSources)
			{
				_aggregatedSourceKeys.Add(sourceKey);
				firstForSource = true;
			}
			else
			{
				_aggregatedSourceCountIsLowerBound = true;
			}
		}

		if (firstForSource)
		{
			_metrics.IncrementShardAggregations();
		}

		if (_guardAlerted)
		{
			return;
		}

		_guardAlerted = true;
		string message = string.Format(
			CultureInfo.InvariantCulture,
			"Shard cardinality guard engaged ({0}): new low-volume sources are routed into an IPv4 /24 or IPv6 /64 aggregate shard; shardFiles={1} newFilesInInterval={2} sourceRowsInInterval={3} minSourceRows={4}.",
			decision.Trigger,
			decision.ShardFileCount,
			decision.NewFilesInInterval,
			decision.SourceRowsInInterval,
			options.SubnetAggregation.ResolveMinSourceRowsPerInterval());

		_logger.LogWarning(
			"Shard cardinality guard engaged: trigger={Trigger} shardFiles={ShardFiles} newFilesInInterval={NewFiles} sourceRowsInInterval={SourceRows}",
			decision.Trigger,
			decision.ShardFileCount,
			decision.NewFilesInInterval,
			decision.SourceRowsInInterval);
		WriteAuditSafelyAsync("ShardCardinalityGuard.Engaged", message, decision.Trigger.ToString());
	}

	/// <summary>Fire-and-forget audit write. A shard-capacity alert must never block or fail an append,
	/// so every failure is logged at debug level instead of surfacing in the ingestion path.</summary>
	private void WriteAuditSafelyAsync(string operation, string message, string detailsJson)
	{
		IOperationLogWriter? writer = _operationLog;
		if (writer is null)
		{
			return;
		}

		_ = WriteAuditAsync(writer, operation, message, detailsJson);
	}

	private async Task WriteAuditAsync(IOperationLogWriter writer, string operation, string message, string detailsJson)
	{
		try
		{
			await writer.WriteAsync(new OperationLogEntry
			{
				Severity = OperationLogSeverity.Warning,
				Source = "Sharding",
				Operation = operation,
				Message = message,
				DetailsJson = detailsJson,
				Actor = "Service",
			}).ConfigureAwait(false);
		}
		catch (Exception ex)
		{
			_logger.LogDebug(ex, "Shard capacity audit entry {Operation} could not be written", operation);
		}
	}

	/// <summary>One operator-facing sentence per degraded capacity fact; null when nothing is degraded.</summary>
	private static string? DescribeCapacityStatus(ShardCapacityStatusDto status)
	{
		List<string> parts = new();
		if (status.RefusalActive)
		{
			parts.Add(string.Format(
				CultureInfo.InvariantCulture,
				"new shards refused since {0} ({1}); {2} source(s) unsharded so far",
				status.RefusalSinceUtc?.ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture) ?? "unknown",
				status.LastRefusalReason,
				status.RefusedSourceCount));
		}

		if (status.FileBudgetExceeded)
		{
			parts.Add("shard file budget reached");
		}

		if (status.ByteBudgetExceeded)
		{
			parts.Add("shard byte budget reached");
		}

		if (status.DiskFloorBreached)
		{
			parts.Add("shard volume free space at or below the floor");
		}

		if (status.CardinalityGuardActive)
		{
			parts.Add(string.Format(
				CultureInfo.InvariantCulture,
				"cardinality guard engaged; {0} source(s) aggregated into subnet buckets",
				status.AggregatedSourceCount));
		}

		return parts.Count == 0 ? null : string.Join("; ", parts);
	}

	private static ShardFileWriterAdapter CreateProductionWriter(string absolutePath, int capacity)
		=> new(ShardWriter.OpenOrCreate(absolutePath, capacity));

	private static ShardRecord CreateRecord(RawEvent rawEvent, bool isSubnetAggregate)
	{
		uint status = ParseHex(rawEvent.Status);
		byte confidence = rawEvent.SourceIpUnresolved ? (byte)0 : rawEvent.SourceIpDerived ? (byte)128 : (byte)255;
		// bit0 must mean the same thing here as everywhere else: an RDP-relevant 4624. A Service (5)
		// or Batch (4) logon is local by construction and would otherwise be marked as a success in
		// the forensic record. Records written before this change keep the old bit; the record still
		// carries the raw event id and logon type, so a reader can always reclassify.
		bool isRdpSuccess = rawEvent.EventId == 4624
			&& AttackStatsAggregator.IsRdpRelevantLogonType(rawEvent.LogonType);
		uint flags = isRdpSuccess ? 1u : rawEvent.EventId == 4625 ? 2u : 0u;
		if (isSubnetAggregate)
		{
			// bit2: the record was written into a subnet aggregate, so it belongs to the bucket rather
			// than to the single host its file name used to imply. The layout already reserves the bit.
			flags |= 4u;
		}

		// ShardWriter has no string heap yet. These offsets remain -1 until a durable heap is added.
		return ShardRecord.Create(
			rawEvent.IngestionSequence, rawEvent.TimeUtc.Ticks, rawEvent.EventId,
			(ushort)ChannelCodeMap.FromChannelName(rawEvent.Channel), (byte)rawEvent.EventLayer,
			confidence, unchecked((byte)(rawEvent.LogonType ?? 0)), unchecked((byte)status),
			(ushort)(status >> 16), rawEvent.SessionId ?? -1, ParseLogonId(rawEvent.LogonId),
			-1, -1, -1, -1, -1, flags);
	}

	private static uint ParseHex(string? value)
	{
		if (string.IsNullOrWhiteSpace(value))
		{
			return 0;
		}

		ReadOnlySpan<char> digits = value.AsSpan().Trim();
		if (digits.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
		{
			digits = digits[2..];
		}

		return uint.TryParse(digits, NumberStyles.AllowHexSpecifier, CultureInfo.InvariantCulture, out uint parsed) ? parsed : 0;
	}

	private static long ParseLogonId(string? value)
	{
		if (string.IsNullOrWhiteSpace(value))
		{
			return 0;
		}

		ReadOnlySpan<char> digits = value.AsSpan().Trim();
		if (digits.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
		{
			digits = digits[2..];
		}

		return long.TryParse(digits, NumberStyles.AllowHexSpecifier, CultureInfo.InvariantCulture, out long parsed) ? parsed : 0;
	}

	private static bool TryResolveAddress(RawEvent rawEvent, out IPAddress address, out byte[] ipBinary16)
	{
		if (rawEvent.SourceIpBinary is { Length: 4 or 16 } binary)
		{
			address = new IPAddress(binary);
			ipBinary16 = address.AddressFamily == AddressFamily.InterNetwork
				? address.MapToIPv6().GetAddressBytes()
				: binary;
			return true;
		}
		if (!string.IsNullOrWhiteSpace(rawEvent.SourceIp) && IPAddress.TryParse(rawEvent.SourceIp, out IPAddress? parsed))
		{
			address = parsed;
			ipBinary16 = parsed.AddressFamily == AddressFamily.InterNetwork ? parsed.MapToIPv6().GetAddressBytes() : parsed.GetAddressBytes();
			return ipBinary16.Length == 16;
		}
		address = IPAddress.None;
		ipBinary16 = [];
		return false;
	}

	private static SqliteCommand CreateUpdateCommand(SqliteConnection connection, SqliteTransaction transaction)
	{
		SqliteCommand command = connection.CreateCommand();
		command.Transaction = transaction;
		command.CommandText = UpdateSql;
		AddParameter(command, "$path"); AddParameter(command, "$count"); AddParameter(command, "$bytes");
		AddParameter(command, "$version"); AddParameter(command, "$evicted"); AddParameter(command, "$oldest");
		AddParameter(command, "$isAgg"); AddParameter(command, "$ip");
		return command;
	}

	private static void AddParameter(SqliteCommand command, string name)
	{
		SqliteParameter parameter = command.CreateParameter();
		parameter.ParameterName = name;
		command.Parameters.Add(parameter);
	}

	private static void BindUpdate(SqliteCommand command, Entry entry, long bytes)
	{
		command.Parameters["$path"].Value = entry.RelativePath;
		command.Parameters["$count"].Value = (long)entry.Writer.Count;
		command.Parameters["$bytes"].Value = bytes;
		command.Parameters["$version"].Value = (int)ShardHeader.CurrentFormatVersion;
		command.Parameters["$evicted"].Value = checked((long)entry.Writer.TotalEvicted);
		command.Parameters["$oldest"].Value = entry.OldestRetainedUtc is long oldest ? oldest : DBNull.Value;
		command.Parameters["$isAgg"].Value = entry.IsSubnetAggregate ? 1L : 0L;
		command.Parameters["$ip"].Value = entry.Sources[0];
	}

	private void TrimOpenWriters()
	{
		int maximum = _options.CurrentValue.Sharding.ResolveMaxOpenWriters();
		while (true)
		{
			Entry? oldest = null;
			lock (_stateGate)
			{
				if (_writers.Count <= maximum)
				{
					return;
				}

				foreach (Entry candidate in _writers.Values)
				{
					if (candidate.Touched || (oldest is not null && candidate.LastUsedTick >= oldest.LastUsedTick)) continue;
					oldest = candidate;
				}
			}

			if (oldest is null) return;
			CloseAndRemove(oldest);
		}
	}

	private void CloseAndRemove(Entry entry)
	{
		lock (_stateGate)
		{
			_writers.Remove(entry.AbsolutePath);
		}
		try
		{
			entry.Writer.Commit();
		}
		catch (Exception ex)
		{
			_logger.LogWarning(ex, "Failed to flush forensic shard {ShardPath}", entry.RelativePath);
			_metrics.IncrementShardWriteFailures();
		}

		try
		{
			entry.Writer.Dispose();
		}
		catch (Exception ex)
		{
			_logger.LogWarning(ex, "Failed to close forensic shard {ShardPath}", entry.RelativePath);
			_metrics.IncrementShardWriteFailures();
		}
		_metrics.SetShardsOpen(OpenWriterCount());
	}

	// ── Disposal & Pool Returns ──────────────────────────────────────────────────

	public void Dispose()
	{
		if (_disposed)
		{
			return;
		}

		_disposed = true;
		Entry[] entries;
		lock (_stateGate)
		{
			entries = _writers.Values.ToArray();
		}
		foreach (Entry entry in entries)
		{
			CloseAndRemove(entry);
		}
	}

	private sealed class Entry(string absolutePath, string relativePath, byte[] ipBinary16, IShardFileWriter writer, bool isSubnetAggregate)
	{
		public string AbsolutePath { get; } = absolutePath;
		public string RelativePath { get; } = relativePath;
		public IShardFileWriter Writer { get; } = writer;
		public bool IsSubnetAggregate { get; } = isSubnetAggregate;

		/// <summary>Every <c>IpEventSummary</c> row this shard's metadata belongs to: one for a per-IP
		/// shard, one per sharing source for a subnet aggregate.</summary>
		public List<byte[]> Sources { get; } = [ipBinary16];

		public long LastUsedTick { get; set; }
		public long? OldestRetainedUtc { get; set; }
		public bool CanReportOldest { get; init; }
		public bool Touched { get; set; }
	}

	private sealed class ShardFileWriterAdapter(ShardWriter inner) : IShardFileWriter
	{
		public uint Count => inner.Count;
		public ulong TotalEvicted => inner.TotalEvicted;

		public void Append(in ShardRecord record, out bool evictedOne) => inner.Append(in record, out evictedOne);
		public void Commit() => inner.Commit();
		public void Dispose() => inner.Dispose();
	}
}
