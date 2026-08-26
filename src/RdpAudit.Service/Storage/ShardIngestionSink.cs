/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 2.1.0
// File   : ShardIngestionSink.cs
// Project: RdpAudit.Service (RdpAudit.Service.Storage)
// Purpose: Writes committed event evidence into bounded per-IP forensic shard files.
//          v2.1.0: CommitAsync() is now a true durability boundary for the shard batch.
//          _touched is cleared and TrimOpenWriters() runs ONLY after the whole batch
//          commits; IOException / UnauthorizedAccessException / SqliteException /
//          OperationCanceledException are propagated to the caller so
//          CommitShardsAfterDatabaseCommitAsync can classify SQLITE_BUSY/LOCKED and
//          bounded-retry the real shard writes. A failed per-record commit no longer
//          calls CloseAndRemove(), so the pending queue is retained for the next flush.
// Depends: RdpAuditOptions, ShardWriter, RawEvent, ServiceMetrics, SqliteConnection
// Extends: Add subnet aggregation only with a cardinality policy that preserves the truthful metadata contract.

using System.Globalization;
using System.Net;
using System.Net.Sockets;
using Microsoft.Data.Sqlite;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using RdpAudit.Core.Config;
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
	ShardOldestRetainedUtc = $oldest
WHERE IpBinary16 = $ip;
""";

	// ── Fields & DI ──────────────────────────────────────────────────────────────

	private readonly IOptionsMonitor<RdpAuditOptions> _options;
	private readonly ILogger<ShardIngestionSink> _logger;
	private readonly ServiceMetrics _metrics;
	private readonly Func<string, int, IShardFileWriter> _writerFactory;
	private readonly Dictionary<string, Entry> _writers = new(StringComparer.OrdinalIgnoreCase);
	private readonly List<Entry> _touched = [];
	private long _tick;
	private int _knownShardFiles = -1;
	private bool _budgetRefusalLogged;
	private bool _disposed;

	// ── Construction ─────────────────────────────────────────────────────────────

	/// <summary>Production constructor. Creates real <see cref="ShardWriter"/> instances.</summary>
	public ShardIngestionSink(
		IOptionsMonitor<RdpAuditOptions> options,
		ILogger<ShardIngestionSink> logger,
		ServiceMetrics metrics)
		: this(options, logger, metrics, null)
	{
	}

	/// <summary>Internal test seam. <paramref name="writerFactory"/> replaces writer creation.</summary>
	internal ShardIngestionSink(
		IOptionsMonitor<RdpAuditOptions> options,
		ILogger<ShardIngestionSink> logger,
		ServiceMetrics metrics,
		Func<string, int, IShardFileWriter>? writerFactory)
	{
		ArgumentNullException.ThrowIfNull(options);
		ArgumentNullException.ThrowIfNull(logger);
		ArgumentNullException.ThrowIfNull(metrics);
		_options = options;
		_logger = logger;
		_metrics = metrics;
		_writerFactory = writerFactory ?? CreateProductionWriter;
	}

	// ── Public API ───────────────────────────────────────────────────────────────

	/// <summary>Gets whether the current configuration permits shard writing.</summary>
	public bool IsEnabled => !_disposed && _options.CurrentValue.Sharding.Enabled;

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

			Entry? entry = GetOrOpenWriter(absolutePath, relativePath, ipBinary16, actionsRoot, options);
			if (entry is null)
			{
				return;
			}

			ShardRecord record = CreateRecord(rawEvent);
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

			BindUpdate(command, entry, file.Length);
			await command.ExecuteNonQueryAsync(ct).ConfigureAwait(false);
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
			_writers.Remove(entry.AbsolutePath);
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
		_metrics.SetShardsOpen(_writers.Count);
	}

	// ── Core Logic ───────────────────────────────────────────────────────────────

	private Entry? GetOrOpenWriter(
		string absolutePath,
		string relativePath,
		byte[] ipBinary16,
		string actionsRoot,
		ShardingOptions options)
	{
		if (_writers.TryGetValue(absolutePath, out Entry? existing))
		{
			existing.LastUsedTick = ++_tick;
			return existing;
		}

		bool exists = File.Exists(absolutePath);
		if (!exists && !TryReserveShardFile(actionsRoot, Math.Max(0, options.MaxShardFiles)))
		{
			return null;
		}

		string? directory = Path.GetDirectoryName(absolutePath);
		if (directory is null)
		{
			return null;
		}

		Directory.CreateDirectory(directory);
		IShardFileWriter writer = _writerFactory(absolutePath, Math.Max(1, options.ShardCapacityRecords));
		Entry created = new(absolutePath, relativePath, ipBinary16, writer)
		{
			LastUsedTick = ++_tick,
			CanReportOldest = writer.Count == 0 && writer.TotalEvicted == 0,
		};
		_writers.Add(absolutePath, created);
		_metrics.SetShardsOpen(_writers.Count);
		return created;
	}

	private static ShardFileWriterAdapter CreateProductionWriter(string absolutePath, int capacity)
		=> new(ShardWriter.OpenOrCreate(absolutePath, capacity));

	private bool TryReserveShardFile(string actionsRoot, int maximum)
	{
		if (_knownShardFiles < 0)
		{
			_knownShardFiles = CountShardFiles(actionsRoot);
		}

		if (_knownShardFiles >= maximum)
		{
			_metrics.IncrementShardBudgetRefusals();
			if (!_budgetRefusalLogged)
			{
				_budgetRefusalLogged = true;
				_logger.LogWarning("Shard file budget reached at {ShardFileCount} files; new shards are refused", _knownShardFiles);
			}
			return false;
		}

		_knownShardFiles++;
		return true;
	}

	private int CountShardFiles(string actionsRoot)
	{
		if (!Directory.Exists(actionsRoot))
		{
			return 0;
		}

		int count = 0;
		foreach (string _ in Directory.EnumerateFiles(actionsRoot, "*" + ShardPath.ShardExtension, SearchOption.AllDirectories))
		{
			count++;
		}
		return count;
	}

	private static ShardRecord CreateRecord(RawEvent rawEvent)
	{
		uint status = ParseHex(rawEvent.Status);
		byte confidence = rawEvent.SourceIpUnresolved ? (byte)0 : rawEvent.SourceIpDerived ? (byte)128 : (byte)255;
		uint flags = rawEvent.EventId == 4624 ? 1u : rawEvent.EventId == 4625 ? 2u : 0u;

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
		AddParameter(command, "$version"); AddParameter(command, "$evicted"); AddParameter(command, "$oldest"); AddParameter(command, "$ip");
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
		command.Parameters["$ip"].Value = entry.IpBinary16;
	}

	private void TrimOpenWriters()
	{
		int maximum = Math.Max(1, _options.CurrentValue.Sharding.MaxOpenWriters);
		while (_writers.Count > maximum)
		{
			Entry? oldest = null;
			foreach (Entry candidate in _writers.Values)
			{
				if (candidate.Touched || (oldest is not null && candidate.LastUsedTick >= oldest.LastUsedTick)) continue;
				oldest = candidate;
			}
			if (oldest is null) return;
			CloseAndRemove(oldest);
		}
	}

	private void CloseAndRemove(Entry entry)
	{
		_writers.Remove(entry.AbsolutePath);
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
		_metrics.SetShardsOpen(_writers.Count);
	}

	// ── Disposal & Pool Returns ──────────────────────────────────────────────────

	public void Dispose()
	{
		if (_disposed)
		{
			return;
		}

		_disposed = true;
		Entry[] entries = _writers.Values.ToArray();
		foreach (Entry entry in entries)
		{
			CloseAndRemove(entry);
		}
	}

	private sealed class Entry(string absolutePath, string relativePath, byte[] ipBinary16, IShardFileWriter writer)
	{
		public string AbsolutePath { get; } = absolutePath;
		public string RelativePath { get; } = relativePath;
		public byte[] IpBinary16 { get; } = ipBinary16;
		public IShardFileWriter Writer { get; } = writer;
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
