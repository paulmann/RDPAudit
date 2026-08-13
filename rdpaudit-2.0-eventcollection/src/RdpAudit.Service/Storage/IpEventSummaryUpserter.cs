/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 2.0.0
// File   : IpEventSummaryUpserter.cs
// Project: RdpAudit.Service (RdpAudit.Service.Storage)
// Purpose: Zero-alloc raw-SQL upsert into IpEventSummary + IpEventTypeCounter under the caller's
//          SqliteTransaction. Preserves the sacred invariant: the first event per IP is never
//          overwritten. Preserves TotalEventCount across eviction (only ShardRecordCount tracks
//          on-disk state).
// Depends: Microsoft.Data.Sqlite, RdpAudit.Core.Events
// Extends: When adding a new counter (e.g. RemoteConnCount), extend the (IP, EventId) row set
//          rather than adding a new column here.

using Microsoft.Data.Sqlite;

namespace RdpAudit.Service.Storage;

/// <summary>Batched raw-SQL upserter for <c>IpEventSummary</c> and <c>IpEventTypeCounter</c>.
/// Prepared once per batch; parameters are rebound row-by-row without allocation.</summary>
public sealed class IpEventSummaryUpserter : IDisposable
{
	// ── Fields & DI ──────────────────────────────────────────────────────────────

	private const string SummarySql = @"
INSERT INTO IpEventSummary (
	IpBinary16, IpText, AddressFamily,
	FirstEventUtc, FirstEventId, FirstEventSequence, FirstEventSnapshot,
	LastEventUtc, LastEventId, LastEventSequence, LastEventSnapshot,
	TotalEventCount, SuccessCount, FailureCount,
	ShardRelativePath, ShardRecordCount, ShardBytes, ShardFormatVersion,
	ShardEvictedCount, ShardOldestRetainedUtc, IsSubnetAggregate, Flags)
VALUES (
	$ip, $ipText, $family,
	$firstUtc, $firstId, $firstSeq, $firstSnap,
	$lastUtc, $lastId, $lastSeq, $lastSnap,
	1, $successDelta, $failureDelta,
	$shardPath, 1, $shardBytes, $shardVer,
	0, $lastUtc, $isAgg, 0)
ON CONFLICT(IpBinary16) DO UPDATE SET
	LastEventUtc      = excluded.LastEventUtc,
	LastEventId       = excluded.LastEventId,
	LastEventSequence = excluded.LastEventSequence,
	LastEventSnapshot = excluded.LastEventSnapshot,
	TotalEventCount   = IpEventSummary.TotalEventCount + 1,
	SuccessCount      = IpEventSummary.SuccessCount + excluded.SuccessCount,
	FailureCount      = IpEventSummary.FailureCount + excluded.FailureCount,
	ShardRecordCount  = MIN(IpEventSummary.ShardRecordCount + 1, $shardCapacity),
	ShardBytes        = excluded.ShardBytes,
	ShardEvictedCount = IpEventSummary.ShardEvictedCount + $evictedDelta,
	ShardOldestRetainedUtc = CASE
		WHEN $evictedDelta > 0 THEN excluded.LastEventUtc
		ELSE IpEventSummary.ShardOldestRetainedUtc
	END;";

	private const string CounterSql = @"
INSERT INTO IpEventTypeCounter (IpBinary16, EventId, Count, FirstUtc, LastUtc)
VALUES ($ip, $eventId, 1, $utc, $utc)
ON CONFLICT(IpBinary16, EventId) DO UPDATE SET
	Count = IpEventTypeCounter.Count + 1,
	LastUtc = excluded.LastUtc;";

	private readonly SqliteCommand _summary;
	private readonly SqliteCommand _counter;

	private readonly SqliteParameter _pIp;
	private readonly SqliteParameter _pIpText;
	private readonly SqliteParameter _pFamily;
	private readonly SqliteParameter _pFirstUtc;
	private readonly SqliteParameter _pFirstId;
	private readonly SqliteParameter _pFirstSeq;
	private readonly SqliteParameter _pFirstSnap;
	private readonly SqliteParameter _pLastUtc;
	private readonly SqliteParameter _pLastId;
	private readonly SqliteParameter _pLastSeq;
	private readonly SqliteParameter _pLastSnap;
	private readonly SqliteParameter _pShardPath;
	private readonly SqliteParameter _pShardBytes;
	private readonly SqliteParameter _pShardVer;
	private readonly SqliteParameter _pIsAgg;
	private readonly SqliteParameter _pSuccessDelta;
	private readonly SqliteParameter _pFailureDelta;
	private readonly SqliteParameter _pShardCapacity;
	private readonly SqliteParameter _pEvictedDelta;

	private readonly SqliteParameter _cIp;
	private readonly SqliteParameter _cEventId;
	private readonly SqliteParameter _cUtc;

	// ── Construction ─────────────────────────────────────────────────────────────

	public IpEventSummaryUpserter(SqliteConnection connection, SqliteTransaction transaction)
	{
		ArgumentNullException.ThrowIfNull(connection);
		ArgumentNullException.ThrowIfNull(transaction);

		_summary = connection.CreateCommand();
		_summary.Transaction = transaction;
		_summary.CommandText = SummarySql;

		_pIp = _summary.CreateParameter(); _pIp.ParameterName = "$ip";
		_pIpText = _summary.CreateParameter(); _pIpText.ParameterName = "$ipText";
		_pFamily = _summary.CreateParameter(); _pFamily.ParameterName = "$family";
		_pFirstUtc = _summary.CreateParameter(); _pFirstUtc.ParameterName = "$firstUtc";
		_pFirstId = _summary.CreateParameter(); _pFirstId.ParameterName = "$firstId";
		_pFirstSeq = _summary.CreateParameter(); _pFirstSeq.ParameterName = "$firstSeq";
		_pFirstSnap = _summary.CreateParameter(); _pFirstSnap.ParameterName = "$firstSnap";
		_pLastUtc = _summary.CreateParameter(); _pLastUtc.ParameterName = "$lastUtc";
		_pLastId = _summary.CreateParameter(); _pLastId.ParameterName = "$lastId";
		_pLastSeq = _summary.CreateParameter(); _pLastSeq.ParameterName = "$lastSeq";
		_pLastSnap = _summary.CreateParameter(); _pLastSnap.ParameterName = "$lastSnap";
		_pShardPath = _summary.CreateParameter(); _pShardPath.ParameterName = "$shardPath";
		_pShardBytes = _summary.CreateParameter(); _pShardBytes.ParameterName = "$shardBytes";
		_pShardVer = _summary.CreateParameter(); _pShardVer.ParameterName = "$shardVer";
		_pIsAgg = _summary.CreateParameter(); _pIsAgg.ParameterName = "$isAgg";
		_pSuccessDelta = _summary.CreateParameter(); _pSuccessDelta.ParameterName = "$successDelta";
		_pFailureDelta = _summary.CreateParameter(); _pFailureDelta.ParameterName = "$failureDelta";
		_pShardCapacity = _summary.CreateParameter(); _pShardCapacity.ParameterName = "$shardCapacity";
		_pEvictedDelta = _summary.CreateParameter(); _pEvictedDelta.ParameterName = "$evictedDelta";

		_summary.Parameters.Add(_pIp);
		_summary.Parameters.Add(_pIpText);
		_summary.Parameters.Add(_pFamily);
		_summary.Parameters.Add(_pFirstUtc);
		_summary.Parameters.Add(_pFirstId);
		_summary.Parameters.Add(_pFirstSeq);
		_summary.Parameters.Add(_pFirstSnap);
		_summary.Parameters.Add(_pLastUtc);
		_summary.Parameters.Add(_pLastId);
		_summary.Parameters.Add(_pLastSeq);
		_summary.Parameters.Add(_pLastSnap);
		_summary.Parameters.Add(_pShardPath);
		_summary.Parameters.Add(_pShardBytes);
		_summary.Parameters.Add(_pShardVer);
		_summary.Parameters.Add(_pIsAgg);
		_summary.Parameters.Add(_pSuccessDelta);
		_summary.Parameters.Add(_pFailureDelta);
		_summary.Parameters.Add(_pShardCapacity);
		_summary.Parameters.Add(_pEvictedDelta);
		_summary.Prepare();

		_counter = connection.CreateCommand();
		_counter.Transaction = transaction;
		_counter.CommandText = CounterSql;

		_cIp = _counter.CreateParameter(); _cIp.ParameterName = "$ip";
		_cEventId = _counter.CreateParameter(); _cEventId.ParameterName = "$eventId";
		_cUtc = _counter.CreateParameter(); _cUtc.ParameterName = "$utc";

		_counter.Parameters.Add(_cIp);
		_counter.Parameters.Add(_cEventId);
		_counter.Parameters.Add(_cUtc);
		_counter.Prepare();
	}

	// ── Public API ───────────────────────────────────────────────────────────────

	/// <summary>Upserts one IP-attributed event under the caller's transaction. All parameters
	/// are re-bound to existing SqliteParameter instances so this call allocates only through
	/// the ADO.NET driver's internal buffers.</summary>
	public void Upsert(in IpEventRow row)
	{
		_pIp.Value = row.IpBinary;
		_pIpText.Value = row.IpText;
		_pFamily.Value = row.AddressFamily;
		_pFirstUtc.Value = row.EventUtcTicks;
		_pFirstId.Value = row.EventId;
		_pFirstSeq.Value = row.Sequence;
		_pFirstSnap.Value = row.Snapshot;
		_pLastUtc.Value = row.EventUtcTicks;
		_pLastId.Value = row.EventId;
		_pLastSeq.Value = row.Sequence;
		_pLastSnap.Value = row.Snapshot;
		_pShardPath.Value = row.ShardRelativePath;
		_pShardBytes.Value = row.ShardBytes;
		_pShardVer.Value = row.ShardFormatVersion;
		_pIsAgg.Value = row.IsSubnetAggregate ? 1 : 0;
		_pSuccessDelta.Value = row.IsSuccess ? 1 : 0;
		_pFailureDelta.Value = row.IsFailure ? 1 : 0;
		_pShardCapacity.Value = row.ShardCapacity;
		_pEvictedDelta.Value = row.EvictedOne ? 1 : 0;

		_summary.ExecuteNonQuery();

		_cIp.Value = row.IpBinary;
		_cEventId.Value = row.EventId;
		_cUtc.Value = row.EventUtcTicks;
		_counter.ExecuteNonQuery();
	}

	// ── Disposal & Pool Returns ──────────────────────────────────────────────────

	/// <inheritdoc />
	public void Dispose()
	{
		_summary.Dispose();
		_counter.Dispose();
	}
}

/// <summary>Value type carrying one upsert's parameters. Passed by <c>in</c>-ref for zero copy.</summary>
public readonly struct IpEventRow
{
	public readonly byte[] IpBinary;
	public readonly string IpText;
	public readonly int AddressFamily;
	public readonly long EventUtcTicks;
	public readonly int EventId;
	public readonly long Sequence;
	public readonly byte[] Snapshot;
	public readonly string ShardRelativePath;
	public readonly long ShardBytes;
	public readonly int ShardFormatVersion;
	public readonly int ShardCapacity;
	public readonly bool IsSubnetAggregate;
	public readonly bool IsSuccess;
	public readonly bool IsFailure;
	public readonly bool EvictedOne;

	public IpEventRow(
		byte[] ipBinary,
		string ipText,
		int addressFamily,
		long eventUtcTicks,
		int eventId,
		long sequence,
		byte[] snapshot,
		string shardRelativePath,
		long shardBytes,
		int shardFormatVersion,
		int shardCapacity,
		bool isSubnetAggregate,
		bool isSuccess,
		bool isFailure,
		bool evictedOne)
	{
		IpBinary = ipBinary;
		IpText = ipText;
		AddressFamily = addressFamily;
		EventUtcTicks = eventUtcTicks;
		EventId = eventId;
		Sequence = sequence;
		Snapshot = snapshot;
		ShardRelativePath = shardRelativePath;
		ShardBytes = shardBytes;
		ShardFormatVersion = shardFormatVersion;
		ShardCapacity = shardCapacity;
		IsSubnetAggregate = isSubnetAggregate;
		IsSuccess = isSuccess;
		IsFailure = isFailure;
		EvictedOne = evictedOne;
	}
}
