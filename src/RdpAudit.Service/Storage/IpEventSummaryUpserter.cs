/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 2.0.1
// File   : IpEventSummaryUpserter.cs
// Project: RdpAudit.Service (RdpAudit.Service.Storage)
// Purpose: Updates durable IP event summaries and per-event counters inside the caller's SQLite transaction.
// Depends: SqliteConnection, SqliteTransaction, RawEvent
// Extends: Add new summary counters by extending both prepared commands and IpEventRow construction.
//          Shard columns are owned by the shard writer, not by this type: leave them untouched
//          here until ShardWriter is wired into the ingestion path.

using System.Net;
using System.Net.Sockets;
using System.Text;
using Microsoft.Data.Sqlite;
using RdpAudit.Core.Models;

namespace RdpAudit.Service.Storage;

/// <summary>Updates IP summary and event-type counter rows without replacing the first observed event.</summary>
public sealed class IpEventSummaryUpserter
{
	// ── Fields & DI ──────────────────────────────────────────────────────────────

	// This statement deliberately never names a Shard* column. Those columns describe
	// a shard file on disk, and this type does not create one, so it has nothing
	// truthful to say about them. They are left null by the INSERT and untouched by
	// the ON CONFLICT branch. When ShardWriter is connected to the ingestion path it
	// becomes their sole writer, updating them from the real shard header inside this
	// same transaction.
	private const string SummarySql = """
INSERT INTO IpEventSummary (
	IpBinary16, IpText, AddressFamily,
	FirstEventUtc, FirstEventId, FirstEventSequence, FirstEventSnapshot,
	LastEventUtc, LastEventId, LastEventSequence, LastEventSnapshot,
	TotalEventCount, SuccessCount, FailureCount,
	IsSubnetAggregate, Flags)
VALUES (
	$ip, $ipText, $family,
	$firstUtc, $firstId, $firstSequence, $firstSnapshot,
	$lastUtc, $lastId, $lastSequence, $lastSnapshot,
	1, $successDelta, $failureDelta,
	0, 0)
ON CONFLICT(IpBinary16) DO UPDATE SET
	LastEventUtc = excluded.LastEventUtc,
	LastEventId = excluded.LastEventId,
	LastEventSequence = excluded.LastEventSequence,
	LastEventSnapshot = excluded.LastEventSnapshot,
	TotalEventCount = IpEventSummary.TotalEventCount + 1,
	SuccessCount = IpEventSummary.SuccessCount + excluded.SuccessCount,
	FailureCount = IpEventSummary.FailureCount + excluded.FailureCount;
""";
	private const string CounterSql = """
INSERT INTO IpEventTypeCounter (IpBinary16, EventId, Count, FirstUtc, LastUtc)
VALUES ($ip, $eventId, 1, $utc, $utc)
ON CONFLICT(IpBinary16, EventId) DO UPDATE SET
	Count = IpEventTypeCounter.Count + 1,
	LastUtc = excluded.LastUtc;
""";

	// ── Public API ───────────────────────────────────────────────────────────────

	/// <summary>Updates summaries for all resolved-IP events using the supplied open transaction.</summary>
	public async Task UpsertBatchAsync(
		SqliteConnection connection,
		SqliteTransaction transaction,
		IReadOnlyList<RawEvent> events,
		CancellationToken cancellationToken)
	{
		ArgumentNullException.ThrowIfNull(connection);
		ArgumentNullException.ThrowIfNull(transaction);
		ArgumentNullException.ThrowIfNull(events);

		await using SqliteCommand summary = CreateSummaryCommand(connection, transaction);
		await using SqliteCommand counter = CreateCounterCommand(connection, transaction);
		await summary.PrepareAsync(cancellationToken).ConfigureAwait(false);
		await counter.PrepareAsync(cancellationToken).ConfigureAwait(false);

		for (int index = 0; index < events.Count; index++)
		{
			cancellationToken.ThrowIfCancellationRequested();
			RawEvent rawEvent = events[index];
			if (!TryCreateRow(rawEvent, out IpEventRow row))
			{
				continue;
			}

			BindSummary(summary, row);
			await summary.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
			BindCounter(counter, row);
			await counter.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
		}
	}

	// ── Core Logic ───────────────────────────────────────────────────────────────

	private static SqliteCommand CreateSummaryCommand(SqliteConnection connection, SqliteTransaction transaction)
	{
		SqliteCommand command = connection.CreateCommand();
		command.Transaction = transaction;
		command.CommandText = SummarySql;
		AddParameter(command, "$ip");
		AddParameter(command, "$ipText");
		AddParameter(command, "$family");
		AddParameter(command, "$firstUtc");
		AddParameter(command, "$firstId");
		AddParameter(command, "$firstSequence");
		AddParameter(command, "$firstSnapshot");
		AddParameter(command, "$lastUtc");
		AddParameter(command, "$lastId");
		AddParameter(command, "$lastSequence");
		AddParameter(command, "$lastSnapshot");
		AddParameter(command, "$successDelta");
		AddParameter(command, "$failureDelta");
		return command;
	}

	private static SqliteCommand CreateCounterCommand(SqliteConnection connection, SqliteTransaction transaction)
	{
		SqliteCommand command = connection.CreateCommand();
		command.Transaction = transaction;
		command.CommandText = CounterSql;
		AddParameter(command, "$ip");
		AddParameter(command, "$eventId");
		AddParameter(command, "$utc");
		return command;
	}

	private static void AddParameter(SqliteCommand command, string name)
	{
		SqliteParameter parameter = command.CreateParameter();
		parameter.ParameterName = name;
		command.Parameters.Add(parameter);
	}

	private static bool TryCreateRow(RawEvent rawEvent, out IpEventRow row)
	{
		if (string.IsNullOrWhiteSpace(rawEvent.SourceIp)
			|| !IPAddress.TryParse(rawEvent.SourceIp, out IPAddress? address))
		{
			row = default;
			return false;
		}

		IPAddress canonicalAddress = address.AddressFamily == AddressFamily.InterNetwork
			? address.MapToIPv6()
			: address;
		byte[] binaryAddress = rawEvent.SourceIpBinary is { Length: 16 }
			? rawEvent.SourceIpBinary
			: canonicalAddress.GetAddressBytes();
		long utcTicks = rawEvent.TimeUtc.Ticks;
		byte[] snapshot = Encoding.UTF8.GetBytes(rawEvent.Details ?? string.Empty);
		bool isSuccess = rawEvent.EventId == 4624;
		bool isFailure = rawEvent.EventId == 4625;
		row = new IpEventRow(
			binaryAddress,
			canonicalAddress.ToString(),
			address.AddressFamily == AddressFamily.InterNetwork ? 4 : 6,
			utcTicks,
			rawEvent.EventId,
			rawEvent.IngestionSequence,
			snapshot,
			isSuccess,
			isFailure);
		return true;
	}

	private static void BindSummary(SqliteCommand command, in IpEventRow row)
	{
		command.Parameters["$ip"].Value = row.IpBinary;
		command.Parameters["$ipText"].Value = row.IpText;
		command.Parameters["$family"].Value = row.AddressFamily;
		command.Parameters["$firstUtc"].Value = row.UtcTicks;
		command.Parameters["$firstId"].Value = row.EventId;
		command.Parameters["$firstSequence"].Value = row.IngestionSequence;
		command.Parameters["$firstSnapshot"].Value = row.Snapshot;
		command.Parameters["$lastUtc"].Value = row.UtcTicks;
		command.Parameters["$lastId"].Value = row.EventId;
		command.Parameters["$lastSequence"].Value = row.IngestionSequence;
		command.Parameters["$lastSnapshot"].Value = row.Snapshot;
		command.Parameters["$successDelta"].Value = row.IsSuccess ? 1 : 0;
		command.Parameters["$failureDelta"].Value = row.IsFailure ? 1 : 0;
	}

	private static void BindCounter(SqliteCommand command, in IpEventRow row)
	{
		command.Parameters["$ip"].Value = row.IpBinary;
		command.Parameters["$eventId"].Value = row.EventId;
		command.Parameters["$utc"].Value = row.UtcTicks;
	}

	private readonly record struct IpEventRow(
		byte[] IpBinary,
		string IpText,
		int AddressFamily,
		long UtcTicks,
		int EventId,
		long IngestionSequence,
		byte[] Snapshot,
		bool IsSuccess,
		bool IsFailure);
}
