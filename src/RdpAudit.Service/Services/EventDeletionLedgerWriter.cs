// File:    src/RdpAudit.Service/Services/EventDeletionLedgerWriter.cs
// Module:  RdpAudit.Service.Services
// Purpose: The single writer of EventDeletionLedger rows. Every deletion path that must be auditable -
//          information-density retention and operator-initiated subject purge - appends through this class,
//          so all of them produce the same twelve content columns AND the same SHA-256 chain link
//          (PreviousHash -> EntryHash). Two independent INSERT statements would eventually disagree about
//          the canonical hash input, and a chain that two writers compute differently reports tampering
//          that never happened, which is worse than no chain at all.
//          The writer never opens its own connection or transaction: it runs on the caller's, inside the
//          caller's transaction, so a ledger row and the deletion it accounts for commit or roll back
//          together. A ledger entry that survives a rolled-back delete would claim evidence was removed
//          when it was not.
// Extends: System.Object

using System.Globalization;
using Microsoft.Data.Sqlite;
using RdpAudit.Core.Integrity;

namespace RdpAudit.Service.Services;

/// <summary>Appends hash-chained rows to <c>EventDeletionLedger</c> on a caller-owned connection and
/// transaction.</summary>
internal static class EventDeletionLedgerWriter
{
	/// <summary>Reads the head of the chain: the EntryHash of the newest chained row, or the genesis value
	/// when the ledger has no chained rows yet. Rows written before the chain existed carry null hashes and
	/// are skipped by the filter, which is what makes the chain start after the upgrade instead of
	/// pretending to cover history it never saw.</summary>
	internal static async Task<string> ReadChainHeadAsync(
		SqliteConnection connection,
		SqliteTransaction? transaction,
		CancellationToken cancellationToken)
	{
		ArgumentNullException.ThrowIfNull(connection);

		using SqliteCommand command = connection.CreateCommand();
		command.Transaction = transaction;
		command.CommandText =
			"SELECT \"EntryHash\" FROM \"EventDeletionLedger\" " +
			"WHERE \"EntryHash\" IS NOT NULL ORDER BY \"Id\" DESC LIMIT 1;";
		object? value = await command.ExecuteScalarAsync(cancellationToken).ConfigureAwait(false);
		return value is string hash && LedgerChainHasher.IsHashShaped(hash)
			? hash
			: LedgerChainHasher.GenesisPreviousHash;
	}

	/// <summary>Appends one ledger row inside the caller's transaction and returns the row's own EntryHash,
	/// which is the chain head for the next append.</summary>
	internal static async Task<string> AppendAsync(
		SqliteConnection connection,
		SqliteTransaction? transaction,
		LedgerChainEntry entry,
		string previousHashHex,
		CancellationToken cancellationToken)
	{
		ArgumentNullException.ThrowIfNull(connection);
		ArgumentException.ThrowIfNullOrWhiteSpace(previousHashHex);

		string entryHash = LedgerChainHasher.ComputeEntryHash(previousHashHex, entry);

		using SqliteCommand command = connection.CreateCommand();
		command.Transaction = transaction;
		command.CommandText =
			"INSERT INTO \"EventDeletionLedger\"" +
			" (\"EventCode\", \"Scope\", \"IpBinary16\", \"WindowStartUtc\", \"WindowEndUtc\"," +
			" \"RowsDeleted\", \"Trigger\", \"RuleVersion\", \"Reason\", \"InitiatedBy\", \"CreatedUtc\"," +
			" \"PreviousHash\", \"EntryHash\")" +
			" VALUES ($eventCode, $scope, $ipBinary16, $windowStart, $windowEnd," +
			" $rowsDeleted, $trigger, $ruleVersion, $reason, $initiatedBy, $createdUtc," +
			" $previousHash, $entryHash);";
		command.Parameters.AddWithValue("$eventCode", entry.EventCode);
		command.Parameters.AddWithValue("$scope", entry.Scope);
		command.Parameters.Add(new SqliteParameter("$ipBinary16", (object?)entry.IpBinary16 ?? DBNull.Value));
		command.Parameters.AddWithValue("$windowStart", entry.WindowStartUtc);
		command.Parameters.AddWithValue("$windowEnd", entry.WindowEndUtc);
		command.Parameters.AddWithValue("$rowsDeleted", entry.RowsDeleted);
		command.Parameters.AddWithValue("$trigger", entry.Trigger);
		command.Parameters.AddWithValue("$ruleVersion", entry.RuleVersion);
		command.Parameters.AddWithValue("$reason", entry.Reason);
		command.Parameters.AddWithValue("$initiatedBy", entry.InitiatedBy);
		command.Parameters.AddWithValue("$createdUtc", entry.CreatedUtc);
		command.Parameters.AddWithValue("$previousHash", previousHashHex);
		command.Parameters.AddWithValue("$entryHash", entryHash);
		await command.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);

		return entryHash;
	}

	/// <summary>Renders the operator-facing reason text. Kept here so both deletion paths describe
	/// themselves in the same shape and a ledger reader can parse either with one format string.</summary>
	internal static string BuildReason(string ruleName, string trigger, string detail)
		=> string.Create(
			CultureInfo.InvariantCulture,
			$"{ruleName}; trigger={trigger}; {detail}");
}
