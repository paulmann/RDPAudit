/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 1.0.0
// File   : LedgerChainVerifier.cs
// Project: RdpAudit.Core (RdpAudit.Core.Integrity)
// Purpose: Verifies the SHA-256 chain over EventDeletionLedger rows and reports exactly WHERE it broke.
//          The verification is a pure function over an ordered row list, so the same code path serves the
//          startup tamper check, the Database-tab overview and the tests - there is no second
//          implementation that could disagree.
//          What each attack looks like:
//            - a modified value  -> recomputing the row's own hash no longer matches its stored EntryHash;
//            - a deleted row     -> the successor's stored PreviousHash no longer matches its actual
//                                   predecessor's EntryHash, which is why deletion from the middle is
//                                   detected even though nothing about the survivor changed;
//            - a reordered row   -> the moved row's stored PreviousHash does not match the new neighbour
//                                   it now follows, so insertion/reordering is a break too;
//            - a truncated tail  -> the chain stays internally consistent: truncation of the newest rows
//              (or tail)            cannot be detected by a chain alone, and the fingerprint comparison
//                                   in StoreIntegrityComparer is what covers it. This is stated rather
//                                   than glossed over, because "the ledger verifies" must not be read as
//                                   "nothing can be removed from the ledger".
//          Rows written before the chain existed (both hash columns null) are counted separately as
//          unverifiable instead of being treated as a break: they genuinely cannot be verified, and
//          reporting them as tampering would be a false alarm.
// Depends: LedgerChainHasher, Microsoft.Data.Sqlite
// Extends: Add a new check as another field on LedgerChainVerification and a rule in Verify; keep the
//          entry point pure so it stays testable without a database.

using Microsoft.Data.Sqlite;

namespace RdpAudit.Core.Integrity;

/// <summary>One ledger row as the verifier needs it: the hashed content plus the two stored chain
/// columns.</summary>
public sealed record LedgerChainRow(
	long Id,
	LedgerChainEntry Entry,
	string? PreviousHash,
	string? EntryHash);

/// <summary>Outcome of a chain verification.</summary>
public sealed record LedgerChainVerification(
	bool IsIntact,
	long ChainedRows,
	long UnchainedRows,
	long? FirstBrokenId,
	string Message)
{
	/// <summary>True when there is at least one chained row, i.e. the chain is actually doing work.</summary>
	public bool HasChainedHistory => ChainedRows > 0;
}

/// <summary>Reads and verifies the deletion-ledger hash chain.</summary>
public static class LedgerChainVerifier
{
	/// <summary>Verifies an ordered (by ascending id) row list. Pure: no I/O, no database.</summary>
	public static LedgerChainVerification Verify(IReadOnlyList<LedgerChainRow> rows)
	{
		ArgumentNullException.ThrowIfNull(rows);

		long chained = 0;
		long unchained = 0;
		string previousHash = LedgerChainHasher.GenesisPreviousHash;

		foreach (LedgerChainRow row in rows)
		{
			if (row.EntryHash is null && row.PreviousHash is null)
			{
				// Pre-chain row: genuinely unverifiable, and not a break.
				unchained++;
				continue;
			}

			if (!LedgerChainHasher.IsHashShaped(row.EntryHash) || !LedgerChainHasher.IsHashShaped(row.PreviousHash))
			{
				return Broken(row, chained, unchained,
					"its chain columns are not SHA-256 hex values, so the row cannot be part of a chain");
			}

			if (!string.Equals(row.PreviousHash, previousHash, StringComparison.OrdinalIgnoreCase))
			{
				return Broken(row, chained, unchained,
					"its PreviousHash does not match the preceding entry, which means a row was deleted, "
						+ "inserted or reordered");
			}

			string expected = LedgerChainHasher.ComputeEntryHash(previousHash, row.Entry);
			if (!string.Equals(row.EntryHash, expected, StringComparison.OrdinalIgnoreCase))
			{
				return Broken(row, chained, unchained,
					"its content no longer hashes to its stored EntryHash, which means the row was modified");
			}

			previousHash = row.EntryHash!;
			chained++;
		}

		string message = unchained == 0
			? string.Format(
				System.Globalization.CultureInfo.InvariantCulture,
				"The deletion-ledger hash chain is intact across {0} entry(ies).",
				chained)
			: string.Format(
				System.Globalization.CultureInfo.InvariantCulture,
				"The deletion-ledger hash chain is intact across {0} entry(ies); {1} pre-chain entry(ies) "
					+ "written before the chain existed cannot be verified and are not counted.",
				chained,
				unchained);

		return new LedgerChainVerification(true, chained, unchained, null, message);
	}

	private static LedgerChainVerification Broken(
		LedgerChainRow row,
		long chained,
		long unchained,
		string reason)
	{
		string message = string.Format(
			System.Globalization.CultureInfo.InvariantCulture,
			"The deletion-ledger hash chain is BROKEN at entry {0}: {1}. Every entry after it is "
				+ "unverifiable, so deletions recorded there cannot be trusted.",
			row.Id,
			reason);
		return new LedgerChainVerification(false, chained, unchained, row.Id, message);
	}

	/// <summary>Reads every ledger row, ordered by id, and verifies the chain. Read-only.</summary>
	public static async Task<LedgerChainVerification> VerifyAsync(
		SqliteConnection connection,
		CancellationToken cancellationToken)
	{
		ArgumentNullException.ThrowIfNull(connection);
		List<LedgerChainRow> rows = await ReadAllAsync(connection, cancellationToken).ConfigureAwait(false);
		return Verify(rows);
	}

	/// <summary>Reads every ledger row in insertion order. The ledger holds one row per deletion pass and
	/// code, so it is small by construction; the read is still streamed rather than materialized twice.</summary>
	public static async Task<List<LedgerChainRow>> ReadAllAsync(
		SqliteConnection connection,
		CancellationToken cancellationToken)
	{
		ArgumentNullException.ThrowIfNull(connection);

		List<LedgerChainRow> rows = [];
		await using SqliteCommand command = connection.CreateCommand();
		command.CommandText =
			"SELECT \"Id\", \"EventCode\", \"Scope\", \"IpBinary16\", \"WindowStartUtc\", \"WindowEndUtc\", "
			+ "\"RowsDeleted\", \"Trigger\", \"RuleVersion\", \"Reason\", \"InitiatedBy\", \"CreatedUtc\", "
			+ "\"PreviousHash\", \"EntryHash\" "
			+ "FROM \"EventDeletionLedger\" ORDER BY \"Id\" ASC;";

		await using SqliteDataReader reader = await command.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
		while (await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
		{
			bool hasChainColumns = !reader.IsDBNull(12) || !reader.IsDBNull(13);
			rows.Add(new LedgerChainRow(
				reader.GetInt64(0),
				new LedgerChainEntry(
					reader.GetInt32(1),
					reader.GetInt32(2),
					reader.IsDBNull(3) ? null : (byte[])reader.GetValue(3),
					ReadTimestamp(reader, 4),
					ReadTimestamp(reader, 5),
					reader.GetInt64(6),
					reader.GetInt32(7),
					reader.GetInt32(8),
					reader.IsDBNull(9) ? string.Empty : reader.GetString(9),
					reader.IsDBNull(10) ? string.Empty : reader.GetString(10),
					ReadTimestamp(reader, 11)),
				hasChainColumns && !reader.IsDBNull(12) ? reader.GetString(12) : null,
				hasChainColumns && !reader.IsDBNull(13) ? reader.GetString(13) : null));
		}

		return rows;
	}

	/// <summary>Reads a DateTime column that must be present. EF's SQLite provider stores DateTime as
	/// ISO-8601 text, so the reader hands it over as a string; the value is parsed as the wall-clock UTC
	/// it was written as, which is exactly what the hash covers.</summary>
	private static DateTime ReadTimestamp(SqliteDataReader reader, int ordinal)
	{
		object value = reader.GetValue(ordinal);
		return value switch
		{
			DateTime dateTime => dateTime,
			string text => DateTime.Parse(
				text,
				System.Globalization.CultureInfo.InvariantCulture,
				System.Globalization.DateTimeStyles.None),
			_ => DateTime.MinValue,
		};
	}
}
