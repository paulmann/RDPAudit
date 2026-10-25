/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 2.0.0
// File   : DatabaseSnapshotVerifier.cs
// Project: RdpAudit.Core (RdpAudit.Core.Backup)
// Purpose: Verifies a database snapshot on disk before anything is allowed to trust it: the manifest
//          must parse, the database file must exist, its SHA-256 must equal the manifest's, the copy
//          must pass PRAGMA quick_check, and - when the caller supplies the migrations the running
//          binaries know - the snapshot's schema must not be ahead of them (restoring such a snapshot
//          would install a downgrade). Shared by the Service (verify IPC command) and the Configurator
//          (restore), so both answer "is this snapshot usable" with exactly the same code. Read-only
//          in the strongest sense: the snapshot is opened read-only and nothing under it is written,
//          moved or deleted.
// Depends: Microsoft.Data.Sqlite, SchemaCompatibility, DatabaseBackupManifest, DatabaseBackupLayout
// Extends: Add a check by adding a DatabaseSnapshotVerdict member and its evaluation here; both
//          callers pick the new verdict up automatically.

using System.Globalization;
using System.Security.Cryptography;
using Microsoft.Data.Sqlite;

namespace RdpAudit.Core.Backup;

/// <summary>Why a snapshot is or is not usable. Ordered by the stage of verification that produced it.</summary>
public enum DatabaseSnapshotVerdict
{
	/// <summary>Every check passed.</summary>
	Ok = 0,

	/// <summary>The snapshot directory does not exist.</summary>
	SnapshotMissing = 1,

	/// <summary>The snapshot has no readable manifest.</summary>
	ManifestUnreadable = 2,

	/// <summary>The snapshot's database file is missing.</summary>
	DatabaseMissing = 3,

	/// <summary>The database file does not match the SHA-256 recorded when the snapshot was taken.</summary>
	HashMismatch = 4,

	/// <summary>PRAGMA quick_check did not report the copy as sound.</summary>
	QuickCheckFailed = 5,

	/// <summary>The snapshot's schema is ahead of the running binaries, so restoring it would be a
	/// downgrade.</summary>
	SchemaIncompatible = 6,

	/// <summary>The snapshot's database could not be opened for verification.</summary>
	Unreadable = 7,
}

/// <summary>Evidence behind a snapshot verification verdict.</summary>
public sealed record DatabaseSnapshotVerification(
	DatabaseSnapshotVerdict Verdict,
	string SnapshotDirectory,
	string? DatabasePath,
	DatabaseBackupManifest? Manifest,
	string? ManifestError,
	string? ExpectedSha256,
	string? ActualSha256,
	string? QuickCheckResult,
	SchemaCompatibilityResult? Schema,
	string Message)
{
	/// <summary>True only when every check passed.</summary>
	public bool IsUsable => Verdict == DatabaseSnapshotVerdict.Ok;
}

/// <summary>Read-only verification of a database snapshot directory.</summary>
public static class DatabaseSnapshotVerifier
{
	/// <summary>Tables whose row counts are recorded in a manifest, in reporting order. Kept in one
	/// place so a snapshot's manifest and its verification describe the same evidence.</summary>
	public static readonly string[] CountedTables =
	[
		"RawEvents",
		"AuthAttemptFacts",
		"RdpConnectionFacts",
		"IpEventSummaries",
		"IpEventTypeCounters",
		"Alerts",
		"ActiveBlocks",
		"AttackStats",
		"AbuseReports",
		"OperationLogs",
		"CrossHostFacts",
		"ProcessObservations",
		"EventDeletionLedger",
	];

	/// <summary>Name of the EF Core migrations history table.</summary>
	public const string MigrationsHistoryTable = "__EFMigrationsHistory";

	/// <summary>
	/// Verifies the snapshot at <paramref name="snapshotDirectory"/>. <paramref name="knownMigrations"/>
	/// is the migration list of the running binaries; pass null to skip the downgrade check (a caller
	/// that only wants integrity, for example a maintenance probe). Never throws for a bad snapshot:
	/// every failure is reported as a verdict with an English message.
	/// </summary>
	public static DatabaseSnapshotVerification Verify(
		string snapshotDirectory,
		IReadOnlyList<string>? knownMigrations,
		CancellationToken cancellationToken)
	{
		ArgumentException.ThrowIfNullOrWhiteSpace(snapshotDirectory);
		string leafName = Path.GetFileName(snapshotDirectory.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar));
		string directory = Path.GetFullPath(snapshotDirectory);
		if (!DatabaseBackupLayout.TryParseTimestamp(leafName, out _, out _))
		{
			return new DatabaseSnapshotVerification(
				DatabaseSnapshotVerdict.SnapshotMissing,
				directory,
				null,
				null,
				null,
				null,
				null,
				null,
				null,
				"The directory name is not a recognised database snapshot name (expected " + DatabaseBackupLayout.TimestampFormat + ").");
		}

		string manifestPath = Path.Combine(directory, DatabaseBackupLayout.ManifestFileName);
		string databasePath = Path.Combine(
			directory,
			DatabaseBackupLayout.DatabaseFolderName,
			DatabaseBackupLayout.DatabaseFileName);

		if (!Directory.Exists(directory))
		{
			return new DatabaseSnapshotVerification(
				DatabaseSnapshotVerdict.SnapshotMissing,
				directory,
				null,
				null,
				null,
				null,
				null,
				null,
				null,
				"The snapshot directory does not exist: " + directory);
		}

		if (!DatabaseBackupManifestCodec.TryRead(manifestPath, out DatabaseBackupManifest? manifest, out string? manifestError)
			|| manifest is null)
		{
			return new DatabaseSnapshotVerification(
				DatabaseSnapshotVerdict.ManifestUnreadable,
				directory,
				null,
				null,
				manifestError,
				null,
				null,
				null,
				null,
				"This snapshot cannot be trusted: " + (manifestError ?? "the manifest is unreadable."));
		}

		if (!File.Exists(databasePath))
		{
			return new DatabaseSnapshotVerification(
				DatabaseSnapshotVerdict.DatabaseMissing,
				directory,
				databasePath,
				manifest,
				null,
				manifest.DatabaseSha256,
				null,
				null,
				null,
				"The snapshot manifest is readable but the database copy is missing: " + databasePath);
		}

		string expected = (manifest.DatabaseSha256 ?? string.Empty).Trim();
		string actual;
		try
		{
			actual = ComputeSha256(databasePath, cancellationToken);
		}
		catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
		{
			throw;
		}
		catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
		{
			return new DatabaseSnapshotVerification(
				DatabaseSnapshotVerdict.Unreadable,
				directory,
				databasePath,
				manifest,
				null,
				expected,
				null,
				null,
				null,
				"The snapshot database could not be read for hashing: " + ex.Message);
		}

		if (expected.Length == 0 || !string.Equals(expected, actual, StringComparison.OrdinalIgnoreCase))
		{
			return new DatabaseSnapshotVerification(
				DatabaseSnapshotVerdict.HashMismatch,
				directory,
				databasePath,
				manifest,
				null,
				expected,
				actual,
				null,
				null,
				"The snapshot database does not match the SHA-256 recorded when it was taken, so it was modified or damaged after the snapshot. Expected "
					+ (expected.Length == 0 ? "(none recorded)" : expected) + ", computed " + actual + ".");
		}

		string quickCheck;
		IReadOnlyList<string> appliedMigrations;
		try
		{
			quickCheck = RunQuickCheck(databasePath, cancellationToken);
			appliedMigrations = ReadAppliedMigrations(databasePath, cancellationToken);
		}
		catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
		{
			throw;
		}
		catch (SqliteException ex)
		{
			return new DatabaseSnapshotVerification(
				DatabaseSnapshotVerdict.Unreadable,
				directory,
				databasePath,
				manifest,
				null,
				expected,
				actual,
				null,
				null,
				"The snapshot database could not be opened: " + ex.Message);
		}

		if (!string.Equals(quickCheck, "ok", StringComparison.OrdinalIgnoreCase))
		{
			return new DatabaseSnapshotVerification(
				DatabaseSnapshotVerdict.QuickCheckFailed,
				directory,
				databasePath,
				manifest,
				null,
				expected,
				actual,
				quickCheck,
				null,
				"PRAGMA quick_check reported problems in the snapshot database: " + quickCheck);
		}

		SchemaCompatibilityResult? schema = null;
		if (knownMigrations is not null)
		{
			schema = SchemaCompatibility.Evaluate(appliedMigrations, knownMigrations, databasePath);
			if (schema.Verdict == SchemaCompatibilityVerdict.DatabaseAheadOfBinaries)
			{
				return new DatabaseSnapshotVerification(
					DatabaseSnapshotVerdict.SchemaIncompatible,
					directory,
					databasePath,
					manifest,
					null,
					expected,
					actual,
					quickCheck,
					schema,
					"The snapshot is sound but its schema is ahead of this build, so restoring it would downgrade the store. " + schema.Message);
			}
		}

		string message = string.Format(
			CultureInfo.InvariantCulture,
			"The snapshot is sound: {0} bytes, SHA-256 verified, quick_check ok, {1} table(s) counted, {2} applied migration(s).",
			manifest.DatabaseBytes,
			manifest.RowCounts.Count,
			manifest.AppliedMigrationCount);

		return new DatabaseSnapshotVerification(
			DatabaseSnapshotVerdict.Ok,
			directory,
			databasePath,
			manifest,
			null,
			expected,
			actual,
			quickCheck,
			schema,
			message);
	}

	/// <summary>Streamed uppercase hexadecimal SHA-256 of a file. Streaming keeps a multi-gigabyte
	/// snapshot from being materialized in memory.</summary>
	public static string ComputeSha256(string filePath, CancellationToken cancellationToken)
	{
		ArgumentException.ThrowIfNullOrWhiteSpace(filePath);
		using FileStream stream = new(filePath, FileMode.Open, FileAccess.Read, FileShare.Read, 1024 * 1024, FileOptions.SequentialScan);
		using SHA256 sha = SHA256.Create();
		byte[] hash = sha.ComputeHash(stream);
		cancellationToken.ThrowIfCancellationRequested();
		return Convert.ToHexString(hash);
	}

	/// <summary>Runs <c>PRAGMA quick_check</c> against a database file opened read-only and returns its
	/// first row. "ok" means the copy is structurally sound.</summary>
	public static string RunQuickCheck(string databasePath, CancellationToken cancellationToken)
	{
		ArgumentException.ThrowIfNullOrWhiteSpace(databasePath);
		using SqliteConnection connection = OpenReadOnly(databasePath);
		using SqliteCommand command = connection.CreateCommand();
		command.CommandText = "PRAGMA quick_check;";
		object? result = command.ExecuteScalar();
		cancellationToken.ThrowIfCancellationRequested();
		return result as string ?? "(no result)";
	}

	/// <summary>Reads the EF migration history of a database file, newest known order preserved: the
	/// table is ordered by <c>MigrationId</c>, which is the same order EF applies migrations in. An
	/// absent history table yields an empty list (a new database). A history table that exists but
	/// cannot be read yields null, which <see cref="SchemaCompatibility"/> reports as unavailable.</summary>
	public static IReadOnlyList<string> ReadAppliedMigrations(string databasePath, CancellationToken cancellationToken)
	{
		ArgumentException.ThrowIfNullOrWhiteSpace(databasePath);
		using SqliteConnection connection = OpenReadOnly(databasePath);
		if (!TableExists(connection, MigrationsHistoryTable))
		{
			return Array.Empty<string>();
		}

		List<string> migrations = [];
		using SqliteCommand command = connection.CreateCommand();
		command.CommandText = "SELECT MigrationId FROM __EFMigrationsHistory ORDER BY MigrationId;";
		using SqliteDataReader reader = command.ExecuteReader();
		while (reader.Read())
		{
			cancellationToken.ThrowIfCancellationRequested();
			migrations.Add(reader.IsDBNull(0) ? string.Empty : reader.GetString(0));
		}

		return migrations;
	}

	/// <summary>Counts the rows of <see cref="CountedTables"/> inside a database file. A table that does
	/// not exist in this schema is skipped rather than reported as zero, so "empty" and "absent" stay
	/// distinguishable in the manifest.</summary>
	public static Dictionary<string, long> CountKeyTables(string databasePath, CancellationToken cancellationToken)
	{
		ArgumentException.ThrowIfNullOrWhiteSpace(databasePath);
		Dictionary<string, long> counts = new(StringComparer.Ordinal);
		using SqliteConnection connection = OpenReadOnly(databasePath);
		foreach (string table in CountedTables)
		{
			cancellationToken.ThrowIfCancellationRequested();
			string? statement = CountStatementFor(table);
			if (statement is null || !TableExists(connection, table))
			{
				continue;
			}

			using SqliteCommand command = connection.CreateCommand();
			SetCommandText(command, statement);
			object? result = command.ExecuteScalar();
			if (result is long count)
			{
				counts[table] = count;
			}
		}

		return counts;
	}

	/// <summary>
	/// Assigns a count statement to a command. The statement comes from
	/// <see cref="CountStatementFor"/> and is therefore a compile-time literal: no identifier and no
	/// literal ever comes from configuration, from an operator or from a manifest, and the only
	/// variable part - the table name used to look the literal up - never reaches SQL. The CA2100
	/// review therefore resolves to "not injectable", and the single reviewed site is kept here.
	/// </summary>
	private static void SetCommandText(SqliteCommand command, string sql)
	{
#pragma warning disable CA2100 // Reviewed: the statement is a literal selected by table name; no input reaches SQL.
		command.CommandText = sql;
#pragma warning restore CA2100
	}

	/// <summary>
	/// The count statement of one table. Every statement is a literal so no table name is ever
	/// concatenated into SQL; the switch is also the single list of tables a manifest counts, and it
	/// stays in sync with <see cref="CountedTables"/> by construction of the callers.
	/// </summary>
	private static string? CountStatementFor(string table) => table switch
	{
		"RawEvents" => "SELECT COUNT(*) FROM \"RawEvents\";",
		"AuthAttemptFacts" => "SELECT COUNT(*) FROM \"AuthAttemptFacts\";",
		"RdpConnectionFacts" => "SELECT COUNT(*) FROM \"RdpConnectionFacts\";",
		"IpEventSummaries" => "SELECT COUNT(*) FROM \"IpEventSummaries\";",
		"IpEventTypeCounters" => "SELECT COUNT(*) FROM \"IpEventTypeCounters\";",
		"Alerts" => "SELECT COUNT(*) FROM \"Alerts\";",
		"ActiveBlocks" => "SELECT COUNT(*) FROM \"ActiveBlocks\";",
		"AttackStats" => "SELECT COUNT(*) FROM \"AttackStats\";",
		"AbuseReports" => "SELECT COUNT(*) FROM \"AbuseReports\";",
		"OperationLogs" => "SELECT COUNT(*) FROM \"OperationLogs\";",
		"CrossHostFacts" => "SELECT COUNT(*) FROM \"CrossHostFacts\";",
		"ProcessObservations" => "SELECT COUNT(*) FROM \"ProcessObservations\";",
		"EventDeletionLedger" => "SELECT COUNT(*) FROM \"EventDeletionLedger\";",
		_ => null,
	};

	/// <summary>True when the named table exists. The name is always a compile-time constant.</summary>
	public static bool TableExists(SqliteConnection connection, string tableName)
	{
		ArgumentNullException.ThrowIfNull(connection);
		ArgumentException.ThrowIfNullOrWhiteSpace(tableName);
		using SqliteCommand command = connection.CreateCommand();
		command.CommandText = "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = $name LIMIT 1;";
		command.Parameters.AddWithValue("$name", tableName);
		return command.ExecuteScalar() is not null;
	}

	/// <summary>
	/// Opens a database file read-only. Snapshots written by the backup service are normalised to
	/// <c>journal_mode = DELETE</c>, so a read-only open never needs to create a WAL sidecar; a
	/// snapshot that cannot be opened read-only is reported as unreadable rather than silently
	/// upgraded to a write.
	///
	/// Pooling is disabled: a pooled connection is returned to the pool while its file handle stays
	/// open, and the caller of a verification is routinely about to delete, move or replace the file it
	/// just verified. Verification is a cold path, so a fresh handle costs nothing that matters.
	/// </summary>
	private static SqliteConnection OpenReadOnly(string databasePath)
	{
		SqliteConnection connection = new(new SqliteConnectionStringBuilder
		{
			DataSource = databasePath,
			Mode = SqliteOpenMode.ReadOnly,
			Cache = SqliteCacheMode.Private,
			Pooling = false,
		}.ToString());
		connection.Open();
		return connection;
	}
}
