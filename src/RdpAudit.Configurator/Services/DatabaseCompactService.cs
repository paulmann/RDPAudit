/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 1.0.0
// File   : DatabaseCompactService.cs
// Project: RdpAudit.Configurator (RdpAudit.Configurator.Services)
// Purpose: The OFFLINE compaction of the evidence store - the only operation in the product that may
//          rewrite the whole SQLite file, and therefore the only one that requires the Windows service to
//          be stopped. A full VACUUM on a live store can hold the single writer for minutes on a
//          multi-gigabyte database, which is why the online purge path deliberately has no VACUUM and only
//          releases freelist pages with a bounded incremental vacuum (see docs/88).
//          The sequence mirrors the restore flow exactly - it shares LiveDatabaseSwap for the
//          rename/sidecar/staging mechanics - and adds the verification steps a compaction needs:
//            1. a WAL checkpoint (TRUNCATE) so committed frames are part of the copy,
//            2. VACUUM INTO a staging file next to the live database (the live file is only read),
//            3. the auto-vacuum mode of the COPY is normalised to INCREMENTAL: VACUUM INTO carries the
//               source's mode over (measured), so a store created before B27 produces a copy that is
//               still in mode NONE - and on such a store the online incremental_vacuum stays a no-op
//               forever. Bringing the copy to INCREMENTAL costs one further VACUUM over the already
//               compacted copy (measured: 0.66 s on a 57 MB store, file size unchanged within 0.1%)
//               and needs room for a second copy of it, which is why it refuses unless the volume
//               reports that much free space,
//            4. quick_check + per-table row counts + applied migrations of the copy compared against the
//               live store - if anything differs, nothing is swapped and the live store is untouched,
//            5. a foreign-key check of the copy,
//            6. the atomic swap.
//          A compaction that cannot prove data preservation is refused. The point of the operation is to
//          shrink the file, never to change what is in it - and the one thing this operation does change
//          by design is the auto-vacuum mode, which is a header setting no row depends on.
// Depends: ServiceControlRunner, LiveDatabaseSwap, DatabaseSnapshotVerifier
// Extends: Add a further offline store operation as a sibling method that validates its own artifact and
//          then calls LiveDatabaseSwap; never re-implement the swap sequence.

using System.Diagnostics;
using System.Globalization;
using System.Runtime.Versioning;
using System.Text;
using Microsoft.Data.Sqlite;
using RdpAudit.Core.Backup;
using RdpAudit.Core.Util;

namespace RdpAudit.Configurator.Services;

/// <summary>Outcome of an offline compaction. <see cref="BytesBefore"/> and <see cref="BytesAfter"/> are
/// the main database file lengths, so the report can state the reclaim in bytes rather than imply it.
/// <see cref="Compacted"/> and <see cref="Success"/> are deliberately separate: the store can be compacted
/// and swapped in while the Windows service fails to restart, and an operator needs to tell "the evidence
/// file is compacted, start the service by hand" apart from "the compaction never happened".
/// <see cref="AutoVacuumModeBefore"/> and <see cref="AutoVacuumModeAfter"/> are the <c>PRAGMA auto_vacuum</c>
/// values of the store before the operation and of the file that replaced it, so the operator can verify
/// that a legacy store really left mode NONE instead of taking the log's word for it.</summary>
public sealed record DatabaseCompactResult(
	bool Success,
	bool Compacted,
	long BytesBefore,
	long BytesAfter,
	string? PreStateBackupPath,
	string Log,
	int AutoVacuumModeBefore = -1,
	int AutoVacuumModeAfter = -1)
{
	/// <summary>Bytes the database file lost, or zero when it did not shrink.</summary>
	public long BytesReclaimed => BytesBefore > BytesAfter ? BytesBefore - BytesAfter : 0;

	/// <summary>Builds a failed result carrying only the report. Nothing was compacted and the store is
	/// untouched, so both flags are false.</summary>
	public static DatabaseCompactResult Fail(string log) => new(false, false, -1, -1, null, log);
}

/// <summary>Compacts the database file with the service stopped: <c>VACUUM INTO</c> a verified copy, then
/// an atomic swap. Never throws; every outcome is returned as a report.</summary>
[SupportedOSPlatform("windows")]
public sealed class DatabaseCompactService
{
	private const string DefaultServiceName = "RdpAuditService";
	private const string DefaultDisplayName = "RdpAudit Service";

	/// <summary>Suffix of the staging file the shared swap creates next to the live database while the
	/// validated copy is moved onto the freed name. Names the swap if it is ever found left behind.</summary>
	public const string StagingSuffix = ".compacting";

	/// <summary>Suffix of the compacted copy produced by <c>VACUUM INTO</c> and validated before the swap.
	/// Distinct from <see cref="StagingSuffix"/> on purpose: the copy is the swap's SOURCE, so it must not
	/// share a name with the file the swap creates and then renames.</summary>
	public const string CompactedCopySuffix = ".compacted";

	/// <summary>Suffix of the sidecar written next to the pre-state backup: the audit record of the
	/// compaction. It lives on disk because the operation replaces the very database that would otherwise
	/// hold an OperationLog row for it.</summary>
	public const string ReceiptSuffix = ".compact.json";

	/// <summary>The <c>PRAGMA auto_vacuum</c> value that lets the online path release free pages, and the
	/// mode this operation leaves behind. A store created before the B27 fix carries <c>0</c>, and on such a
	/// store <c>PRAGMA incremental_vacuum</c> is a documented no-op - which is the whole reason a legacy
	/// store needs this offline pass at all.</summary>
	public const int IncrementalAutoVacuumMode = 2;

	/// <summary>Free-space headroom this operation demands on the store's volume before it rewrites the
	/// compacted copy in place, as a multiple of that copy's size. A full <c>VACUUM</c> rebuilds the whole
	/// file, so the pass needs room for a second copy of it; refusing below that margin keeps a
	/// disk-limited host from starting a rewrite it cannot finish (which would leave the store uncompacted,
	/// never damaged - the copy is discarded and the live file is untouched).</summary>
	public const int RequiredFreeSpaceFactor = 2;

	private readonly string _serviceName;
	private readonly string _displayName;

	/// <summary>Creates the service for the production service name.</summary>
	public DatabaseCompactService()
		: this(DefaultServiceName, DefaultDisplayName)
	{
	}

	/// <summary>Creates the service for an explicit service name (tests, renamed installs).</summary>
	public DatabaseCompactService(string serviceName, string displayName)
	{
		ArgumentException.ThrowIfNullOrWhiteSpace(serviceName);
		ArgumentException.ThrowIfNullOrWhiteSpace(displayName);
		_serviceName = serviceName;
		_displayName = displayName;
	}

	/// <summary>Compacts <paramref name="databasePath"/> in place.</summary>
	public async Task<DatabaseCompactResult> ExecuteAsync(string databasePath, CancellationToken ct = default)
	{
		ArgumentException.ThrowIfNullOrWhiteSpace(databasePath);

		StringBuilder log = new();
		string operatorIdentity = ResolveOperatorIdentity();
		log.AppendLine("RdpAudit offline database compaction (VACUUM INTO + atomic swap)");
		log.AppendLine("=================================================================");
		log.AppendLine("Started (UTC):  " + DateTime.UtcNow.ToString("O", CultureInfo.InvariantCulture));
		log.AppendLine("Operator:       " + operatorIdentity);
		log.AppendLine("Database:       " + databasePath);
		log.AppendLine();

		string databaseFullPath = Path.GetFullPath(databasePath);
		if (!File.Exists(databaseFullPath))
		{
			log.AppendLine("REFUSED: no database file exists at " + databaseFullPath + ".");
			return DatabaseCompactResult.Fail(log.ToString());
		}

		log.AppendLine("Stopping service '" + _serviceName + "' before compacting the database...");
		ServiceControlRunner runner = new(_serviceName, _displayName);
		ServiceOperationResult stopResult = await runner.StopAsync(ct).ConfigureAwait(false);
		log.AppendLine(stopResult.Format());

		ServiceProcessInfo process = await runner.QueryAsync(ct).ConfigureAwait(false);
		if (process.Installed && process.ProcessId is not null)
		{
			log.AppendLine();
			log.AppendLine("REFUSED: the service is still running (PID "
				+ process.ProcessId.Value.ToString(CultureInfo.InvariantCulture)
				+ "). A full VACUUM rewrites the entire file and would hold the writer for the whole "
				+ "rewrite; stop the service and retry.");
			return DatabaseCompactResult.Fail(log.ToString());
		}

		long bytesBefore = new FileInfo(databaseFullPath).Length;
		string compactedPath = databaseFullPath + CompactedCopySuffix;
		LiveDatabaseSwap.TryDelete(compactedPath);

		// Read before anything is written: this is the mode of the store the operator started with, and the
		// report has to be able to say whether this pass was the one that brought it to INCREMENTAL.
		int autoVacuumModeBefore = ReadAutoVacuumMode(databaseFullPath);
		int autoVacuumModeAfter;
		log.AppendLine("Auto-vacuum mode reported by the live store: "
			+ DescribeAutoVacuumMode(autoVacuumModeBefore)
			+ (autoVacuumModeBefore == IncrementalAutoVacuumMode
				? " (online reclamation is available on this store)."
				: " - online reclamation is a no-op here until this store is rewritten."));

		try
		{
			PrepareSource(databaseFullPath, log);
			CreateCompactedCopy(databaseFullPath, compactedPath, log);
			autoVacuumModeAfter = NormaliseAutoVacuumMode(compactedPath, log);
		}
		catch (OperationCanceledException)
		{
			LiveDatabaseSwap.TryDelete(compactedPath);
			log.AppendLine("CANCELLED: the compaction was cancelled before the copy was validated; nothing was replaced.");
			return DatabaseCompactResult.Fail(log.ToString());
		}
		catch (Exception ex) when (ex is SqliteException or InvalidOperationException or IOException or UnauthorizedAccessException)
		{
			LiveDatabaseSwap.TryDelete(compactedPath);
			log.AppendLine();
			log.AppendLine("FAILED: " + ex.GetType().Name + " - " + ex.Message);
			log.AppendLine("The live database was not touched; it is still served by the same file.");
			return DatabaseCompactResult.Fail(log.ToString());
		}

		if (!ValidateCopy(databaseFullPath, compactedPath, log, ct))
		{
			LiveDatabaseSwap.TryDelete(compactedPath);
			log.AppendLine();
			log.AppendLine("REFUSED: the compacted copy did not prove data preservation, so the live store was NOT");
			log.AppendLine("touched. This is a bug signal, not an operator error - please report it with this log.");
			return DatabaseCompactResult.Fail(log.ToString());
		}

		string stamp = LiveDatabaseSwap.BuildStamp();
		LiveDatabaseSwap.SwapOutcome swap = LiveDatabaseSwap.SwapIn(
			databaseFullPath,
			compactedPath,
			StagingSuffix,
			stamp,
			log);
		LiveDatabaseSwap.TryDelete(compactedPath);
		LiveDatabaseSwap.TryDelete(databaseFullPath + StagingSuffix);
		if (!swap.Swapped)
		{
			log.AppendLine();
			log.AppendLine(string.Equals(swap.FailureReason, "cancelled", StringComparison.Ordinal)
				? "CANCELLED: the compaction was cancelled before the swap completed; the pre-state database was put back."
				: "REFUSED: " + swap.FailureReason);
			return DatabaseCompactResult.Fail(log.ToString());
		}

		long bytesAfter = new FileInfo(databaseFullPath).Length;
		long reclaimed = bytesBefore > bytesAfter ? bytesBefore - bytesAfter : 0;
		log.AppendLine();
		log.AppendLine(string.Create(
			CultureInfo.InvariantCulture,
			$"Size before: {bytesBefore} bytes; after: {bytesAfter} bytes; reclaimed: {reclaimed} bytes."));
		log.AppendLine(string.Format(
			CultureInfo.InvariantCulture,
			"Auto-vacuum mode: {0} -> {1}. The store that is now in place is the one the service reopens.",
			autoVacuumModeBefore,
			autoVacuumModeAfter));

		string? receiptPath = WriteReceipt(
			swap.PreStateBackupPath,
			databaseFullPath,
			operatorIdentity,
			bytesBefore,
			bytesAfter,
			autoVacuumModeBefore,
			autoVacuumModeAfter,
			log);

		log.AppendLine();
		log.AppendLine("Starting service '" + _serviceName + "'...");
		ServiceOperationResult startResult = await runner.StartAsync(ct).ConfigureAwait(false);
		log.AppendLine(startResult.Format());
		if (!startResult.Success)
		{
			log.AppendLine();
			log.AppendLine("The database was compacted but the service could not be started. Start it manually");
			log.AppendLine("via services.msc. The pre-compaction database is at:");
			log.AppendLine(swap.PreStateBackupPath ?? "(no pre-state backup was needed)");
			return new DatabaseCompactResult(
				false,
				Compacted: true,
				bytesBefore,
				bytesAfter,
				swap.PreStateBackupPath,
				log.ToString(),
				autoVacuumModeBefore,
				autoVacuumModeAfter);
		}

		log.AppendLine();
		log.AppendLine("Compaction complete. The database was rewritten into a compact file with the same content;");
		log.AppendLine("the pre-compaction database is kept until you delete it.");
		if (receiptPath is not null)
		{
			log.AppendLine("Compaction receipt: " + receiptPath);
		}

		return new DatabaseCompactResult(
			true,
			Compacted: true,
			bytesBefore,
			bytesAfter,
			swap.PreStateBackupPath,
			log.ToString(),
			autoVacuumModeBefore,
			autoVacuumModeAfter);
	}

	// ── Source preparation ───────────────────────────────────────────────────────

	/// <summary>Opens a NON-POOLED connection to a database file. Pooling is disabled deliberately: this
	/// service exists to rename the database file, and a pooled connection keeps a Win32 handle on it after
	/// Dispose, which turns the swap into "the file is being used by another process". A compaction opens
	/// two connections in its whole lifetime, so pooling would buy nothing and cost the operation.</summary>
	private static SqliteConnection OpenConnection(string databasePath)
	{
		SqliteConnectionStringBuilder builder = new()
		{
			DataSource = databasePath,
			Pooling = false,
		};
		SqliteConnection connection = new(builder.ToString());
		connection.Open();
		return connection;
	}

	/// <summary>Checkpoints the WAL so every committed frame is part of the main file the copy is read
	/// from. Without this a compaction run right after a busy period could copy a file whose latest
	/// commits still live in the sidecar - the copy would be consistent, but it would silently move the
	/// WAL boundary.</summary>
	private static void PrepareSource(string databasePath, StringBuilder log)
	{
		using SqliteConnection connection = OpenConnection(databasePath);
		using SqliteCommand command = connection.CreateCommand();
		command.CommandText = "PRAGMA wal_checkpoint(TRUNCATE);";
		command.ExecuteNonQuery();
		log.AppendLine("WAL checkpoint (TRUNCATE) issued on the live database.");
	}

	/// <summary>Writes the compacted copy with <c>VACUUM INTO</c>, which reads the source and writes a new
	/// file: the live database is never modified by this step, so a failure here is free.</summary>
	private static void CreateCompactedCopy(string databasePath, string stagingPath, StringBuilder log)
	{
		using SqliteConnection connection = OpenConnection(databasePath);
		using SqliteCommand command = connection.CreateCommand();

		// The statement is composed from a constant plus a path this process resolved. VACUUM INTO takes a
		// string literal, not a bound parameter, so the path is escaped by doubling single quotes rather
		// than concatenated raw.
#pragma warning disable CA2100 // Reviewed: constant statement plus a single-quote-escaped absolute path resolved by this process.
		command.CommandText = "VACUUM INTO '" + stagingPath.Replace("'", "''", StringComparison.Ordinal) + "';";
#pragma warning restore CA2100
		command.ExecuteNonQuery();
		log.AppendLine("VACUUM INTO produced the compacted copy: " + stagingPath);
	}

	// ── Copy validation ──────────────────────────────────────────────────────────

	/// <summary>Brings the compacted copy to <c>auto_vacuum = INCREMENTAL</c> and returns the mode it
	/// reports afterwards. This is the operator's offline route out of B27: <c>VACUUM INTO</c> copies the
	/// source's auto-vacuum mode into the new file (measured on SQLite 3.41.2 - a copy of a mode-NONE store
	/// is mode NONE), so without this step a legacy store would be compacted back into the very mode whose
	/// online reclamation is a no-op, and the next purge would release nothing again.
	/// <para>
	/// SQLite applies an auto-vacuum change to a store that already has pages only through a full
	/// <c>VACUUM</c>, and that is exactly what runs here - on the COPY, never on the live file, and only
	/// after the operator asked for an offline compaction with the service stopped. The rewrite is bounded
	/// by the copy's own size (measured: 0.66 s on a 57 MB store, the file unchanged within 0.1%), and the
	/// volume must report at least <see cref="RequiredFreeSpaceFactor"/> times the copy's size free before
	/// it starts, because a full <c>VACUUM</c> rebuilds the whole file.
	/// </para>
	/// <para>
	/// A copy that cannot be proven to be INCREMENTAL afterwards throws: swapping in a store whose mode is
	/// not what the report claims would defeat the purpose of the operation, and the live store is still
	/// untouched at that point.
	/// </para>
	/// </summary>
	private static int NormaliseAutoVacuumMode(string compactedPath, StringBuilder log)
	{
		int modeBefore = ReadAutoVacuumMode(compactedPath);
		if (modeBefore == IncrementalAutoVacuumMode)
		{
			log.AppendLine("Compact copy auto-vacuum mode: " + DescribeAutoVacuumMode(modeBefore)
				+ " (carried over from the source); no further rewrite was needed.");
			return modeBefore;
		}

		long copyBytes = new FileInfo(compactedPath).Length;
		long requiredFreeBytes = copyBytes * RequiredFreeSpaceFactor;
		long freeBytes = ReadVolumeFreeBytes(compactedPath);
		if (freeBytes >= 0 && freeBytes < requiredFreeBytes)
		{
			throw new InvalidOperationException(string.Format(
				CultureInfo.InvariantCulture,
				"REFUSED: normalising the auto-vacuum mode needs room for a second copy of the compacted file "
				+ "({0} bytes), i.e. at least {1} bytes free, but the volume reports {2}. Free space on the "
				+ "store's volume and run the compaction again; the live store is unchanged.",
				copyBytes,
				requiredFreeBytes,
				freeBytes));
		}

		if (freeBytes < 0)
		{
			log.AppendLine("WARNING: the free space of the store's volume could not be read; the mode-normalising");
			log.AppendLine("         rewrite proceeds. If it runs out of room it fails and the live store stays as it is.");
		}

		Stopwatch timer = Stopwatch.StartNew();
		using (SqliteConnection connection = OpenConnection(compactedPath))
		{
			// Both statements on ONE connection: the pragma is a pending request that the VACUUM issued from
			// the same connection is what applies. This is also the pair the offline procedure documents.
			using SqliteCommand command = connection.CreateCommand();
			command.CommandText = "PRAGMA auto_vacuum = INCREMENTAL; VACUUM;";
			command.ExecuteNonQuery();
		}

		timer.Stop();
		int modeAfter = ReadAutoVacuumMode(compactedPath);
		if (modeAfter != IncrementalAutoVacuumMode)
		{
			throw new InvalidOperationException(string.Format(
				CultureInfo.InvariantCulture,
				"the compacted copy still reports auto_vacuum = {0} after the rewrite, so it was not swapped "
				+ "in. Online space reclamation would have stayed a no-op on it.",
				modeAfter));
		}

		log.AppendLine(string.Format(
			CultureInfo.InvariantCulture,
			"Compact copy auto-vacuum mode normalised: {0} -> {1} (one VACUUM over the {2}-byte copy in "
			+ "{3:0.###} s, {4} bytes free on the volume). Online space reclamation is available on the "
			+ "store that will be swapped in.",
			modeBefore,
			modeAfter,
			copyBytes,
			timer.Elapsed.TotalSeconds,
			freeBytes));
		return modeAfter;
	}

	/// <summary>Reads <c>PRAGMA auto_vacuum</c> from a database file, or <c>-1</c> when it cannot be
	/// read. A reader that cannot state the mode must not be reported as if it had.</summary>
	internal static int ReadAutoVacuumMode(string databasePath)
	{
		try
		{
			using SqliteConnection connection = OpenConnection(databasePath);
			using SqliteCommand command = connection.CreateCommand();
			command.CommandText = "PRAGMA auto_vacuum;";
			object? value = command.ExecuteScalar();
			return value is null or DBNull ? -1 : Convert.ToInt32(value, CultureInfo.InvariantCulture);
		}
		catch (Exception ex) when (ex is SqliteException or InvalidOperationException or IOException or UnauthorizedAccessException)
		{
			return -1;
		}
	}

	/// <summary>Names the auto-vacuum mode the way the operator meets it in the SQLite documentation, and
	/// says "unknown" rather than guessing when the mode could not be read.</summary>
	internal static string DescribeAutoVacuumMode(int mode) => mode switch
	{
		IncrementalAutoVacuumMode => "INCREMENTAL (2)",
		1 => "FULL (1)",
		0 => "NONE (0) - online space reclamation is a no-op",
		_ => "unknown (" + mode.ToString(CultureInfo.InvariantCulture) + ")",
	};

	/// <summary>Free bytes on the volume hosting a file, or <c>-1</c> when the volume cannot be inspected.
	/// A negative answer is reported as unknown and never as "no room".</summary>
	internal static long ReadVolumeFreeBytes(string path)
	{
		try
		{
			string? root = Path.GetPathRoot(Path.GetFullPath(path));
			if (string.IsNullOrEmpty(root))
			{
				return -1;
			}

			DriveInfo drive = new(root);
			return drive.IsReady ? drive.AvailableFreeSpace : -1;
		}
		catch (Exception ex) when (ex is ArgumentException or IOException or UnauthorizedAccessException)
		{
			return -1;
		}
	}

	/// <summary>Proves the compacted copy holds the same evidence as the live store before anything is
	/// swapped: structural integrity (quick_check), the same applied migrations, the same row count for
	/// every counted table, and no foreign-key violations. Any mismatch refuses the swap, because the
	/// purpose of the operation is to shrink the file and never to change its content.</summary>
	private static bool ValidateCopy(
		string databasePath,
		string stagingPath,
		StringBuilder log,
		CancellationToken ct)
	{
		string quickCheck = DatabaseSnapshotVerifier.RunQuickCheck(stagingPath, ct);
		log.AppendLine("quick_check on the copy: " + quickCheck);
		if (!string.Equals(quickCheck, "ok", StringComparison.OrdinalIgnoreCase))
		{
			return false;
		}

		IReadOnlyList<string> sourceMigrations = DatabaseSnapshotVerifier.ReadAppliedMigrations(databasePath, ct);
		IReadOnlyList<string> copyMigrations = DatabaseSnapshotVerifier.ReadAppliedMigrations(stagingPath, ct);
		if (!sourceMigrations.SequenceEqual(copyMigrations, StringComparer.Ordinal))
		{
			log.AppendLine(string.Create(
				CultureInfo.InvariantCulture,
				$"Migration history differs: source has {sourceMigrations.Count}, copy has {copyMigrations.Count}."));
			return false;
		}

		log.AppendLine(string.Create(
			CultureInfo.InvariantCulture,
			$"Applied migrations match: {sourceMigrations.Count}."));

		Dictionary<string, long> sourceCounts = DatabaseSnapshotVerifier.CountKeyTables(databasePath, ct);
		Dictionary<string, long> copyCounts = DatabaseSnapshotVerifier.CountKeyTables(stagingPath, ct);
		foreach ((string table, long sourceCount) in sourceCounts.OrderBy(pair => pair.Key, StringComparer.Ordinal))
		{
			if (!copyCounts.TryGetValue(table, out long copyCount) || copyCount != sourceCount)
			{
				log.AppendLine(string.Create(
					CultureInfo.InvariantCulture,
					$"Row count differs for {table}: source={sourceCount} copy={(copyCounts.TryGetValue(table, out long value) ? value.ToString(CultureInfo.InvariantCulture) : "absent")}."));
				return false;
			}
		}

		log.AppendLine(string.Create(
			CultureInfo.InvariantCulture,
			$"Row counts match for all {sourceCounts.Count} counted table(s)."));

		string foreignKeys = RunForeignKeyCheck(stagingPath);
		log.AppendLine("foreign_key_check on the copy: " + foreignKeys);
		return foreignKeys.StartsWith("ok", StringComparison.Ordinal);
	}

	/// <summary>Runs <c>PRAGMA foreign_key_check</c> against a database file and returns a one-line
	/// outcome. Read-only: a failure to run it is reported as such instead of being read as a pass.</summary>
	private static string RunForeignKeyCheck(string databasePath)
	{
		try
		{
			using SqliteConnection connection = OpenConnection(databasePath);
			using SqliteCommand command = connection.CreateCommand();
			command.CommandText = "PRAGMA foreign_key_check;";
			int violations = 0;
			using SqliteDataReader reader = command.ExecuteReader();
			while (reader.Read())
			{
				violations++;
			}

			return violations == 0
				? "ok (no violations)"
				: violations.ToString(CultureInfo.InvariantCulture) + " violation(s)";
		}
		catch (Exception ex) when (ex is SqliteException or InvalidOperationException or IOException or UnauthorizedAccessException)
		{
			return "not run (" + ex.GetType().Name + " - " + ex.Message + ")";
		}
	}

	// ── Audit ────────────────────────────────────────────────────────────────────

	/// <summary>Writes the compaction receipt next to the pre-state backup. Best effort but reported, so
	/// "the compaction ran" and "the compaction is recorded" never collapse into one claim.</summary>
	private static string? WriteReceipt(
		string? preStatePath,
		string databasePath,
		string operatorIdentity,
		long bytesBefore,
		long bytesAfter,
		int autoVacuumModeBefore,
		int autoVacuumModeAfter,
		StringBuilder log)
	{
		if (string.IsNullOrWhiteSpace(preStatePath))
		{
			return null;
		}

		string receiptPath = preStatePath + ReceiptSuffix;
		try
		{
			object receipt = new
			{
				compactedUtc = DateTime.UtcNow,
				operatorIdentity,
				databasePath,
				bytesBefore,
				bytesAfter,
				autoVacuumModeBefore,
				autoVacuumModeAfter,
				preStateBackupPath = preStatePath,
			};
			File.WriteAllText(receiptPath, System.Text.Json.JsonSerializer.Serialize(receipt, JsonOptions.Indented));
			return receiptPath;
		}
		catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
		{
			log.AppendLine("WARNING: the compaction receipt could not be written: " + ex.Message);
			return null;
		}
	}

	private static string ResolveOperatorIdentity()
	{
		try
		{
			if (OperatingSystem.IsWindows())
			{
				using System.Security.Principal.WindowsIdentity identity = System.Security.Principal.WindowsIdentity.GetCurrent();
				return identity.Name ?? "(unknown)";
			}
		}
		catch (Exception ex) when (ex is InvalidOperationException or UnauthorizedAccessException)
		{
			// Best effort - identity is observational.
		}

		return Environment.UserDomainName + "\\" + Environment.UserName;
	}
}
