/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 1.0.0
// File   : LiveDatabaseSwap.cs
// Project: RdpAudit.Configurator (RdpAudit.Configurator.Services)
// Purpose: The single, shared implementation of the only safe way to REPLACE the live SQLite evidence
//          file while the Windows service is stopped. It exists because two operations need exactly the
//          same mechanics for entirely different reasons - a restore (put a verified snapshot in place)
//          and an offline compaction (put a VACUUM INTO copy in place) - and a second copy of these rules
//          is how one of them eventually forgets to move the WAL sidecar aside.
//          The sequence is deliberately conservative and reversible at every step:
//            1. rename the live database aside to a timestamped .bak (the operator's undo),
//            2. move the -wal and -shm sidecars aside - if a sidecar cannot be moved, abort, because
//               leaving a WAL from the old database next to a new database file is how a swap corrupts
//               the store it was meant to protect,
//            3. move the validated replacement onto the freed name through a staging file (a
//               cross-volume-safe move cannot be assumed, so the bytes are copied then renamed),
//            4. on cancellation or an IO/permission failure, put the original names back.
//          The caller owns validation: this class never decides whether a replacement is trustworthy.
// Depends: System.IO
// Extends: Add a new caller by validating its own artifact first and then calling SwapIn; do not add a
//          second implementation of the rename/sidecar/staging sequence.

using System.Globalization;
using System.Text;

namespace RdpAudit.Configurator.Services;

/// <summary>Shared mechanics for replacing the live database file with a validated replacement, with the
/// service stopped and every step reversible until the final move.</summary>
public static class LiveDatabaseSwap
{
	/// <summary>Sidecar suffixes SQLite keeps next to a WAL-mode database. Both must move with the
	/// database or the next reader sees a foreign WAL.</summary>
	public static readonly string[] SidecarSuffixes = ["-wal", "-shm"];

	/// <summary>Outcome of <see cref="SwapIn"/>. <see cref="PreStateBackupPath"/> is null when no live
	/// database existed before the swap, and is set whenever a previous file was renamed aside - including
	/// on failure, so the caller can tell the operator where their data went.</summary>
	public sealed record SwapOutcome(bool Swapped, string? PreStateBackupPath, string? FailureReason);

	/// <summary>Timestamp stamp used for the <c>.bak</c> names, in the same sortable format the snapshot
	/// layout uses.</summary>
	public static string BuildStamp() => DateTime.UtcNow.ToString("yyyyMMdd-HHmmss", CultureInfo.InvariantCulture);

	/// <summary>Replaces <paramref name="databasePath"/> with <paramref name="replacementPath"/>.
	/// Never throws: cancellation is reported as a failure so a caller that already logged the start of an
	/// operation can also log its end.</summary>
	/// <param name="databasePath">Absolute path of the live database to replace.</param>
	/// <param name="replacementPath">Absolute path of the already-validated replacement file.</param>
	/// <param name="stagingSuffix">Suffix of the staging file created next to the live database; it is
	/// named per operation (<c>.restoring</c>, <c>.compacting</c>) so a leftover staging file names the
	/// operation that was interrupted.</param>
	/// <param name="stamp">Stamp for the pre-state <c>.bak</c> names; see <see cref="BuildStamp"/>.</param>
	/// <param name="log">Report the caller is building.</param>
	public static SwapOutcome SwapIn(
		string databasePath,
		string replacementPath,
		string stagingSuffix,
		string stamp,
		StringBuilder log)
	{
		ArgumentException.ThrowIfNullOrWhiteSpace(databasePath);
		ArgumentException.ThrowIfNullOrWhiteSpace(replacementPath);
		ArgumentException.ThrowIfNullOrWhiteSpace(stagingSuffix);
		ArgumentNullException.ThrowIfNull(log);

		string databaseFullPath = Path.GetFullPath(databasePath);
		string preStatePath = databaseFullPath + "." + stamp + ".bak";
		string stagingPath = databaseFullPath + stagingSuffix;
		bool databaseMoved = false;

		try
		{
			if (File.Exists(databaseFullPath))
			{
				File.Move(databaseFullPath, preStatePath);
				databaseMoved = true;
				log.AppendLine("Renamed the live database to: " + preStatePath);
			}
			else
			{
				log.AppendLine("No live database file exists at the target; the replacement will create it.");
			}

			if (!MoveSidecarsAside(databaseFullPath, stamp, log))
			{
				// Put the database back: a WAL left behind with a different database file is worse than an
				// aborted operation.
				RestoreDatabaseName(databaseFullPath, preStatePath, databaseMoved, log);
				return new SwapOutcome(
					false,
					databaseMoved ? preStatePath : null,
					"A WAL/SHM sidecar could not be moved aside, so nothing was replaced.");
			}

			string? targetDirectory = Path.GetDirectoryName(databaseFullPath);
			if (!string.IsNullOrEmpty(targetDirectory))
			{
				Directory.CreateDirectory(targetDirectory);
			}

			File.Copy(replacementPath, stagingPath, overwrite: true);
			File.Move(stagingPath, databaseFullPath, overwrite: true);
			log.AppendLine("Moved the validated replacement into place: " + databaseFullPath);
			return new SwapOutcome(true, databaseMoved ? preStatePath : null, null);
		}
		catch (OperationCanceledException)
		{
			TryDelete(stagingPath);
			RestoreDatabaseName(databaseFullPath, preStatePath, databaseMoved, log);
			log.AppendLine("CANCELLED: the replacement was cancelled before it completed; the pre-state database was put back.");
			return new SwapOutcome(false, databaseMoved ? preStatePath : null, "cancelled");
		}
		catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
		{
			TryDelete(stagingPath);
			RestoreDatabaseName(databaseFullPath, preStatePath, databaseMoved, log);
			log.AppendLine();
			log.AppendLine("FAILED: " + ex.GetType().Name + " - " + ex.Message);
			log.AppendLine("The pre-state database was put back; the store is unchanged.");
			return new SwapOutcome(false, databaseMoved ? preStatePath : null, ex.Message);
		}
	}

	/// <summary>
	/// Moves the WAL and SHM sidecars of the live database to timestamped <c>.bak</c> names, following
	/// the convention the guided database reset already uses. Returns false when a sidecar exists but
	/// could not be moved, which the caller treats as a reason to abort.
	/// </summary>
	public static bool MoveSidecarsAside(string databasePath, string stamp, StringBuilder log)
	{
		foreach (string suffix in SidecarSuffixes)
		{
			string sidecar = databasePath + suffix;
			if (!File.Exists(sidecar))
			{
				continue;
			}

			try
			{
				string moved = sidecar + "." + stamp + ".bak";
				File.Move(sidecar, moved);
				log.AppendLine("Renamed sidecar to:        " + moved);
			}
			catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
			{
				log.AppendLine("ERROR: could not move sidecar '" + sidecar + "': " + ex.GetType().Name + " - " + ex.Message);
				return false;
			}
		}

		return true;
	}

	/// <summary>Renames the pre-state database back onto the live name. Only acts when the live name is
	/// still free, so it can never overwrite a replacement that already landed.</summary>
	public static void RestoreDatabaseName(string databasePath, string preStatePath, bool databaseMoved, StringBuilder log)
	{
		if (!databaseMoved)
		{
			return;
		}

		try
		{
			if (File.Exists(preStatePath) && !File.Exists(databasePath))
			{
				File.Move(preStatePath, databasePath);
				log.AppendLine("Rolled the live database name back: " + databasePath);
			}
		}
		catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
		{
			log.AppendLine("WARNING: could not roll the database name back: " + ex.Message
				+ " The previous database is at " + preStatePath + ".");
		}
	}

	/// <summary>Deletes a file if it exists, swallowing the two failures that mean "someone else has it" -
	/// a leftover staging file is inert and the next operation overwrites it.</summary>
	public static void TryDelete(string path)
	{
		try
		{
			if (File.Exists(path))
			{
				File.Delete(path);
			}
		}
		catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
		{
			// Best effort.
		}
	}
}
