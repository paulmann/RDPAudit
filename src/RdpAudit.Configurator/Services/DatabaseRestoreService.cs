/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 2.0.0
// File   : DatabaseRestoreService.cs
// Project: RdpAudit.Configurator (RdpAudit.Configurator.Services)
// Purpose: Restores a database snapshot OVER the live evidence store. The Configurator owns this path
//          because it needs the Windows service stopped: the file the service holds open cannot be
//          replaced while it runs. The sequence is deliberately conservative and reversible at every
//          step: verify the snapshot first (manifest, SHA-256, quick_check, and - when the migrations of
//          the installed binaries are known - a schema check that refuses a downgrade), stop the
//          service, hand the swap to the shared LiveDatabaseSwap mechanics (rename the live database
//          and its WAL/SHM sidecars aside as timestamped .bak files, move the snapshot onto the freed
//          name through a staging file), run a foreign-key check against the restored file, write a
//          restore receipt, and
//          start the service again. If any step before the copy fails, the original file names are
//          restored; if the copy fails, the pre-state backup is put back. A sidecar that cannot be
//          moved aside aborts the restore, because leaving a WAL from the old database next to a new
//          database file is how a restore corrupts the store it was meant to recover.
//          No WinForms type is referenced here: this is the service-layer half of the flow, so the UI
//          layer can call it and a test can drive it.
// Depends: ServiceControlRunner, DatabaseSnapshotVerifier, DatabaseBackupLayout, AuditDbContext
// Extends: Add a restore variant (for example shard-tree replacement) as a sibling method so each
//          destructive step keeps its own report and its own pre-state backup.

using System.Globalization;
using System.Runtime.Versioning;
using System.Text;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using RdpAudit.Core.Backup;
using RdpAudit.Core.Data;
using RdpAudit.Core.Util;

namespace RdpAudit.Configurator.Services;

/// <summary>Outcome of a database restore. <see cref="PreStateBackupPath"/> names the file the previous
/// live database was renamed to, so the operator can undo the restore by hand if needed.</summary>
public sealed record DatabaseRestoreResult(
	bool Success,
	string? RestoredFrom,
	string? PreStateBackupPath,
	string Log)
{
	/// <summary>Builds a failed result carrying only the report.</summary>
	public static DatabaseRestoreResult Fail(string log) => new(false, null, null, log);
}

/// <summary>Restores a verified database snapshot over the live store, with the service stopped.</summary>
[SupportedOSPlatform("windows")]
public sealed class DatabaseRestoreService
{
	private const string DefaultServiceName = "RdpAuditService";
	private const string DefaultDisplayName = "RdpAudit Service";

	/// <summary>Suffix appended to the restore receipt written next to the pre-state backup. The receipt
	/// is the audit record of a restore: the operation replaces the very database that would normally
	/// hold an OperationLog row, so the trail has to live on disk.</summary>
	public const string ReceiptSuffix = ".restore.json";

	private readonly string _serviceName;
	private readonly string _displayName;

	/// <summary>Creates the service for the production service name.</summary>
	public DatabaseRestoreService()
		: this(DefaultServiceName, DefaultDisplayName)
	{
	}

	/// <summary>Creates the service for an explicit service name (tests, renamed installs).</summary>
	public DatabaseRestoreService(string serviceName, string displayName)
	{
		ArgumentException.ThrowIfNullOrWhiteSpace(serviceName);
		ArgumentException.ThrowIfNullOrWhiteSpace(displayName);
		_serviceName = serviceName;
		_displayName = displayName;
	}

	/// <summary>Restores <paramref name="snapshotDirectory"/> onto <paramref name="databasePath"/>.
	/// Never throws: every outcome, including a refused one, is returned as a report so the caller can
	/// display it verbatim.</summary>
	/// <param name="snapshotDirectory">Absolute snapshot directory to restore from.</param>
	/// <param name="databasePath">Absolute path of the live database to replace.</param>
	/// <param name="knownMigrations">Migrations of the installed binaries. When null they are read from
	/// the Configurator's own assembly, which is the same list, so the downgrade check stays armed.</param>
	/// <param name="ct">Cancellation token.</param>
	public async Task<DatabaseRestoreResult> ExecuteAsync(
		string snapshotDirectory,
		string databasePath,
		IReadOnlyList<string>? knownMigrations = null,
		CancellationToken ct = default)
	{
		ArgumentException.ThrowIfNullOrWhiteSpace(snapshotDirectory);
		ArgumentException.ThrowIfNullOrWhiteSpace(databasePath);

		StringBuilder log = new();
		string operatorIdentity = ResolveOperatorIdentity();
		log.AppendLine("RdpAudit database restore");
		log.AppendLine("=========================");
		log.AppendLine("Started (UTC):  " + DateTime.UtcNow.ToString("O", CultureInfo.InvariantCulture));
		log.AppendLine("Operator:       " + operatorIdentity);
		log.AppendLine("Snapshot:       " + snapshotDirectory);
		log.AppendLine("Target:         " + databasePath);
		log.AppendLine();

		IReadOnlyList<string> migrations = knownMigrations ?? ResolveKnownMigrations();
		DatabaseSnapshotVerification verification = DatabaseSnapshotVerifier.Verify(snapshotDirectory, migrations, ct);
		log.AppendLine("Verification:   " + verification.Verdict + " - " + verification.Message);
		if (verification.ExpectedSha256 is not null)
		{
			log.AppendLine("Expected SHA-256: " + verification.ExpectedSha256);
			log.AppendLine("Actual SHA-256:   " + (verification.ActualSha256 ?? "(not computed)"));
		}

		if (!verification.IsUsable || verification.DatabasePath is null)
		{
			log.AppendLine();
			log.AppendLine("REFUSED: the snapshot did not pass verification, so the live store was NOT touched.");
			return DatabaseRestoreResult.Fail(log.ToString());
		}

		log.AppendLine();
		log.AppendLine("Stopping service '" + _serviceName + "' before replacing the database...");
		ServiceControlRunner runner = new(_serviceName, _displayName);
		ServiceOperationResult stopResult = await runner.StopAsync(ct).ConfigureAwait(false);
		log.AppendLine(stopResult.Format());

		ServiceProcessInfo process = await runner.QueryAsync(ct).ConfigureAwait(false);
		if (process.Installed && process.ProcessId is not null)
		{
			log.AppendLine();
			log.AppendLine("REFUSED: the service is still running (PID " + process.ProcessId.Value.ToString(CultureInfo.InvariantCulture)
				+ "). Replacing its database file now would corrupt it. Stop the service and retry.");
			return DatabaseRestoreResult.Fail(log.ToString());
		}

		string stamp = LiveDatabaseSwap.BuildStamp();
		string databaseFullPath = Path.GetFullPath(databasePath);

		LiveDatabaseSwap.SwapOutcome swap = LiveDatabaseSwap.SwapIn(
			databaseFullPath,
			verification.DatabasePath,
			".restoring",
			stamp,
			log);
		if (!swap.Swapped)
		{
			log.AppendLine();
			log.AppendLine(string.Equals(swap.FailureReason, "cancelled", StringComparison.Ordinal)
				? "CANCELLED: the restore was cancelled before it completed; the pre-state database was put back."
				: "REFUSED: " + swap.FailureReason);
			return DatabaseRestoreResult.Fail(log.ToString());
		}

		string? preStatePath = swap.PreStateBackupPath ?? databaseFullPath + "." + stamp + ".bak";
		string fkCheck = RunForeignKeyCheck(databaseFullPath, log);

		string? receiptPath = WriteReceipt(
			preStatePath,
			snapshotDirectory,
			databaseFullPath,
			verification,
			operatorIdentity,
			fkCheck,
			log);

		log.AppendLine();
		log.AppendLine("Starting service '" + _serviceName + "'...");
		ServiceOperationResult startResult = await runner.StartAsync(ct).ConfigureAwait(false);
		log.AppendLine(startResult.Format());
		if (!startResult.Success)
		{
			log.AppendLine();
			log.AppendLine("The database was replaced but the service could not be started. Start it manually via");
			log.AppendLine("services.msc, or run install.ps1 if it is no longer registered. The previous database is at:");
			log.AppendLine(preStatePath);
			return new DatabaseRestoreResult(false, snapshotDirectory, preStatePath, log.ToString());
		}

		log.AppendLine();
		log.AppendLine("Restore complete. The service is starting against the restored database; the previous");
		log.AppendLine("database is kept at " + preStatePath + " until you delete it.");
		if (receiptPath is not null)
		{
			log.AppendLine("Restore receipt: " + receiptPath);
		}

		return new DatabaseRestoreResult(true, snapshotDirectory, preStatePath, log.ToString());
	}

	// ── Post-swap integrity ──────────────────────────────────────────────────────

	/// <summary>Runs <c>PRAGMA foreign_key_check</c> against the freshly restored database and returns its
	/// outcome as a one-line report. Requirement R23 asks for a foreign-key check after every restore: a
	/// snapshot that is byte-consistent can still carry rows whose parents were removed by the peer that
	/// produced it, and a referential violation found here is fixable while the service is still stopped.
	/// The check is read-only, so a failure to run it cannot damage the restored store - and the report
	/// says so instead of implying the check passed.</summary>
	private static string RunForeignKeyCheck(string databasePath, StringBuilder log)
	{
		string outcome;
		try
		{
			// Pooling is disabled deliberately: a pooled connection keeps a handle on the file after
			// Dispose, and this one has just been swapped into place by a rename.
			Microsoft.Data.Sqlite.SqliteConnection connection = new(new Microsoft.Data.Sqlite.SqliteConnectionStringBuilder
			{
				DataSource = databasePath,
				Pooling = false,
			}.ToString());
			using (connection)
			{
				connection.Open();
				using Microsoft.Data.Sqlite.SqliteCommand command = connection.CreateCommand();
				command.CommandText = "PRAGMA foreign_key_check;";
				int violations = 0;
				using (Microsoft.Data.Sqlite.SqliteDataReader reader = command.ExecuteReader())
				{
					while (reader.Read())
					{
						violations++;
					}
				}

				outcome = violations == 0
					? "ok (no foreign-key violations)"
					: violations.ToString(CultureInfo.InvariantCulture) + " foreign-key violation(s)";
			}
		}
		catch (Exception ex) when (ex is InvalidOperationException or IOException or UnauthorizedAccessException
			or Microsoft.Data.Sqlite.SqliteException)
		{
			outcome = "not run (" + ex.GetType().Name + " - " + ex.Message + ")";
		}

		log.AppendLine("Foreign-key check: " + outcome);
		return outcome;
	}

	// ── Audit ────────────────────────────────────────────────────────────────────

	/// <summary>
	/// Writes the restore receipt next to the pre-state backup. The receipt is best-effort but reported:
	/// the operator is told whether the audit record exists, so "the restore ran" and "the restore is
	/// recorded" never collapse into one claim.
	/// </summary>
	private static string? WriteReceipt(
		string preStatePath,
		string snapshotDirectory,
		string databasePath,
		DatabaseSnapshotVerification verification,
		string operatorIdentity,
		string foreignKeyCheck,
		StringBuilder log)
	{
		string receiptPath = preStatePath + ReceiptSuffix;
		try
		{
			object receipt = new
			{
				restoredUtc = DateTime.UtcNow,
				operatorIdentity,
				snapshotDirectory,
				snapshotSha256 = verification.ActualSha256,
				snapshotVerdict = verification.Verdict.ToString(),
				databasePath,
				preStateBackupPath = preStatePath,
				foreignKeyCheck,
			};
			File.WriteAllText(receiptPath, JsonSerializer.Serialize(receipt, JsonOptions.Indented));
			return receiptPath;
		}
		catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
		{
			log.AppendLine("WARNING: the restore receipt could not be written: " + ex.Message);
			return null;
		}
	}

	/// <summary>
	/// Migrations of the binaries that ship with this Configurator. Read from the EF model, which is
	/// an in-memory enumeration, so no database is opened and the live store is not touched.
	/// </summary>
	private static List<string> ResolveKnownMigrations()
	{
		try
		{
			DbContextOptions<AuditDbContext> options = AuditDbContextOptionsFactory.Create(":memory:");
			using AuditDbContext db = new(options);
			List<string> known = [];
			foreach (string migration in db.Database.GetMigrations())
			{
				known.Add(migration);
			}

			return known;
		}
		catch (Exception ex) when (ex is InvalidOperationException or NotSupportedException)
		{
			// Without the list the schema check cannot run; verification then reports integrity only, and
			// the service's own downgrade guard still refuses a newer schema at startup.
			return [];
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
