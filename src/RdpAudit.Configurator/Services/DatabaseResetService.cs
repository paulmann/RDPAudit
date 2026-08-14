/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 1.0.0
// File   : DatabaseResetService.cs
// Project: RdpAudit.Configurator (RdpAudit.Configurator.Services)
// Purpose: Guided recovery for an incompatible SQLite database. Called from the Diagnostics tab
//          when the Service left a migration-failure marker under ProgramData. Stops the Windows
//          service, backs up the database (plus WAL/SHM sidecar files) with a timestamped .bak
//          suffix, deletes the marker, and restarts the service so it can bootstrap a fresh
//          schema via EnsureCreatedAsync / MigrateAsync on the empty file.
// Depends: ServiceControlRunner, DatabaseMigrationFailureMarker, ServiceOperationResult, ILogger
// Extends: If additional recovery strategies are added (e.g. selective per-table drop and replay
//          from event source), model them here as sibling methods so the UI can offer a picker.

using System.Globalization;
using System.Runtime.Versioning;
using RdpAudit.Core.Data;

namespace RdpAudit.Configurator.Services;

/// <summary>Outcome of a database reset attempt.</summary>
public sealed record DatabaseResetResult(
	bool Success,
	string? BackupPath,
	string Log)
{
	public static DatabaseResetResult Fail(string log) => new(false, null, log);
}

/// <summary>Guided recovery when the Service left a migration-failure marker on disk.</summary>
[SupportedOSPlatform("windows")]
public sealed class DatabaseResetService
{
	private const string DefaultServiceName = "RdpAuditService";
	private const string DefaultDisplayName = "RdpAudit Service";

	private readonly string _serviceName;
	private readonly string _displayName;

	public DatabaseResetService()
		: this(DefaultServiceName, DefaultDisplayName)
	{
	}

	public DatabaseResetService(string serviceName, string displayName)
	{
		ArgumentException.ThrowIfNullOrWhiteSpace(serviceName);
		ArgumentException.ThrowIfNullOrWhiteSpace(displayName);
		_serviceName = serviceName;
		_displayName = displayName;
	}

	/// <summary>Reset the database referenced by the marker. Never throws; failures are surfaced
	/// through the returned <see cref="DatabaseResetResult"/> so the UI can render the reason.</summary>
	public async Task<DatabaseResetResult> ExecuteAsync(
		MigrationFailureMarkerPayload marker,
		string programDataDirectory,
		CancellationToken ct = default)
	{
		ArgumentNullException.ThrowIfNull(marker);
		ArgumentException.ThrowIfNullOrWhiteSpace(programDataDirectory);

		System.Text.StringBuilder log = new();
		AppendHeader(log, marker);

		string dbPath = ResolveDatabasePath(marker, programDataDirectory);
		if (string.IsNullOrWhiteSpace(dbPath))
		{
			log.AppendLine("ERROR: Could not resolve the database path from the marker.");
			return DatabaseResetResult.Fail(log.ToString());
		}
		log.AppendLine("Target database: " + dbPath);

		if (!File.Exists(dbPath))
		{
			// Nothing to back up — delete the marker so future launches do not re-prompt.
			log.AppendLine("Database file does not exist; nothing to back up. Deleting stale marker.");
			DatabaseMigrationFailureMarker.Delete(programDataDirectory);
			return await StartServiceOrExplainAsync(log, ct).ConfigureAwait(false);
		}

		ServiceControlRunner runner = new(_serviceName, _displayName);

		// 1. Stop the service so the database file is not held open. Ignore "not installed" and
		//    "already stopped" — both are acceptable pre-conditions for the backup.
		log.AppendLine("Stopping service '" + _serviceName + "' before backup...");
		ServiceOperationResult stopResult = await runner.StopAsync(ct).ConfigureAwait(false);
		log.AppendLine(stopResult.Format());

		// 2. Backup the database plus WAL/SHM sidecars using a timestamped .bak suffix.
		string suffix = "." + DateTime.UtcNow.ToString("yyyyMMdd-HHmmss", CultureInfo.InvariantCulture) + ".bak";
		string backupPath;
		try
		{
			backupPath = BackupWithSidecars(dbPath, suffix, log);
		}
		catch (Exception ex)
		{
			log.AppendLine("ERROR: Backup failed: " + ex.GetType().Name + " — " + ex.Message);
			log.AppendLine("The database has NOT been touched. Aborting recovery.");
			return new DatabaseResetResult(false, null, log.ToString());
		}

		// 3. Delete the marker so the Configurator does not re-prompt on next launch.
		DatabaseMigrationFailureMarker.Delete(programDataDirectory);
		log.AppendLine("Migration-failure marker deleted.");

		// 4. Start the service. It will detect the missing database and bootstrap a fresh schema
		//    via AuditDbInitializer.EnsureCreatedAsync + MigrateAsync on the empty file.
		DatabaseResetResult startResult = await StartServiceOrExplainAsync(log, ct).ConfigureAwait(false);
		return startResult with { BackupPath = backupPath };
	}

	private static void AppendHeader(System.Text.StringBuilder log, MigrationFailureMarkerPayload marker)
	{
		log.AppendLine("RdpAudit database reset");
		log.AppendLine("=======================");
		log.AppendLine("Started (UTC):   " + DateTime.UtcNow.ToString("O", CultureInfo.InvariantCulture));
		log.AppendLine("Marker written:  " + marker.TimestampUtc.ToString("O", CultureInfo.InvariantCulture));
		log.AppendLine("Failed migration: " + FirstOrNone(marker.PendingMigrations));
		log.AppendLine("Exception:       " + (marker.ExceptionType ?? "(unknown)") + " — " + (marker.ExceptionMessage ?? "(no message)"));
		log.AppendLine();
	}

	private static string FirstOrNone(IReadOnlyList<string> list) =>
		list.Count > 0 ? list[0] : "(none)";

	private static string ResolveDatabasePath(MigrationFailureMarkerPayload marker, string programDataDirectory)
	{
		if (!string.IsNullOrWhiteSpace(marker.DatabasePath))
		{
			return marker.DatabasePath;
		}
		return Path.Combine(programDataDirectory, "rdpaudit.db");
	}

	private static string BackupWithSidecars(string dbPath, string suffix, System.Text.StringBuilder log)
	{
		string primaryBackup = dbPath + suffix;
		File.Move(dbPath, primaryBackup);
		log.AppendLine("Renamed database file to: " + primaryBackup);

		string walPath = dbPath + "-wal";
		if (File.Exists(walPath))
		{
			string walBackup = walPath + suffix;
			try
			{
				File.Move(walPath, walBackup);
				log.AppendLine("Renamed WAL sidecar to:   " + walBackup);
			}
			catch (Exception ex)
			{
				log.AppendLine("WARNING: Could not rename WAL sidecar '" + walPath + "': " + ex.Message);
			}
		}

		string shmPath = dbPath + "-shm";
		if (File.Exists(shmPath))
		{
			string shmBackup = shmPath + suffix;
			try
			{
				File.Move(shmPath, shmBackup);
				log.AppendLine("Renamed SHM sidecar to:   " + shmBackup);
			}
			catch (Exception ex)
			{
				log.AppendLine("WARNING: Could not rename SHM sidecar '" + shmPath + "': " + ex.Message);
			}
		}

		return primaryBackup;
	}

	private async Task<DatabaseResetResult> StartServiceOrExplainAsync(
		System.Text.StringBuilder log,
		CancellationToken ct)
	{
		ServiceControlRunner runner = new(_serviceName, _displayName);
		log.AppendLine("Starting service '" + _serviceName + "'...");
		ServiceOperationResult startResult = await runner.StartAsync(ct).ConfigureAwait(false);
		log.AppendLine(startResult.Format());

		bool ok = startResult.Success;
		if (!ok)
		{
			log.AppendLine();
			log.AppendLine("The database has been backed up but the service could not be started. Start it");
			log.AppendLine("manually via services.msc or run install.ps1 to re-register the service if it is");
			log.AppendLine("no longer installed.");
		}
		else
		{
			log.AppendLine();
			log.AppendLine("Service started. A fresh database will be created on demand by the service.");
		}

		return new DatabaseResetResult(ok, null, log.ToString());
	}
}
