/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 2.0.4
// File   : AuditDbInitializer.cs
// Project: RdpAudit.Core (RdpAudit.Core)
// Purpose: Applies and serializes database schema initialization before any dependent service component
//          uses SQLite. Three stages guard the store before it is touched:
//          (1) downgrade guard - a database whose applied migrations are newer than the running binaries
//              is never opened silently; the initializer writes a marker and refuses to start;
//          (2) mandatory pre-migration snapshot - when migrations are pending, one snapshot is taken
//              through IPreMigrationBackupProvider before MigrateAsync; if it cannot be taken, no
//              migration is attempted at all, because migrating without a rollback point is exactly the
//              failure this protects against. One snapshot per migration session, not one per migration;
//          (3) migration, with a recovery marker written on a fatal failure so the Configurator can
//              offer the operator a guided "back up and reset database" flow instead of leaving the
//              service in a Win32 1067 restart loop with no user-facing recovery affordance.
// Depends: AuditDbContext, IDbContextFactory<AuditDbContext>, ILogger<AuditDbInitializer>, SemaphoreSlim,
//          Volatile, Interlocked, DatabaseMigrationFailureMarker, IPreMigrationBackupProvider,
//          SchemaCompatibility, DatabaseMigrationFailedException, DatabaseInitializationBlockedException
// Extends: Add provider-specific bootstrap steps here when introducing a new database backend or
//          pre-flight schema validation stage. When adding a new failure category that should surface
//          the reset dialog, extend the exception filter in ApplyMigrationsAsync accordingly and give
//          the hosted worker its exit code.

using System.Data.Common;
using System.Globalization;
using System.Reflection;
using System.Threading;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using RdpAudit.Core.Backup;
using RdpAudit.Core.Config;
using RdpAudit.Core.Util;

namespace RdpAudit.Core.Data;

public sealed class AuditDbInitializer : IDisposable
{
	// ── Fields & DI ──────────────────────────────────────────────────────────────

	private readonly IDbContextFactory<AuditDbContext> _factory;
	private readonly ILogger<AuditDbInitializer> _logger;
	private readonly IPreMigrationBackupProvider? _preMigrationBackup;
	private readonly RdpAuditOptions? _options;
	private readonly SemaphoreSlim _initializationGate;
	private int _isInitialized;
	private int _initializationAttempted;
	private bool _disposed;

	// ── Construction ─────────────────────────────────────────────────────────────

	/// <summary>
	/// Creates the initializer. <paramref name="preMigrationBackup"/> is optional so a host that owns
	/// no snapshot engine (and every unit test that constructs the initializer directly) keeps working;
	/// when it is absent or reports <see cref="IPreMigrationBackupProvider.IsEnabled"/> false, the
	/// initializer migrates and logs that it did so without a pre-migration snapshot.
	/// </summary>
	public AuditDbInitializer(
		IDbContextFactory<AuditDbContext> factory,
		ILogger<AuditDbInitializer> logger,
		IPreMigrationBackupProvider? preMigrationBackup = null,
		RdpAuditOptions? options = null)
	{
		_factory = factory ?? throw new ArgumentNullException(nameof(factory));
		_logger = logger ?? throw new ArgumentNullException(nameof(logger));
		_preMigrationBackup = preMigrationBackup;
		_options = options;
		_initializationGate = new SemaphoreSlim(1, 1);
	}

	// ── Public API ───────────────────────────────────────────────────────────────

	public async Task EnsureCreatedAsync(CancellationToken ct = default)
	{
		ObjectDisposedException.ThrowIf(_disposed, this);

		if (Volatile.Read(ref _isInitialized) == 1)
		{
			return;
		}

		await _initializationGate.WaitAsync(ct).ConfigureAwait(false);
		try
		{
			if (Volatile.Read(ref _isInitialized) == 1)
			{
				return;
			}

			bool isFirstAttempt = Interlocked.CompareExchange(ref _initializationAttempted, 1, 0) == 0;
			if (isFirstAttempt)
			{
				_logger.LogInformation("Database initialization started.");
			}
			else
			{
				_logger.LogWarning("Database initialization re-entered before completion; continuing under serialized gate.");
			}

			// Encryption-at-rest guard (defence in depth). Program.cs already asserted this before the host
			// was built, but the initializer is the first component that would OPEN the store, so the refusal
			// is repeated here: a host that wires the initializer without going through Main (tests, an
			// embedding) must not be able to open a store under an encryption claim this build cannot honour.
			StorageEncryptionGuard.AssertSupported(_options?.Storage.Encryption);

			await using AuditDbContext db = await _factory.CreateDbContextAsync(ct).ConfigureAwait(false);

			// Downgrade guard. Runs before anything else touches the schema, including the
			// no-migrations path: an older binary opening a newer store is the failure that must never be
			// silent, and it is not something a migration could repair.
			await GuardAgainstSchemaDowngradeAsync(db, ct).ConfigureAwait(false);

			if (HasDefinedMigrations(db))
			{
				await ApplyMigrationsAsync(db, ct).ConfigureAwait(false);
			}
			else
			{
				await EnsureCreatedWithoutMigrationsAsync(db, ct).ConfigureAwait(false);
			}

			Volatile.Write(ref _isInitialized, 1);

			// Recovery succeeded: any stale marker from a previous failed boot is now obsolete and must
			// be cleared so the Configurator does not show a spurious "database is incompatible" prompt
			// after the operator upgraded the service binaries.
			ClearStaleMarker(db);

			_logger.LogInformation("Database initialization completed successfully.");
		}
		catch (OperationCanceledException)
		{
			_logger.LogWarning("Database initialization canceled.");
			throw;
		}
		catch (DatabaseMigrationFailedException)
		{
			// Already logged and marker already written by ApplyMigrationsAsync. Rethrow so the hosted
			// worker can decide how to stop the process without SCM feeding a Win32 1067 restart loop.
			throw;
		}
		catch (DatabaseInitializationBlockedException)
		{
			// Already logged and marker already written by the guard that refused. Same contract as
			// above: the worker stops the host with the exit code for this reason.
			throw;
		}
		catch (Exception ex)
		{
			_logger.LogCritical(ex, "Database initialization failed.");
			throw;
		}
		finally
		{
			_initializationGate.Release();
		}
	}

	// ── Core Logic ───────────────────────────────────────────────────────────────

	private async Task ApplyMigrationsAsync(AuditDbContext db, CancellationToken ct)
	{
		List<string> pendingMigrations = await GetPendingMigrationNamesAsync(db, ct).ConfigureAwait(false);
		if (pendingMigrations.Count == 0)
		{
			_logger.LogInformation("Schema up-to-date; no pending migrations.");
			return;
		}

		_logger.LogInformation(
			"Applying {Count} pending EF migrations: {Migrations}",
			pendingMigrations.Count,
			string.Join(", ", pendingMigrations));

		// One snapshot per migration session, taken before the first migration is applied. A snapshot
		// per migration would multiply the disk cost for no additional recovery value: the operator
		// restores the pre-upgrade state, not an intermediate one.
		string? preMigrationSnapshot = await TakePreMigrationSnapshotAsync(db, pendingMigrations, ct).ConfigureAwait(false);
		if (preMigrationSnapshot is not null)
		{
			_logger.LogInformation(
				"Pre-migration snapshot taken at {SnapshotDirectory}; applying {Count} pending migration(s).",
				preMigrationSnapshot,
				pendingMigrations.Count);
		}

		try
		{
			await db.Database.MigrateAsync(ct).ConfigureAwait(false);
		}
		catch (OperationCanceledException)
		{
			throw;
		}
		catch (Exception ex) when (IsMigrationFailure(ex))
		{
			// Persist a recovery marker so the Configurator can surface the "back up and reset
			// database" prompt on next launch. This path is intentionally taken only for genuine
			// schema-application failures (SQLite constraint / bad column / read-only DB) — not for
			// transient IO or cancellation, which should keep the SCM restart semantics intact.
			MigrationFailureMarkerPayload marker = BuildMarker(db, pendingMigrations, ex);
			DatabaseMigrationFailureMarker.Write(ResolveMarkerDirectory(marker.DatabasePath), marker);

			_logger.LogCritical(ex,
				"Database migration failed on {FailedMigration} — recovery marker written to ProgramData. " +
				"The service will stop; the Configurator can back up the incompatible database and let " +
				"the service create a fresh one on next start.",
				marker.PendingMigrations.Count > 0 ? marker.PendingMigrations[0] : "(unknown)");

			throw new DatabaseMigrationFailedException(
				"Database schema migration failed; recovery marker written for the Configurator.",
				ex,
				marker);
		}
	}

	private async Task EnsureCreatedWithoutMigrationsAsync(AuditDbContext db, CancellationToken ct)
	{
		bool created = await db.Database.EnsureCreatedAsync(ct).ConfigureAwait(false);
		_logger.LogInformation(
			"No migrations defined; EnsureCreatedAsync executed (created={Created})",
			created);
	}

	// ── Downgrade guard ──────────────────────────────────────────────────────────

	/// <summary>
	/// Refuses to open a database whose applied migrations are newer than the running binaries. The
	/// comparison itself is the pure <see cref="SchemaCompatibility.Evaluate"/>; this method owns only
	/// the I/O around it. An unreadable history is logged and skipped rather than treated as a failure:
	/// EF Core reports a missing history table as "no applied migrations", and anything that genuinely
	/// cannot be read will surface as a real error when the schema is used.
	/// </summary>
	private async Task GuardAgainstSchemaDowngradeAsync(AuditDbContext db, CancellationToken ct)
	{
		List<string> applied = [];
		IReadOnlyList<string>? appliedHistory;
		try
		{
			IEnumerable<string> fromDatabase = await db.Database.GetAppliedMigrationsAsync(ct).ConfigureAwait(false);
			foreach (string migration in fromDatabase)
			{
				applied.Add(migration);
			}

			appliedHistory = applied;
		}
		catch (OperationCanceledException)
		{
			throw;
		}
		catch (Exception ex)
		{
			_logger.LogWarning(
				ex,
				"The applied migration history could not be read; the schema downgrade guard is skipped for this start. " +
				"Any real schema problem will surface when the database is first used.");
			return;
		}

		string databasePath = ResolveDatabasePath(db);
		SchemaCompatibilityResult compatibility = SchemaCompatibility.Evaluate(appliedHistory, [.. db.Database.GetMigrations()], databasePath);
		switch (compatibility.Verdict)
		{
			case SchemaCompatibilityVerdict.Compatible:
				_logger.LogInformation(
					"Schema compatibility check passed for {DatabasePath}: {AppliedCount} applied migration(s), all known to this build.",
					databasePath,
					compatibility.AppliedMigrations.Count);
				return;

			case SchemaCompatibilityVerdict.HistoryUnavailable:
				_logger.LogWarning(
					"Schema compatibility could not be proven for {DatabasePath}: {Message}",
					databasePath,
					compatibility.Message);
				return;

			case SchemaCompatibilityVerdict.DatabaseAheadOfBinaries:
				throw RefuseInitialization(
					db,
					DatabaseInitializationBlockReason.SchemaAheadOfBinaries,
					MigrationFailureKind.SchemaAheadOfBinaries,
					compatibility.Message + " Guidance: install the RdpAudit build that created this database. Downgrading the binaries while keeping the upgraded store is not supported. If you must run this build, restore the snapshot taken before the upgrade (Backups\\<timestamp>\\db\\rdpaudit.db) or let the Configurator back the database up and start from a fresh one.",
					compatibility.UnknownAppliedMigrations,
					expectedBackupDirectory: null);

			case SchemaCompatibilityVerdict.HistoryInvalid:
				throw RefuseInitialization(
					db,
					DatabaseInitializationBlockReason.MigrationHistoryInvalid,
					MigrationFailureKind.MigrationHistoryInvalid,
					compatibility.Message + " Guidance: the store will not be opened on a damaged migration history. Restore a database snapshot, or let the Configurator back the database up and start from a fresh one.",
					unknownAppliedMigrations: [],
					expectedBackupDirectory: null);

			default:
				return;
		}
	}

	/// <summary>
	/// Writes the recovery marker and builds the exception for a refusal that happens before any
	/// migration is attempted. Every refusal reaches the operator with the same shape: what happened,
	/// which path is involved, and what to do next.
	/// </summary>
	private DatabaseInitializationBlockedException RefuseInitialization(
		AuditDbContext db,
		DatabaseInitializationBlockReason reason,
		string failureKind,
		string message,
		IReadOnlyList<string> unknownAppliedMigrations,
		string? expectedBackupDirectory)
	{
		string databasePath = ResolveDatabasePath(db);
		MigrationFailureMarkerPayload marker = new()
		{
			Version = 1,
			TimestampUtc = DateTime.UtcNow,
			DatabasePath = databasePath,
			PendingMigrations = [],
			ExceptionType = typeof(DatabaseInitializationBlockedException).FullName,
			ExceptionMessage = message,
			ServiceVersion = ResolveServiceVersion(),
			FailureKind = failureKind,
			ExpectedBackupDirectory = expectedBackupDirectory,
			UnknownAppliedMigrations = unknownAppliedMigrations,
			Guidance = message,
		};

		DatabaseMigrationFailureMarker.Write(ResolveMarkerDirectory(databasePath), marker);
		_logger.LogCritical(
			"Database initialization refused ({FailureKind}) for {DatabasePath}: {Message}",
			failureKind,
			databasePath,
			message);

		return new DatabaseInitializationBlockedException(message, reason, marker);
	}

	// ── Mandatory pre-migration snapshot ─────────────────────────────────────────

	/// <summary>
	/// Takes the one snapshot that must exist before any pending migration is applied. Returns the
	/// snapshot directory on success, and null when this host migrates without a snapshot - either
	/// because no snapshot engine is registered or because the operator switched
	/// <c>Backup.PreMigrationBackupEnabled</c> off. Both cases are logged as warnings, never silent.
	/// A configured snapshot that cannot be taken blocks the migration: it writes the recovery marker
	/// and throws, so the store stays in its pre-migration state and the operator can fix the cause.
	/// </summary>
	private async Task<string?> TakePreMigrationSnapshotAsync(
		AuditDbContext db,
		List<string> pendingMigrations,
		CancellationToken ct)
	{
		if (_preMigrationBackup is null)
		{
			_logger.LogWarning(
				"This host registered no pre-migration snapshot provider, so the {Count} pending migration(s) will be applied WITHOUT a rollback snapshot.",
				pendingMigrations.Count);
			return null;
		}

		if (!_preMigrationBackup.IsEnabled)
		{
			_logger.LogWarning(
				"Backup.PreMigrationBackupEnabled is false, so the {Count} pending migration(s) will be applied WITHOUT a rollback snapshot.",
				pendingMigrations.Count);
			return null;
		}

		string databasePath = ResolveDatabasePath(db);
		if (!File.Exists(databasePath))
		{
			// Nothing to roll back to: a store that was never created holds no evidence, so requiring a
			// snapshot of it would block the first start of a fresh installation for no recovery value.
			_logger.LogInformation(
				"No database file exists yet at {DatabasePath}; the {Count} pending migration(s) will create it without a pre-migration snapshot.",
				databasePath,
				pendingMigrations.Count);
			return null;
		}

		PreMigrationBackupResult backup;
		try
		{
			backup = await _preMigrationBackup.CreateAsync(databasePath, ct).ConfigureAwait(false);
		}
		catch (OperationCanceledException)
		{
			throw;
		}
		catch (Exception ex)
		{
			backup = PreMigrationBackupResult.Failed(_preMigrationBackup.ExpectedDirectory, ex.GetType().Name + ": " + ex.Message);
		}

		if (backup.Success && backup.SnapshotDirectory is not null)
		{
			return backup.SnapshotDirectory;
		}

		string expectedDirectory = string.IsNullOrWhiteSpace(backup.ExpectedDirectory)
			? _preMigrationBackup.ExpectedDirectory
			: backup.ExpectedDirectory;
		string reason = backup.Error ?? "the snapshot engine reported no reason.";
		string message = string.Format(
			CultureInfo.InvariantCulture,
			"Database schema migration was NOT started: the mandatory pre-migration snapshot could not be taken. Reason: {0} The snapshot was expected in '{1}'. The database at '{2}' is unchanged and still at its pre-migration schema, so no migration ran and no data was touched. Guidance: free space on the destination volume (or point RdpAudit:Storage:Backup:BackupDirectory at a writable location with room for a full database copy), then start the service again. To migrate without a rollback snapshot - only when the volume genuinely cannot hold a second copy - set RdpAudit:Storage:Backup:PreMigrationBackupEnabled to false in appsettings.json and restart.",
			reason,
			expectedDirectory,
			databasePath);

		throw RefuseInitialization(
			db,
			DatabaseInitializationBlockReason.PreMigrationBackupFailed,
			MigrationFailureKind.PreMigrationBackupFailed,
			message,
			unknownAppliedMigrations: [],
			expectedBackupDirectory: expectedDirectory);
	}

	// ── Error Handling & Retry ───────────────────────────────────────────────────

	private static bool HasDefinedMigrations(AuditDbContext db)
	{
		foreach (string _ in db.Database.GetMigrations())
		{
			return true;
		}

		return false;
	}

	private static async Task<List<string>> GetPendingMigrationNamesAsync(AuditDbContext db, CancellationToken ct)
	{
		IEnumerable<string> pending = await db.Database.GetPendingMigrationsAsync(ct).ConfigureAwait(false);
		List<string> names = new List<string>();

		foreach (string migrationName in pending)
		{
			names.Add(migrationName);
		}

		return names;
	}

	/// <summary>Only classify true schema-application failures as recoverable via database reset.
	/// Transient IO, cancellation, timeout, and disk-full errors are excluded — they should be retried
	/// by the SCM restart policy, not resolved by wiping the database.</summary>
	private static bool IsMigrationFailure(Exception ex)
	{
		if (ex is DbException)
		{
			return true;
		}

		// Microsoft.EntityFrameworkCore wraps some provider errors in InvalidOperationException with
		// the underlying DbException as InnerException. Unwrap one level to catch that shape.
		if (ex is InvalidOperationException && ex.InnerException is DbException)
		{
			return true;
		}

		// Sqlite provider throws Microsoft.Data.Sqlite.SqliteException which derives from DbException;
		// the check above already covers it. AggregateException guard for async pipeline unwrap.
		if (ex is AggregateException agg)
		{
			foreach (Exception inner in agg.InnerExceptions)
			{
				if (IsMigrationFailure(inner))
				{
					return true;
				}
			}
		}

		return false;
	}

	private static MigrationFailureMarkerPayload BuildMarker(
		AuditDbContext db,
		List<string> pendingMigrations,
		Exception ex)
	{
		string dbPath = ResolveDatabasePath(db);
		Exception root = UnwrapRoot(ex);

		return new MigrationFailureMarkerPayload
		{
			Version           = 1,
			TimestampUtc      = DateTime.UtcNow,
			DatabasePath      = dbPath,
			PendingMigrations = pendingMigrations.ToArray(),
			ExceptionType     = root.GetType().FullName,
			ExceptionMessage  = root.Message,
			ExceptionStack    = ex.ToString(),
			FailedSql         = TryExtractFailedSql(ex),
			ServiceVersion    = ResolveServiceVersion(),
			FailureKind       = MigrationFailureKind.MigrationFailed,
			Guidance          = "Guidance: the database is at its pre-migration schema because the migration that failed did not complete. A snapshot taken before this migration exists in the Backups folder when Backup.PreMigrationBackupEnabled was on; restore it, or let the Configurator back the database up and start from a fresh one. Inspect the marker's exceptionMessage and the service log for the failing statement.",
		};
	}

	/// <summary>Directory the recovery marker lives in. It sits next to the database unless the database
	/// path cannot be resolved, in which case it falls back to the ProgramData default.</summary>
	private static string ResolveMarkerDirectory(string databasePath)
	{
		if (string.IsNullOrWhiteSpace(databasePath))
		{
			return GetProgramDataDirectory();
		}

		return Path.GetDirectoryName(databasePath) ?? GetProgramDataDirectory();
	}

	private static Exception UnwrapRoot(Exception ex)
	{
		Exception current = ex;
		while (current.InnerException is not null)
		{
			current = current.InnerException;
		}
		return current;
	}

	/// <summary>Best-effort extraction of the last executed SQL from the exception chain. EF Core does
	/// not expose the failed command on the exception itself, so we fall back to null when the SQL is
	/// not present in the message — the log already captured it via Microsoft.EntityFrameworkCore.Database.Command.</summary>
	private static string? TryExtractFailedSql(Exception ex)
	{
		Exception? cursor = ex;
		while (cursor is not null)
		{
			if (cursor.Data.Contains("CommandText") && cursor.Data["CommandText"] is string commandText && commandText.Length > 0)
			{
				return commandText;
			}
			cursor = cursor.InnerException;
		}
		return null;
	}

	private static string ResolveDatabasePath(AuditDbContext db)
	{
		try
		{
			DbConnection connection = db.Database.GetDbConnection();
			string? source = connection.DataSource;
			if (!string.IsNullOrWhiteSpace(source))
			{
				return Path.GetFullPath(source);
			}
		}
		catch
		{
			// Ignore — fall through to default.
		}

		return RdpAuditPaths.Default.DatabasePath;
	}

	private static string GetProgramDataDirectory()
	{
		return RdpAuditPaths.Default.ProgramDataDirectory;
	}

	private static string? ResolveServiceVersion()
	{
		try
		{
			return typeof(AuditDbInitializer).Assembly
				.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion
				?? typeof(AuditDbInitializer).Assembly.GetName().Version?.ToString();
		}
		catch
		{
			return null;
		}
	}

	private static void ClearStaleMarker(AuditDbContext db)
	{
		try
		{
			string dbPath = ResolveDatabasePath(db);
			string programData = dbPath.Length > 0
				? Path.GetDirectoryName(dbPath) ?? GetProgramDataDirectory()
				: GetProgramDataDirectory();

			if (OperatingSystem.IsWindows())
			{
				DatabaseMigrationFailureMarker.Delete(programData);
			}
		}
		catch
		{
			// Ignore — a stale marker is not fatal, only surfaces a spurious dialog.
		}
	}

	// ── Disposal & Pool Returns ──────────────────────────────────────────────────

	public void Dispose()
	{
		if (_disposed)
		{
			return;
		}

		_initializationGate.Dispose();
		_disposed = true;
	}
}
