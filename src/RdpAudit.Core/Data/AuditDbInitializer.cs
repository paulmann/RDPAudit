/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 2.0.3
// File   : AuditDbInitializer.cs
// Project: RdpAudit.Core (RdpAudit.Core)
// Purpose: Applies and serializes database schema initialization before any dependent service component
//          uses SQLite. On a fatal migration failure it persists a recovery marker under ProgramData so
//          the Configurator can offer the operator a guided "back up and reset database" flow instead
//          of leaving the service in a Win32 1067 restart loop with no user-facing recovery affordance.
// Depends: AuditDbContext, IDbContextFactory<AuditDbContext>, ILogger<AuditDbInitializer>, SemaphoreSlim,
//          Volatile, Interlocked, DatabaseMigrationFailureMarker, DatabaseMigrationFailedException
// Extends: Add provider-specific bootstrap steps here when introducing a new database backend or
//          pre-flight schema validation stage. When adding a new failure category that should surface
//          the reset dialog, extend the exception filter in ApplyMigrationsAsync accordingly.

using System.Data.Common;
using System.Reflection;
using System.Threading;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using RdpAudit.Core.Util;

namespace RdpAudit.Core.Data;

public sealed class AuditDbInitializer : IDisposable
{
	// ── Fields & DI ──────────────────────────────────────────────────────────────

	private readonly IDbContextFactory<AuditDbContext> _factory;
	private readonly ILogger<AuditDbInitializer> _logger;
	private readonly SemaphoreSlim _initializationGate;
	private int _isInitialized;
	private int _initializationAttempted;
	private bool _disposed;

	// ── Construction ─────────────────────────────────────────────────────────────

	public AuditDbInitializer(
		IDbContextFactory<AuditDbContext> factory,
		ILogger<AuditDbInitializer> logger)
	{
		_factory = factory ?? throw new ArgumentNullException(nameof(factory));
		_logger = logger ?? throw new ArgumentNullException(nameof(logger));
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

			await using AuditDbContext db = await _factory.CreateDbContextAsync(ct).ConfigureAwait(false);

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
			DatabaseMigrationFailureMarker.Write(marker.DatabasePath.Length > 0
				? Path.GetDirectoryName(marker.DatabasePath) ?? GetProgramDataDirectory()
				: GetProgramDataDirectory(),
				marker);

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
		};
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
