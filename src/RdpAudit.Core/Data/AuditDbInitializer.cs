/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 2.0.1
// File   : AuditDbInitializer.cs
// Project: RdpAudit.Core (RdpAudit.Core)
// Purpose: Applies and serializes database schema initialization before any dependent service component uses SQLite.
// Depends: AuditDbContext, IDbContextFactory<AuditDbContext>, ILogger<AuditDbInitializer>, SemaphoreSlim, Volatile, Interlocked
// Extends: Add provider-specific bootstrap steps here when introducing a new database backend or pre-flight schema validation stage.

using System.Threading;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;

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
			_logger.LogInformation("Database initialization completed successfully.");
		}
		catch (OperationCanceledException)
		{
			_logger.LogWarning("Database initialization canceled.");
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

		await db.Database.MigrateAsync(ct).ConfigureAwait(false);
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
