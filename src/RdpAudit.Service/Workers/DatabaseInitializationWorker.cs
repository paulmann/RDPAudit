/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 1.1.0
// File   : DatabaseInitializationWorker.cs
// Project: RdpAudit.Service (RdpAudit.Service)
// Purpose: Performs one-time database schema initialization and bookmark hydration as the first
//          hosted service during startup. On a fatal migration failure it triggers a graceful host
//          shutdown so the SCM records a clean stop with a distinct exit code, instead of the
//          previous behaviour that raised the exception and left the SCM cycling the service on
//          Win32 1067 every ~60 seconds without any user-facing recovery affordance.
// Depends: AuditDbInitializer, BookmarkStore, IHostApplicationLifetime, ILogger, DatabaseMigrationFailedException
// Extends: Add further startup prerequisites here that must complete before event ingestion, IPC
//          mutation, or DB-backed workers begin. When adding another recoverable failure category,
//          catch it below and StopApplication after writing a Configurator-visible marker.

using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using RdpAudit.Core.Data;
using RdpAudit.Core.Events;

namespace RdpAudit.Service.Workers;

public sealed class DatabaseInitializationWorker : IHostedService
{
	// ── Fields & DI ──────────────────────────────────────────────────────────────

	/// <summary>Distinct exit code recorded on the Application event log so the Configurator's
	/// diagnostic runner can tell "migration crash awaiting recovery" apart from ordinary crashes.
	/// Value chosen outside the 0..15 well-known SCM range and outside 1067.</summary>
	public const int MigrationFailureExitCode = 20260814;

	private readonly AuditDbInitializer _dbInitializer;
	private readonly BookmarkStore _bookmarkStore;
	private readonly IHostApplicationLifetime _lifetime;
	private readonly ILogger<DatabaseInitializationWorker> _logger;
	private int _started;

	// ── Construction ─────────────────────────────────────────────────────────────

	public DatabaseInitializationWorker(
		AuditDbInitializer dbInitializer,
		BookmarkStore bookmarkStore,
		IHostApplicationLifetime lifetime,
		ILogger<DatabaseInitializationWorker> logger)
	{
		_dbInitializer = dbInitializer ?? throw new ArgumentNullException(nameof(dbInitializer));
		_bookmarkStore = bookmarkStore ?? throw new ArgumentNullException(nameof(bookmarkStore));
		_lifetime = lifetime ?? throw new ArgumentNullException(nameof(lifetime));
		_logger = logger ?? throw new ArgumentNullException(nameof(logger));
	}

	// ── Public API ───────────────────────────────────────────────────────────────

	public async Task StartAsync(CancellationToken cancellationToken)
	{
		if (Interlocked.Exchange(ref _started, 1) != 0)
		{
			_logger.LogWarning("Database initialization worker StartAsync called more than once; duplicate call ignored.");
			return;
		}

		_logger.LogInformation("Database initialization worker starting.");

		try
		{
			await _dbInitializer.EnsureCreatedAsync(cancellationToken).ConfigureAwait(false);
			await _bookmarkStore.LoadAllAsync(cancellationToken).ConfigureAwait(false);
		}
		catch (DatabaseMigrationFailedException ex)
		{
			// The initializer already wrote the migration-failure marker. Stop the host cleanly so the
			// SCM records a Stopped state and does not enter the 1067 restart loop that historically
			// masked the underlying incompatibility. The Configurator's Diagnostics tab detects the
			// marker on next launch and offers the operator a guided database-reset flow.
			_logger.LogCritical(ex,
				"Database schema is incompatible; a recovery marker has been written for the Configurator. " +
				"Requesting graceful host shutdown (exit code {ExitCode}) so the SCM does not enter a restart loop.",
				MigrationFailureExitCode);

			Environment.ExitCode = MigrationFailureExitCode;
			_lifetime.StopApplication();
			return;
		}

		_logger.LogInformation("Database initialization worker completed.");
	}

	public Task StopAsync(CancellationToken cancellationToken)
	{
		_logger.LogInformation("Database initialization worker stopped.");
		return Task.CompletedTask;
	}
}
