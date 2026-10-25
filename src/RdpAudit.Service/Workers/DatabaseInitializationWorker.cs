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
using RdpAudit.Core.Integrity;
using RdpAudit.Service.Services;

namespace RdpAudit.Service.Workers;

public sealed class DatabaseInitializationWorker : IHostedService
{
	// ── Fields & DI ──────────────────────────────────────────────────────────────

	/// <summary>Distinct exit code recorded on the Application event log so the Configurator's
	/// diagnostic runner can tell "migration crash awaiting recovery" apart from ordinary crashes.
	/// Value chosen outside the 0..15 well-known SCM range and outside 1067.</summary>
	public const int MigrationFailureExitCode = 20260814;

	/// <summary>Exit code when the initializer refused to migrate because the mandatory pre-migration
	/// snapshot could not be taken. Distinct from a migration failure: nothing was attempted, and the
	/// database is untouched at its pre-migration schema.</summary>
	public const int PreMigrationBackupFailureExitCode = 20260815;

	/// <summary>Exit code when the initializer refused to open a database whose schema is newer than
	/// these binaries, or whose migration history is damaged.</summary>
	public const int DowngradeDetectedExitCode = 20260816;

	private readonly AuditDbInitializer _dbInitializer;
	private readonly BookmarkStore _bookmarkStore;
	private readonly IHostApplicationLifetime _lifetime;
	private readonly ILogger<DatabaseInitializationWorker> _logger;
	private readonly StoreIntegrityService? _storeIntegrity;
	private int _started;

	// ── Construction ─────────────────────────────────────────────────────────────

	public DatabaseInitializationWorker(
		AuditDbInitializer dbInitializer,
		BookmarkStore bookmarkStore,
		IHostApplicationLifetime lifetime,
		ILogger<DatabaseInitializationWorker> logger,
		StoreIntegrityService? storeIntegrity = null)
	{
		_dbInitializer = dbInitializer ?? throw new ArgumentNullException(nameof(dbInitializer));
		_bookmarkStore = bookmarkStore ?? throw new ArgumentNullException(nameof(bookmarkStore));
		_lifetime = lifetime ?? throw new ArgumentNullException(nameof(lifetime));
		_logger = logger ?? throw new ArgumentNullException(nameof(logger));
		_storeIntegrity = storeIntegrity;
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
			await CompareStoreFingerprintAsync(cancellationToken).ConfigureAwait(false);
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
		catch (DatabaseInitializationBlockedException ex)
		{
			// The initializer already wrote the marker and logged the reason and its guidance. Both
			// refusal reasons stop the host with their own exit code so an operator (and the
			// Configurator's diagnostics) can tell "no migration was attempted" from "a migration
			// failed" without reading the log.
			int exitCode = ex.Reason == DatabaseInitializationBlockReason.PreMigrationBackupFailed
				? PreMigrationBackupFailureExitCode
				: DowngradeDetectedExitCode;

			_logger.LogCritical(ex,
				"Database initialization refused ({Reason}); a recovery marker has been written for the Configurator. " +
				"Requesting graceful host shutdown (exit code {ExitCode}). Guidance: {Guidance}",
				ex.Reason,
				exitCode,
				ex.Marker.Guidance ?? ex.Message);

			Environment.ExitCode = exitCode;
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

	/// <summary>Compares the store against the durable fingerprint taken at the last clean shutdown, so a
	/// store that was modified while the service was not running is reported instead of silently trusted. It
	/// runs HERE - after migrations and after the bookmarks are hydrated - because the applied migration
	/// history is part of what is compared, and a legitimate upgrade appends to it.
	/// <para>
	/// An anomaly is never fatal: the service starts, reports and keeps ingesting. Refusing to start because
	/// a store looks tampered with would turn evidence of tampering into an outage, and the observation is
	/// already durable (OperationLog row plus a marker file the Configurator reads).
	/// </para>
	/// </summary>
	private async Task CompareStoreFingerprintAsync(CancellationToken cancellationToken)
	{
		if (_storeIntegrity is null)
		{
			// Hosts that do not register the integrity service (a trimmed test host) simply have no
			// fingerprint comparison; that absence is not an error.
			return;
		}

		try
		{
			StoreIntegrityReport report = await _storeIntegrity
				.CompareOnStartupAsync(cancellationToken)
				.ConfigureAwait(false);
			if (report.HasAnomalies)
			{
				_logger.LogWarning(
					"Store-integrity check at start-up found {Count} observation(s): {Message}",
					report.Anomalies.Count,
					report.Message);
			}
		}
		catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
		{
			throw;
		}
		catch (Exception ex)
		{
			// The comparison is an observation; failing it must not block start-up.
			_logger.LogWarning(ex, "The store-integrity comparison at start-up could not be completed");
		}
	}
}
