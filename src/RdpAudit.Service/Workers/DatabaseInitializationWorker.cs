/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 1.0.1
// File   : DatabaseInitializationWorker.cs
// Project: RdpAudit.Service (RdpAudit.Service)
// Purpose: Performs one-time database schema initialization and bookmark hydration as the first hosted service during startup.
// Depends: AuditDbInitializer, BookmarkStore, ILogger<DatabaseInitializationWorker>, IHostedService, CancellationToken
// Extends: Add further startup prerequisites here that must complete before event ingestion, IPC mutation, or DB-backed workers begin.

using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using RdpAudit.Core.Data;
using RdpAudit.Core.Events;

namespace RdpAudit.Service.Workers;

public sealed class DatabaseInitializationWorker : IHostedService
{
	// ── Fields & DI ──────────────────────────────────────────────────────────────

	private readonly AuditDbInitializer _dbInitializer;
	private readonly BookmarkStore _bookmarkStore;
	private readonly ILogger<DatabaseInitializationWorker> _logger;
	private int _started;

	// ── Construction ─────────────────────────────────────────────────────────────

	public DatabaseInitializationWorker(
		AuditDbInitializer dbInitializer,
		BookmarkStore bookmarkStore,
		ILogger<DatabaseInitializationWorker> logger)
	{
		_dbInitializer = dbInitializer ?? throw new ArgumentNullException(nameof(dbInitializer));
		_bookmarkStore = bookmarkStore ?? throw new ArgumentNullException(nameof(bookmarkStore));
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

		await _dbInitializer.EnsureCreatedAsync(cancellationToken).ConfigureAwait(false);
		await _bookmarkStore.LoadAllAsync(cancellationToken).ConfigureAwait(false);

		_logger.LogInformation("Database initialization worker completed.");
	}

	public Task StopAsync(CancellationToken cancellationToken)
	{
		_logger.LogInformation("Database initialization worker stopped.");
		return Task.CompletedTask;
	}
}
