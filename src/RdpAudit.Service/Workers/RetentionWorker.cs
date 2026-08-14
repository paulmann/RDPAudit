/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 2.0.0
// File   : RetentionWorker.cs
// Project: RdpAudit.Service (RdpAudit.Service.Workers)
// Purpose: Prunes retention-governed telemetry incrementally without regressing durable IP summary counters.
// Depends: AuditDbContext, EventRetention, RdpAuditOptions, ILogger
// Extends: Add a bounded EF pruning step here whenever a new retained telemetry entity is introduced.

using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using RdpAudit.Core.Config;
using RdpAudit.Core.Data;
using RdpAudit.Core.Models;

namespace RdpAudit.Service.Workers;

/// <summary>Incrementally applies global and per-event retention policies to telemetry tables.</summary>
public sealed class RetentionWorker : BackgroundService
{
	// ── Fields & DI ──────────────────────────────────────────────────────────────

	private static readonly TimeSpan TickInterval = TimeSpan.FromMinutes(1);
	private readonly IDbContextFactory<AuditDbContext> _factory;
	private readonly IOptionsMonitor<RdpAuditOptions> _options;
	private readonly ILogger<RetentionWorker> _logger;

	// ── Construction ─────────────────────────────────────────────────────────────

	/// <summary>Creates a worker with database, configuration, and diagnostic dependencies.</summary>
	public RetentionWorker(
		IDbContextFactory<AuditDbContext> factory,
		IOptionsMonitor<RdpAuditOptions> options,
		ILogger<RetentionWorker> logger)
	{
		ArgumentNullException.ThrowIfNull(factory);
		ArgumentNullException.ThrowIfNull(options);
		ArgumentNullException.ThrowIfNull(logger);
		_factory = factory;
		_options = options;
		_logger = logger;
	}

	// ── Public API ───────────────────────────────────────────────────────────────

	/// <inheritdoc />
	protected override async Task ExecuteAsync(CancellationToken stoppingToken)
	{
		_logger.LogInformation("{Worker} starting", nameof(RetentionWorker));
		try
		{
			while (!stoppingToken.IsCancellationRequested)
			{
				try
				{
					await RunOnceAsync(stoppingToken).ConfigureAwait(false);
				}
				catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
				{
					break;
				}
				catch (Exception exception)
				{
					_logger.LogError(exception, "Retention pass failed; will retry after {Interval}", TickInterval);
				}

				await Task.Delay(TickInterval, stoppingToken).ConfigureAwait(false);
			}
		}
		catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
		{
		}
		finally
		{
			_logger.LogInformation("{Worker} stopped", nameof(RetentionWorker));
		}
	}

	// ── Core Logic ───────────────────────────────────────────────────────────────

	/// <summary>Runs one bounded retention pass. Exposed internally for worker integration tests.</summary>
	internal async Task RunOnceAsync(CancellationToken cancellationToken)
	{
		RdpAuditOptions options = _options.CurrentValue;
		int batchSize = Math.Max(1_000, options.Storage.MaintenanceBatchSize);
		int globalDefaultDays = Math.Max(1, options.Storage.EventRetentionDays);
		DateTime nowUtc = DateTime.UtcNow;

		await using AuditDbContext db = await _factory.CreateDbContextAsync(cancellationToken).ConfigureAwait(false);
		Dictionary<int, int> perEventDays = await db.EventRetentions
			.AsNoTracking()
			.ToDictionaryAsync(item => item.EventId, item => item.RetentionDays, cancellationToken)
			.ConfigureAwait(false);

		long totalPruned = await PruneRawEventsAsync(
			db,
			perEventDays,
			globalDefaultDays,
			nowUtc,
			batchSize,
			cancellationToken).ConfigureAwait(false);
		totalPruned += await PruneFactsAsync(db, options, nowUtc, batchSize, cancellationToken)
			.ConfigureAwait(false);

		if (totalPruned > 0)
		{
			_logger.LogInformation("Retention pass pruned {Rows} rows", totalPruned);
		}

		await db.Database.ExecuteSqlRawAsync("PRAGMA wal_checkpoint(PASSIVE);", cancellationToken)
			.ConfigureAwait(false);
	}

	private static async Task<long> PruneRawEventsAsync(
		AuditDbContext db,
		IReadOnlyDictionary<int, int> perEventDays,
		int globalDefaultDays,
		DateTime nowUtc,
		int batchSize,
		CancellationToken cancellationToken)
	{
		long totalPruned = 0;
		foreach (KeyValuePair<int, int> retention in perEventDays)
		{
			if (retention.Value <= 0)
			{
				continue;
			}

			DateTime cutoffUtc = nowUtc.AddDays(-retention.Value);
			totalPruned += await db.RawEvents
				.Where(item => item.EventId == retention.Key && item.TimeUtc < cutoffUtc)
				.OrderBy(item => item.TimeUtc)
				.Take(batchSize)
				.ExecuteDeleteAsync(cancellationToken)
				.ConfigureAwait(false);
		}

		int[] overrideEventIds = [.. perEventDays.Keys];
		DateTime globalCutoffUtc = nowUtc.AddDays(-globalDefaultDays);
		IQueryable<RawEvent> globallyRetained = db.RawEvents.Where(item => item.TimeUtc < globalCutoffUtc);
		if (overrideEventIds.Length > 0)
		{
			globallyRetained = globallyRetained.Where(item => !overrideEventIds.Contains(item.EventId));
		}

		totalPruned += await globallyRetained
			.OrderBy(item => item.TimeUtc)
			.Take(batchSize)
			.ExecuteDeleteAsync(cancellationToken)
			.ConfigureAwait(false);
		return totalPruned;
	}

	private static async Task<long> PruneFactsAsync(
		AuditDbContext db,
		RdpAuditOptions options,
		DateTime nowUtc,
		int batchSize,
		CancellationToken cancellationToken)
	{
		int sessionDays = Math.Max(7, options.Storage.SessionIpCorrelationRetentionDays);
		int connectionDays = Math.Max(30, options.Storage.RdpConnectionFactRetentionDays);
		int attackDays = Math.Max(14, options.Storage.AttackStatRetentionDays);
		long pruned = await db.SessionIpCorrelations
			.Where(item => item.LastSeenUtc < nowUtc.AddDays(-sessionDays))
			.OrderBy(item => item.LastSeenUtc)
			.Take(batchSize)
			.ExecuteDeleteAsync(cancellationToken)
			.ConfigureAwait(false);
		pruned += await db.RdpConnectionFacts
			.Where(item => item.LastSeenUtc < nowUtc.AddDays(-connectionDays))
			.OrderBy(item => item.LastSeenUtc)
			.Take(batchSize)
			.ExecuteDeleteAsync(cancellationToken)
			.ConfigureAwait(false);
		pruned += await db.AttackStats
			.Where(item => item.LastSeenUtc < nowUtc.AddDays(-attackDays))
			.OrderBy(item => item.LastSeenUtc)
			.Take(batchSize)
			.ExecuteDeleteAsync(cancellationToken)
			.ConfigureAwait(false);
		return pruned;
	}
}
