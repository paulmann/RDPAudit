// File:    src/RdpAudit.Service/Workers/MaintenanceWorker.cs
// Module:  RdpAudit.Service.Workers
// Purpose: Daily housekeeping — retention pruning across RawEvents, Alerts, AbuseReports,
//          inactive ActiveBlocks and stale AttackStats; bounded incremental_vacuum; ThreatScore
//          decay; log rotation. All pruning is batched, cancellable, and tolerates SQLite busy
//          (codes 5/6) errors with exponential backoff so the writer lock is never held for long.
// Extends: Microsoft.Extensions.Hosting.BackgroundService
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using RdpAudit.Core.Config;
using RdpAudit.Core.Data;
using RdpAudit.Core.Models;
using RdpAudit.Core.Util;

namespace RdpAudit.Service.Workers;

/// <summary>Daily housekeeping — retention, compaction, ThreatScore decay, log rotation.</summary>
/// <remarks>
/// Retention pruning is bounded by <see cref="StorageOptions.MaintenanceBatchSize"/> per table per
/// pass to keep the SQLite writer lock short on very large databases. Pruning honours the
/// <see cref="CancellationToken"/> passed to <see cref="ExecuteAsync"/> and retries transient
/// SQLITE_BUSY / SQLITE_LOCKED errors using a short exponential backoff.
/// </remarks>
public sealed class MaintenanceWorker : BackgroundService
{
	private static readonly TimeSpan Period = TimeSpan.FromHours(24);

	private static readonly TimeSpan[] BusyBackoffs =
	{
		TimeSpan.FromMilliseconds(100),
		TimeSpan.FromMilliseconds(200),
		TimeSpan.FromMilliseconds(400),
		TimeSpan.FromMilliseconds(800),
		TimeSpan.FromMilliseconds(2000),
	};

	private readonly IDbContextFactory<AuditDbContext> _factory;
	private readonly IOptionsMonitor<RdpAuditOptions> _options;
	private readonly ILogger<MaintenanceWorker> _logger;

	public MaintenanceWorker(
		IDbContextFactory<AuditDbContext> factory,
		IOptionsMonitor<RdpAuditOptions> options,
		ILogger<MaintenanceWorker> logger)
	{
		_factory = factory;
		_options = options;
		_logger = logger;
	}

	protected override async Task ExecuteAsync(CancellationToken stoppingToken)
	{
		_logger.LogInformation("{Worker} starting", nameof(MaintenanceWorker));
		try
		{
			await Task.Delay(TimeSpan.FromMinutes(1), stoppingToken).ConfigureAwait(false);
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
				catch (Exception ex)
				{
					_logger.LogError(ex, "Maintenance iteration failed");
				}

				await Task.Delay(Period, stoppingToken).ConfigureAwait(false);
			}
		}
		catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
		{
		}
		finally
		{
			_logger.LogInformation("{Worker} stopped", nameof(MaintenanceWorker));
		}
	}

	/// <summary>Runs a single maintenance pass (retention pruning, vacuum, decay, log rotation).
	/// Exposed for tests; production callers use <see cref="ExecuteAsync"/>.</summary>
	internal async Task RunOnceAsync(CancellationToken ct)
	{
		RdpAuditOptions current = _options.CurrentValue;
		StorageOptions storage = current.Storage;
		LogsOptions logs = current.Logs;
		int batch = Math.Max(1000, storage.MaintenanceBatchSize);

		// Resolve retention cutoffs with safe minima — operators can lower these intentionally,
		// but never below the floors documented in StorageOptions.
		DateTime utcNow = DateTime.UtcNow;
		DateTime eventCutoff = utcNow.AddDays(-Math.Max(7, storage.EventRetentionDays));
		DateTime alertCutoff = utcNow.AddDays(-Math.Max(30, storage.AlertRetentionDays));
		DateTime abuseCutoff = utcNow.AddDays(-Math.Max(30, storage.AbuseReportRetentionDays));
		DateTime activeBlockCutoff = utcNow.AddDays(-Math.Max(7, storage.ActiveBlockRetentionDays));
		DateTime attackStatCutoff = utcNow.AddDays(-Math.Max(14, storage.AttackStatRetentionDays));
		DateTime correlationCutoff = utcNow.AddDays(-Math.Max(7, storage.SessionIpCorrelationRetentionDays));
		DateTime connectionFactCutoff = utcNow.AddDays(-Math.Max(30, storage.RdpConnectionFactRetentionDays));

		int eventsDeleted = await PruneBatchedAsync(
			db => db.RawEvents.Where(e => e.TimeUtc < eventCutoff),
			batch,
			ct).ConfigureAwait(false);

		int alertsDeleted = await PruneBatchedAsync(
			db => db.Alerts.Where(a => a.TimeUtc < alertCutoff),
			batch,
			ct).ConfigureAwait(false);

		int abuseReportsDeleted = await PruneBatchedAsync(
			db => db.AbuseReports.Where(a => a.ReportedUtc < abuseCutoff),
			batch,
			ct).ConfigureAwait(false);

		// ActiveBlocks: only remove rows that are no longer load-bearing. A row is eligible if it
		// is Removed, or if it has an ExpiresUtc that is already older than the retention cutoff.
		// Active and Pending rows are NEVER deleted by retention — the expiration worker is the
		// authoritative path for tearing them down.
		int activeBlocksDeleted = await PruneBatchedAsync(
			db => db.ActiveBlocks.Where(b =>
				b.Status == ActiveBlockStatus.Removed
				|| (b.ExpiresUtc != null && b.ExpiresUtc < activeBlockCutoff)),
			batch,
			ct).ConfigureAwait(false);

		int attackStatsDeleted = await PruneBatchedAsync(
			db => db.AttackStats.Where(s => s.LastSeenUtc < attackStatCutoff),
			batch,
			ct).ConfigureAwait(false);

		int correlationsDeleted = await PruneBatchedAsync(
			db => db.SessionIpCorrelations.Where(c => c.LastSeenUtc < correlationCutoff),
			batch,
			ct).ConfigureAwait(false);

		int connectionFactsDeleted = await PruneBatchedAsync(
			db => db.RdpConnectionFacts.Where(f => f.LastSeenUtc < connectionFactCutoff),
			batch,
			ct).ConfigureAwait(false);

		// v1.3.3: operation-log retention. Rows older than the configured (clamped) retention depth
		// are deleted in bounded batches so the operator-facing audit trail stays responsive on the
		// Logs tab and the table never grows without bound on a long-lived host.
		DateTime operationLogCutoff = utcNow.AddDays(-logs.ResolveRetentionDays());
		int operationLogsDeleted = await PruneBatchedAsync(
			db => db.OperationLogs.Where(o => o.TimeUtc < operationLogCutoff),
			batch,
			ct).ConfigureAwait(false);

		await using (AuditDbContext db = await _factory.CreateDbContextAsync(ct).ConfigureAwait(false))
		{
			// Bounded incremental_vacuum: at most 5000 free pages per pass to avoid
			// holding the writer lock for an unbounded amount of time on huge databases.
			await WithBusyRetryAsync(
				token => db.Database.ExecuteSqlRawAsync("PRAGMA incremental_vacuum(5000);", token),
				ct).ConfigureAwait(false);

			List<Address> addresses = await db.Addresses.ToListAsync(ct).ConfigureAwait(false);
			foreach (Address addr in addresses)
			{
				addr.ThreatScore *= 0.95;
			}

			await WithBusyRetryAsync(token => db.SaveChangesAsync(token), ct).ConfigureAwait(false);
		}

		_logger.LogInformation(
			"Maintenance complete: events={Events} alerts={Alerts} abuseReports={Abuse} activeBlocks={Blocks} attackStats={Stats} correlations={Correlations} connectionFacts={ConnectionFacts} operationLogs={OperationLogs}",
			eventsDeleted,
			alertsDeleted,
			abuseReportsDeleted,
			activeBlocksDeleted,
			attackStatsDeleted,
			correlationsDeleted,
			connectionFactsDeleted,
			operationLogsDeleted);

		// Stage A: capture a daily DB-size snapshot so the Overview tab can report growth windows
		// without hot polling. Snapshots older than 45 days are pruned so the DbProps table never
		// grows unbounded.
		await CaptureDbSizeSnapshotAsync(storage, utcNow, ct).ConfigureAwait(false);

		PruneLogFiles(storage);
	}

	/// <summary>Writes the day's DB-size snapshot to <c>DbProps</c> (idempotent per UTC day) and
	/// prunes snapshots older than <see cref="DbSizeGrowthCalculator.MonthLookbackMaxDays"/>.</summary>
	internal async Task CaptureDbSizeSnapshotAsync(StorageOptions storage, DateTime nowUtc, CancellationToken ct)
	{
		long sizeBytes;
		try
		{
			FileInfo fi = new(storage.ResolveDatabasePath());
			if (!fi.Exists)
			{
				return;
			}

			sizeBytes = fi.Length;
		}
		catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or System.Security.SecurityException)
		{
			_logger.LogDebug(ex, "DB size snapshot skipped — file size lookup failed");
			return;
		}

		try
		{
			await using AuditDbContext db = await _factory.CreateDbContextAsync(ct).ConfigureAwait(false);
			string key = DbSizeGrowthCalculator.GetDbPropKey(nowUtc);
			DbProp? existing = await db.DbProps.FirstOrDefaultAsync(p => p.Key == key, ct).ConfigureAwait(false);
			string encoded = DbSizeGrowthCalculator.Encode(new DbSizeSnapshot(nowUtc, sizeBytes));
			if (existing is null)
			{
				db.DbProps.Add(new DbProp { Key = key, Value = encoded, UpdatedUtc = nowUtc });
			}
			else
			{
				existing.Value = encoded;
				existing.UpdatedUtc = nowUtc;
			}

			// Prune snapshots beyond the month window so DbProps stays bounded.
			DateTime pruneCutoff = nowUtc.AddDays(-DbSizeGrowthCalculator.MonthLookbackMaxDays);
			List<DbProp> stale = await db.DbProps
				.Where(p => p.Key.StartsWith("OverviewDbSize:") && p.UpdatedUtc < pruneCutoff)
				.ToListAsync(ct).ConfigureAwait(false);
			if (stale.Count > 0)
			{
				db.DbProps.RemoveRange(stale);
			}

			await WithBusyRetryAsync(token => db.SaveChangesAsync(token), ct).ConfigureAwait(false);
		}
		catch (OperationCanceledException) when (ct.IsCancellationRequested)
		{
			throw;
		}
		catch (Exception ex)
		{
			_logger.LogWarning(ex, "DB size snapshot capture failed");
		}
	}

	/// <summary>Deletes rows matching <paramref name="filter"/> in bounded batches so the SQLite
	/// writer lock is released between batches. Returns the total number of rows deleted.</summary>
	private async Task<int> PruneBatchedAsync<T>(
		Func<AuditDbContext, IQueryable<T>> filter,
		int batchSize,
		CancellationToken ct) where T : class
	{
		int totalDeleted = 0;
		while (!ct.IsCancellationRequested)
		{
			await using AuditDbContext db = await _factory.CreateDbContextAsync(ct).ConfigureAwait(false);
			int deleted = await WithBusyRetryAsync(
				token => filter(db).Take(batchSize).ExecuteDeleteAsync(token),
				ct).ConfigureAwait(false);

			totalDeleted += deleted;
			if (deleted < batchSize)
			{
				break;
			}
		}

		return totalDeleted;
	}

	/// <summary>Executes <paramref name="action"/>, retrying transient SQLite busy/locked errors
	/// (codes 5 / 6) with a short exponential backoff. Other exceptions propagate immediately.</summary>
	private async Task WithBusyRetryAsync(Func<CancellationToken, Task> action, CancellationToken ct)
	{
		await WithBusyRetryAsync<object?>(async token =>
		{
			await action(token).ConfigureAwait(false);
			return null;
		}, ct).ConfigureAwait(false);
	}

	private async Task<TResult> WithBusyRetryAsync<TResult>(
		Func<CancellationToken, Task<TResult>> action,
		CancellationToken ct)
	{
		for (int i = 0; i < BusyBackoffs.Length; i++)
		{
			try
			{
				return await action(ct).ConfigureAwait(false);
			}
			catch (SqliteException ex) when (ex.SqliteErrorCode is 5 or 6)
			{
				if (i == BusyBackoffs.Length - 1)
				{
					throw;
				}

				_logger.LogWarning(
					"Maintenance DB busy (attempt {Attempt}) — retrying in {Ms}ms",
					i + 1,
					BusyBackoffs[i].TotalMilliseconds);
				await Task.Delay(BusyBackoffs[i], ct).ConfigureAwait(false);
			}
		}

		// Unreachable: the loop either returns or rethrows.
		throw new InvalidOperationException("Retry loop exited without producing a result.");
	}

	private void PruneLogFiles(StorageOptions storage)
	{
		try
		{
			string logDir = storage.ResolveLogDirectory();
			if (!Directory.Exists(logDir))
			{
				return;
			}

			DateTime cutoff = DateTime.UtcNow.AddDays(-Math.Max(7, storage.LogRetentionDays));
			foreach (string file in Directory.EnumerateFiles(logDir, "service-*.log"))
			{
				FileInfo info = new(file);
				if (info.LastWriteTimeUtc < cutoff)
				{
					info.Delete();
				}
			}
		}
		catch (Exception ex)
		{
			_logger.LogDebug(ex, "Log pruning failed");
		}
	}
}
