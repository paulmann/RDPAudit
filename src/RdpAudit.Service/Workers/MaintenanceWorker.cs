/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 2.0.0
// File   : MaintenanceWorker.cs
// Project: RdpAudit.Service (RdpAudit.Service.Workers)
// Purpose: Performs bounded housekeeping for non-RawEvent telemetry and service files.
// Depends: AuditDbContext, RdpAuditOptions, ILogger
// Extends: Keep RawEvent retention delegated to RetentionWorker when adding maintenance work.
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using RdpAudit.Core.Config;
using RdpAudit.Core.Data;
using RdpAudit.Core.Integrity;
using RdpAudit.Core.Models;
using RdpAudit.Core.Util;
using RdpAudit.Service.Services;

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
	private readonly StoreIntegrityService? _storeIntegrity;

	public MaintenanceWorker(
		IDbContextFactory<AuditDbContext> factory,
		IOptionsMonitor<RdpAuditOptions> options,
		ILogger<MaintenanceWorker> logger,
		StoreIntegrityService? storeIntegrity = null)
	{
		_factory = factory;
		_options = options;
		_logger = logger;
		_storeIntegrity = storeIntegrity;
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
		DateTime alertCutoff = utcNow.AddDays(-Math.Max(30, storage.AlertRetentionDays));
		DateTime abuseCutoff = utcNow.AddDays(-Math.Max(30, storage.AbuseReportRetentionDays));
		DateTime activeBlockCutoff = utcNow.AddDays(-Math.Max(7, storage.ActiveBlockRetentionDays));
		DateTime attackStatCutoff = utcNow.AddDays(-Math.Max(14, storage.AttackStatRetentionDays));
		DateTime correlationCutoff = utcNow.AddDays(-Math.Max(7, storage.SessionIpCorrelationRetentionDays));
		DateTime connectionFactCutoff = utcNow.AddDays(-Math.Max(30, storage.RdpConnectionFactRetentionDays));

		// RawEvents retention is owned by RetentionWorker because it honours per-event overrides,
		// including the explicit zero-day \"retain forever\" policy. A global maintenance sweep
		// here would silently violate that policy once per day.
		int eventsDeleted = 0;

		int alertsDeleted = await PruneBatchedAsync(
			db => db.Alerts.Where(a => a.TimeUtc < alertCutoff).OrderBy(a => a.TimeUtc).ThenBy(a => a.Id),
			batch,
			ct).ConfigureAwait(false);

		int abuseReportsDeleted = await PruneBatchedAsync(
			db => db.AbuseReports.Where(a => a.ReportedUtc < abuseCutoff).OrderBy(a => a.ReportedUtc).ThenBy(a => a.Id),
			batch,
			ct).ConfigureAwait(false);

		// ActiveBlocks: only remove rows that are no longer load-bearing. A row is eligible when it
		// is Removed, or when it expired past the retention cutoff AND is not Active/Pending. The
		// Active/Pending exclusion is what the comment below promises: deleting one of those rows
		// while its firewall/MikroTik rule is still installed would orphan a live block that the
		// operator can no longer see or unblock. The expiration worker is the authoritative path
		// that tears those rows down first.
		int activeBlocksDeleted = await PruneBatchedAsync(
			db => db.ActiveBlocks
				.Where(b =>
					b.Status == ActiveBlockStatus.Removed
					|| (b.Status != ActiveBlockStatus.Active
						&& b.Status != ActiveBlockStatus.Pending
						&& b.ExpiresUtc != null
						&& b.ExpiresUtc < activeBlockCutoff))
				.OrderBy(b => b.CreatedUtc)
				.ThenBy(b => b.Id),
			batch,
			ct).ConfigureAwait(false);

		int attackStatsDeleted = await PruneBatchedAsync(
			db => db.AttackStats.Where(s => s.LastSeenUtc < attackStatCutoff).OrderBy(s => s.LastSeenUtc).ThenBy(s => s.Ip),
			batch,
			ct).ConfigureAwait(false);

		int correlationsDeleted = await PruneBatchedAsync(
			db => db.SessionIpCorrelations.Where(c => c.LastSeenUtc < correlationCutoff).OrderBy(c => c.LastSeenUtc).ThenBy(c => c.Id),
			batch,
			ct).ConfigureAwait(false);

		int connectionFactsDeleted = await PruneBatchedAsync(
			db => db.RdpConnectionFacts.Where(f => f.LastSeenUtc < connectionFactCutoff).OrderBy(f => f.LastSeenUtc).ThenBy(f => f.Id),
			batch,
			ct).ConfigureAwait(false);

		// v1.3.3: operation-log retention. Rows older than the configured (clamped) retention depth
		// are deleted in bounded batches so the operator-facing audit trail stays responsive on the
		// Logs tab and the table never grows without bound on a long-lived host.
		DateTime operationLogCutoff = utcNow.AddDays(-logs.ResolveRetentionDays());
		int operationLogsDeleted = await PruneBatchedAsync(
			db => db.OperationLogs.Where(o => o.TimeUtc < operationLogCutoff).OrderBy(o => o.TimeUtc).ThenBy(o => o.Id),
			batch,
			ct).ConfigureAwait(false);

		await using (AuditDbContext db = await _factory.CreateDbContextAsync(ct).ConfigureAwait(false))
		{
			// Bounded incremental_vacuum: at most 5000 free pages per pass to avoid
			// holding the writer lock for an unbounded amount of time on huge databases.
			// It releases nothing on a store whose auto-vacuum mode is not INCREMENTAL (B27); the Database
			// tab's overview reports that mode, and the offline compaction is what changes it.
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

		// Stage 5: the scheduled integrity checks and the periodic store fingerprint. Both are observations:
		// the checks journal their outcome and never repair anything, and the fingerprint gives the next
		// start something to compare against when the service was killed rather than stopped cleanly.
		await RunStoreIntegrityPassAsync(utcNow, ct).ConfigureAwait(false);

		PruneLogFiles(storage);
	}

	/// <summary>Runs the scheduled integrity checks and captures the periodic store fingerprint. Best effort:
	/// a maintenance pass that cannot complete its integrity work still completes the retention it exists
	/// for, and the failure is logged rather than thrown so the 24-hour loop is never killed by it.</summary>
	private async Task RunStoreIntegrityPassAsync(DateTime utcNow, CancellationToken ct)
	{
		if (_storeIntegrity is null)
		{
			return;
		}

		try
		{
			IReadOnlyList<DatabaseIntegrityCheckResult> results =
				await _storeIntegrity.RunScheduledChecksAsync(utcNow.ToLocalTime(), ct).ConfigureAwait(false);
			foreach (DatabaseIntegrityCheckResult result in results)
			{
				_logger.LogInformation(
					"Integrity check {Kind} finished with {Outcome} in {DurationMs} ms",
					result.Kind,
					result.Outcome,
					result.DurationMs);
			}

			StoreFingerprint fingerprint = await _storeIntegrity
				.CaptureAsync("Schedule", cleanShutdown: false, ct)
				.ConfigureAwait(false);
			_storeIntegrity.Fingerprints.Write(fingerprint, cleanShutdown: false);
			_logger.LogInformation(
				"Periodic store fingerprint captured: dbBytes={DatabaseBytes} tables={Tables} ledgerChained={Chained} chainIntact={Intact}",
				fingerprint.DatabaseBytes,
				fingerprint.TableRowCounts.Count,
				fingerprint.LedgerChainedRows,
				fingerprint.LedgerChainIntact);
		}
		catch (OperationCanceledException) when (ct.IsCancellationRequested)
		{
			throw;
		}
		catch (Exception ex)
		{
			_logger.LogWarning(ex, "The scheduled store-integrity pass could not be completed");
		}
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
			// All callers already pass a filter with a deterministic OrderBy+ThenBy order,
			// so Take(batchSize) below does not trigger RowLimitingOperationWithoutOrderByWarning
			// and each batch stays bounded, releasing the SQLite writer lock between batches.
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
			catch (Exception ex) when (SqliteTransientErrors.IsTransient(ex))
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
			// Log-file name pattern resolved from the same single source of truth (D2) that
		// Program.ConfigureSerilog uses when composing the day-rolling Serilog file name.
		string serviceLogPattern = RdpAuditPaths.ServiceLogFilePrefix + "*" + RdpAuditPaths.ServiceLogExtension;
		foreach (string file in Directory.EnumerateFiles(logDir, serviceLogPattern))
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
