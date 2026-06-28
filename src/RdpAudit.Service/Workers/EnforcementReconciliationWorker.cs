// File:    src/RdpAudit.Service/Workers/EnforcementReconciliationWorker.cs
// Module:  RdpAudit.Service.Workers
// Purpose: Periodically runs live enforcement reconciliation so RdpAudit never silently claims an
//          IP is blocked when no backend object exists. Each pass scans the real firewall, compares
//          it against the database-intended ActiveBlock rows, logs the verified / unenforced /
//          orphan counts, and demotes any Active row whose enforcement is found Missing or Failed to
//          the Failed status (and promotes a previously-Failed row back to Active once a matching
//          backend object is verified). The interval is config-driven and the worker is a no-op when
//          ReconciliationIntervalSeconds is non-positive.
// Extends: Microsoft.Extensions.Hosting.BackgroundService
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using RdpAudit.Core.Config;
using RdpAudit.Core.Data;
using RdpAudit.Core.Firewall;
using RdpAudit.Core.Ipc.Contracts;
using RdpAudit.Core.Models;
using RdpAudit.Service.Services;

namespace RdpAudit.Service.Workers;

/// <summary>Periodically reconciles database-intended blocks against the live firewall state.</summary>
public sealed class EnforcementReconciliationWorker : BackgroundService
{
	private static readonly TimeSpan ErrorDelay = TimeSpan.FromSeconds(30);
	private static readonly TimeSpan MinInterval = TimeSpan.FromSeconds(15);

	private readonly EnforcementReconciliationService _reconciliation;
	private readonly IDbContextFactory<AuditDbContext> _factory;
	private readonly IOptionsMonitor<RdpAuditOptions> _options;
	private readonly ILogger<EnforcementReconciliationWorker> _logger;

	public EnforcementReconciliationWorker(
		EnforcementReconciliationService reconciliation,
		IDbContextFactory<AuditDbContext> factory,
		IOptionsMonitor<RdpAuditOptions> options,
		ILogger<EnforcementReconciliationWorker> logger)
	{
		ArgumentNullException.ThrowIfNull(reconciliation);
		ArgumentNullException.ThrowIfNull(factory);
		ArgumentNullException.ThrowIfNull(options);
		ArgumentNullException.ThrowIfNull(logger);
		_reconciliation = reconciliation;
		_factory = factory;
		_options = options;
		_logger = logger;
	}

	protected override async Task ExecuteAsync(CancellationToken stoppingToken)
	{
		_logger.LogInformation("{Worker} starting", nameof(EnforcementReconciliationWorker));
		try
		{
			while (!stoppingToken.IsCancellationRequested)
			{
				TimeSpan interval = ResolveInterval();
				if (interval <= TimeSpan.Zero)
				{
					// Reconciliation disabled by config; re-check periodically for a config change.
					await Task.Delay(TimeSpan.FromMinutes(5), stoppingToken).ConfigureAwait(false);
					continue;
				}

				try
				{
					await TickAsync(stoppingToken).ConfigureAwait(false);
					await Task.Delay(interval, stoppingToken).ConfigureAwait(false);
				}
				catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
				{
					break;
				}
				catch (Exception ex)
				{
					_logger.LogError(ex, "Reconciliation iteration failed");
					await Task.Delay(ErrorDelay, stoppingToken).ConfigureAwait(false);
				}
			}
		}
		catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
		{
		}
		finally
		{
			_logger.LogInformation("{Worker} stopped", nameof(EnforcementReconciliationWorker));
		}
	}

	/// <summary>Runs one reconciliation pass and reconciles ActiveBlock row health against it.</summary>
	internal async Task TickAsync(CancellationToken ct)
	{
		ReconciliationReportDto report = await _reconciliation.ReconcileAsync(ct).ConfigureAwait(false);

		_logger.LogInformation(
			"Reconciliation pass: {Total} block(s), {Verified} verified, {Unenforced} unenforced, {Orphans} orphan(s)",
			report.Blocks.Count,
			report.VerifiedCount,
			report.UnenforcedCount,
			report.Orphans.Count);

		// Map each reconciled block to the row health the operator should see: a row whose
		// enforcement could not be verified must never remain Active.
		Dictionary<long, ReconciledBlockDto> byId = new();
		foreach (ReconciledBlockDto b in report.Blocks)
		{
			if (b.ActiveBlockId > 0)
			{
				byId[b.ActiveBlockId] = b;
			}
		}

		if (byId.Count == 0)
		{
			return;
		}

		await using AuditDbContext db = await _factory.CreateDbContextAsync(ct).ConfigureAwait(false);
		List<long> ids = new(byId.Keys);
		List<ActiveBlock> rows = await db.ActiveBlocks
			.Where(r => ids.Contains(r.Id))
			.ToListAsync(ct).ConfigureAwait(false);

		bool changed = false;
		foreach (ActiveBlock row in rows)
		{
			if (!byId.TryGetValue(row.Id, out ReconciledBlockDto? rb))
			{
				continue;
			}

			ActiveBlockStatus desired = MapHealth(rb.Status, rb.Confidence, row.Status);
			if (desired != row.Status)
			{
				_logger.LogWarning(
					"Reconciliation demoting/promoting block {Id} ({Ip}) {Old} -> {New}: {Detail}",
					row.Id,
					row.Ip,
					row.Status,
					desired,
					rb.Detail);
				row.Status = desired;
				if (desired == ActiveBlockStatus.Failed)
				{
					row.LastError = rb.Detail ?? "Enforcement could not be verified during reconciliation.";
				}
				else if (desired == ActiveBlockStatus.Active)
				{
					row.LastError = null;
				}

				changed = true;
			}
		}

		if (changed)
		{
			await db.SaveChangesAsync(ct).ConfigureAwait(false);
		}
	}

	/// <summary>Maps a reconciled status/confidence to the ActiveBlock health the operator should see.
	/// Verified enforcement promotes a row to Active; missing/failed enforcement demotes it to Failed.
	/// Expired rows are left to the expiration worker; unknown states leave the row untouched.</summary>
	private static ActiveBlockStatus MapHealth(
		EnforcementStatus status,
		EnforcementConfidence confidence,
		ActiveBlockStatus current)
	{
		return status switch
		{
			EnforcementStatus.Active when confidence is EnforcementConfidence.Verified
				or EnforcementConfidence.ExistsButProviderMayBypass => ActiveBlockStatus.Active,
			EnforcementStatus.MissingRule => ActiveBlockStatus.Failed,
			EnforcementStatus.Failed => ActiveBlockStatus.Failed,
			EnforcementStatus.ParameterMismatch => ActiveBlockStatus.Failed,
			_ => current,
		};
	}

	private TimeSpan ResolveInterval()
	{
		int seconds = _options.CurrentValue.Firewall.ReconciliationIntervalSeconds;
		if (seconds <= 0)
		{
			return TimeSpan.Zero;
		}

		TimeSpan interval = TimeSpan.FromSeconds(seconds);
		return interval < MinInterval ? MinInterval : interval;
	}
}
