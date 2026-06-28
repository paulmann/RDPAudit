// File:    src/RdpAudit.Service/Workers/AlertWorker.cs
// Module:  RdpAudit.Service.Workers
// Purpose: Periodically scans unprocessed RawEvents and applies the registered alert rules.
// Extends: Microsoft.Extensions.Hosting.BackgroundService
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System.Diagnostics;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using RdpAudit.Core.Config;
using RdpAudit.Core.Data;
using RdpAudit.Core.Events;
using RdpAudit.Core.Models;

namespace RdpAudit.Service.Workers;

/// <summary>Periodically scans unprocessed RawEvents and applies the registered alert rules.</summary>
public sealed class AlertWorker : BackgroundService
{
	private readonly IDbContextFactory<AuditDbContext> _factory;
	private readonly IEnumerable<IAlertRule> _rules;
	private readonly IAlertContext _context;
	private readonly ServiceMetrics _metrics;
	private readonly IOptionsMonitor<RdpAuditOptions> _options;
	private readonly ILogger<AlertWorker> _logger;

	public AlertWorker(
		IDbContextFactory<AuditDbContext> factory,
		IEnumerable<IAlertRule> rules,
		IAlertContext context,
		ServiceMetrics metrics,
		IOptionsMonitor<RdpAuditOptions> options,
		ILogger<AlertWorker> logger)
	{
		_factory = factory;
		_rules = rules;
		_context = context;
		_metrics = metrics;
		_options = options;
		_logger = logger;
	}

	protected override async Task ExecuteAsync(CancellationToken stoppingToken)
	{
		_logger.LogInformation("{Worker} starting with {Count} alert rules",
			nameof(AlertWorker),
			_rules.Count());
		try
		{
			while (!stoppingToken.IsCancellationRequested)
			{
				try
				{
					int processed = await ProcessOnceAsync(stoppingToken).ConfigureAwait(false);
					if (processed == 0)
					{
						await Task.Delay(TimeSpan.FromSeconds(2), stoppingToken).ConfigureAwait(false);
					}
				}
				catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
				{
					break;
				}
				catch (Exception ex)
				{
					_logger.LogError(ex, "Alert evaluation iteration failed");
					await Task.Delay(TimeSpan.FromSeconds(5), stoppingToken).ConfigureAwait(false);
				}
			}
		}
		catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
		{
		}
		finally
		{
			_logger.LogInformation("{Worker} stopped", nameof(AlertWorker));
		}
	}

	private async Task<int> ProcessOnceAsync(CancellationToken ct)
	{
		await using AuditDbContext db = await _factory.CreateDbContextAsync(ct).ConfigureAwait(false);
		List<RawEvent> batch = await db.RawEvents
			.Where(e => !e.Processed)
			.OrderBy(e => e.Id)
			.Take(500)
			.ToListAsync(ct)
			.ConfigureAwait(false);

		if (batch.Count == 0)
		{
			return 0;
		}

		RdpAuditOptions options = _options.CurrentValue;
		bool measure = options.Diagnostics.LogAlertEvaluationTimings;

		foreach (RawEvent evt in batch)
		{
			foreach (IAlertRule rule in _rules)
			{
				if (!rule.IsEnabled(options))
				{
					continue;
				}

				Stopwatch? sw = measure ? Stopwatch.StartNew() : null;
				try
				{
					Alert? alert = await rule.EvaluateAsync(evt, _context, ct).ConfigureAwait(false);
					if (alert is not null)
					{
						db.Alerts.Add(alert);
						_metrics.IncrementAlert();
						_logger.LogWarning(
							"Alert {RuleId} severity={Severity} user={UserName} ip={SourceIp} message={Message}",
							alert.RuleId,
							alert.Severity,
							alert.UserName,
							alert.SourceIp,
							alert.Message);
					}
				}
				catch (Exception ex)
				{
					_logger.LogError(ex, "Alert rule {RuleId} threw on event {EventId}", rule.RuleId, evt.Id);
				}
				finally
				{
					if (sw is not null)
					{
						sw.Stop();
						_logger.LogDebug(
							"Rule {RuleId} took {Elapsed}ms on event {EventId}",
							rule.RuleId,
							sw.ElapsedMilliseconds,
							evt.Id);
					}
				}
			}

			evt.Processed = true;
		}

		await db.SaveChangesAsync(ct).ConfigureAwait(false);
		return batch.Count;
	}
}
