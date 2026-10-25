/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// File   : ZabbixPushWorker.cs
// Project: RdpAudit.Service (RdpAudit.Service.Zabbix)
// Purpose: Background loop that pushes the incident batch on a fixed cadence. The loop re-reads the
//          options every cycle, so enabling the integration or changing the cadence from the
//          Configurator takes effect without restarting the service. A cycle never throws out of the
//          loop: a failed push is recorded by the push service and retried on the next tick.
// Extends: Microsoft.Extensions.Hosting.BackgroundService

using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using RdpAudit.Core.Config;

namespace RdpAudit.Service.Zabbix;

/// <summary>Cadence driver for <see cref="ZabbixPushService"/>.</summary>
public sealed class ZabbixPushWorker : BackgroundService
{
	/// <summary>Initial delay, so migrations and the first alert evaluation are already done.</summary>
	internal static readonly TimeSpan StartupDelay = TimeSpan.FromSeconds(45);

	/// <summary>Delay used while the integration is disabled, so enabling it is picked up quickly.</summary>
	internal static readonly TimeSpan DisabledPollInterval = TimeSpan.FromSeconds(30);

	/// <summary>Upper bound on a single delay, so a pathological value cannot park the loop for a day.</summary>
	internal static readonly TimeSpan MaxDelay = TimeSpan.FromMinutes(15);

	private readonly ZabbixPushService _push;
	private readonly IOptionsMonitor<RdpAuditOptions> _options;
	private readonly ILogger<ZabbixPushWorker> _logger;

	/// <summary>Creates the worker.</summary>
	/// <param name="push">Push service shared with the IPC commands.</param>
	/// <param name="options">Live options.</param>
	/// <param name="logger">Logger.</param>
	public ZabbixPushWorker(
		ZabbixPushService push,
		IOptionsMonitor<RdpAuditOptions> options,
		ILogger<ZabbixPushWorker> logger)
	{
		ArgumentNullException.ThrowIfNull(push);
		ArgumentNullException.ThrowIfNull(options);
		ArgumentNullException.ThrowIfNull(logger);
		_push = push;
		_options = options;
		_logger = logger;
	}

	/// <inheritdoc />
	protected override async Task ExecuteAsync(CancellationToken stoppingToken)
	{
		_logger.LogInformation("{Worker} starting", nameof(ZabbixPushWorker));

		try
		{
			await Task.Delay(StartupDelay, stoppingToken).ConfigureAwait(false);
		}
		catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
		{
			return;
		}

		while (!stoppingToken.IsCancellationRequested)
		{
			TimeSpan delay;
			ZabbixOptions options = _options.CurrentValue.Zabbix;

			if (!options.Enabled || string.IsNullOrWhiteSpace(options.ServerHost))
			{
				delay = DisabledPollInterval;
			}
			else
			{
				delay = TimeSpan.FromSeconds(options.ResolvePushIntervalSeconds());
				try
				{
					await _push.PushAsync(manual: false, stoppingToken).ConfigureAwait(false);
				}
				catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
				{
					return;
				}
				catch (Exception ex)
				{
					// The push service already records the failure; this guard only keeps the loop alive.
					_logger.LogWarning(ex, "The Zabbix push cycle failed unexpectedly; retrying after the interval.");
				}
			}

			if (delay > MaxDelay)
			{
				delay = MaxDelay;
			}

			try
			{
				await Task.Delay(delay, stoppingToken).ConfigureAwait(false);
			}
			catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
			{
				return;
			}
		}
	}
}
