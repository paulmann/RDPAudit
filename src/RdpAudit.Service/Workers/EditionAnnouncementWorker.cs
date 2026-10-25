/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// File   : EditionAnnouncementWorker.cs
// Project: RdpAudit.Service (RdpAudit.Service.Workers)
// Purpose: Startup record of the edition this binary was built for, plus one explicit warning per
//          configured capability the build does not contain. Without it a Pro feature configured on a
//          Community install would be an idle subsystem nobody notices; with it the operator reads
//          "RestApi requires the Pro edition; this build is Community (BSL-1.1)" in the startup log and in
//          startup-sequence.log, where the TimedHostedService wrapper already records the begin/end.
// Depends: IOptionsMonitor<RdpAuditOptions>, ILogger, RdpAudit.Core.Editions
// Extends: Add a warning block when a new gated capability gains a configuration switch.

using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using RdpAudit.Core.Config;
using RdpAudit.Core.Editions;

namespace RdpAudit.Service.Workers;

/// <summary>Logs the build's edition and every configured but unavailable capability once at startup.</summary>
/// <remarks>
/// Read-only and allocation-free in the steady state: it does no work after <see cref="StartAsync"/>,
/// touches no database and never blocks the startup chain. Registered first in the hosted-service
/// chain precisely because it must be seen even when a later worker fails to start.
/// </remarks>
public sealed class EditionAnnouncementWorker : IHostedService
{
	private readonly IOptionsMonitor<RdpAuditOptions> _options;
	private readonly ILogger<EditionAnnouncementWorker> _logger;

	/// <summary>Creates the worker.</summary>
	/// <param name="options">Live options, read once at startup.</param>
	/// <param name="logger">Logger.</param>
	public EditionAnnouncementWorker(
		IOptionsMonitor<RdpAuditOptions> options,
		ILogger<EditionAnnouncementWorker> logger)
	{
		ArgumentNullException.ThrowIfNull(options);
		ArgumentNullException.ThrowIfNull(logger);
		_options = options;
		_logger = logger;
	}

	/// <inheritdoc />
	public Task StartAsync(CancellationToken cancellationToken)
	{
		_logger.LogInformation(
			"RDPAudit edition {Edition} (ordinal {Ordinal}, constant {Constant}, licence {License}), product version {Version}; cross-host budget {HostBudget} host(s).",
			EditionContext.DisplayName,
			(int)EditionContext.Current,
			EditionContext.BuildConstantName,
			EditionContext.LicenseName,
			EditionContext.ProductVersion,
			EditionContext.MaxCrossHostHosts);

		RdpAuditOptions options = _options.CurrentValue;

		if (options.Api.Enabled)
		{
			WarnIfUnavailable(EditionFeature.RestApi, "Api.Enabled");
		}

		if (options.CrossHost.Enabled || options.CrossHost.Hosts.Count > 0)
		{
			WarnIfUnavailable(EditionFeature.CrossHostCorrelation, "CrossHost.Enabled / CrossHost.Hosts");
		}

		if (options.Zabbix.Enabled)
		{
			WarnIfUnavailable(EditionFeature.ZabbixIntegration, "Zabbix.Enabled");
		}

		if (options.Firewall.ResponseDryRun)
		{
			WarnIfUnavailable(EditionFeature.ResponseDryRun, "Firewall.ResponseDryRun");
		}

		return Task.CompletedTask;
	}

	/// <inheritdoc />
	public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;

	private void WarnIfUnavailable(EditionFeature feature, string configuredBy)
	{
		if (EditionContext.Allows(feature))
		{
			return;
		}

		// One line per feature, no exception, no retry: the configuration is valid, the licence is not.
		// Refusing to start the service over a licensing mismatch would take down the local detection
		// that the lower edition legitimately provides.
		_logger.LogWarning(
			"Configured capability {Feature} is not part of this build ({ConfiguredBy} is set). {Reason} Nothing was started for it.",
			feature,
			configuredBy,
			EditionContext.DenialReason(feature));
	}
}
