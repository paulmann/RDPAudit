// File:    src/RdpAudit.Service/Services/MonitoringConfigPostConfigure.cs
// Module:  RdpAudit.Service.Services
// Purpose: Applies MonitoringConfigRepair every time RdpAuditOptions is materialised, records the
//          outcome in ConfigRepairReporter, and logs at Information when a stale appsettings.json
//          was actually patched. Wired as an IPostConfigureOptions so it runs both for the initial
//          DI resolution and for IOptionsMonitor change pushes.
// Extends: Microsoft.Extensions.Options.IPostConfigureOptions{T}
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using RdpAudit.Core.Config;

namespace RdpAudit.Service.Services;

/// <summary>Runs <see cref="MonitoringConfigRepair.Repair"/> on every IOptions materialisation.</summary>
public sealed class MonitoringConfigPostConfigure : IPostConfigureOptions<RdpAuditOptions>
{
	private readonly ConfigRepairReporter _reporter;
	private readonly ILogger<MonitoringConfigPostConfigure> _logger;

	public MonitoringConfigPostConfigure(
		ConfigRepairReporter reporter,
		ILogger<MonitoringConfigPostConfigure> logger)
	{
		_reporter = reporter;
		_logger = logger;
	}

	public void PostConfigure(string? name, RdpAuditOptions options)
	{
		_ = name;
		ArgumentNullException.ThrowIfNull(options);

		MonitoringConfigRepairReport report = MonitoringConfigRepair.Repair(options.Monitoring);
		_reporter.Record(report);

		if (report.Changed)
		{
			_logger.LogInformation(
				"Monitoring configuration repaired at startup. AddedChannels=[{Channels}] AddedEventIds=[{EventIds}] Reason={Reason}",
				string.Join(',', report.AddedChannels),
				string.Join(',', report.AddedEventIds),
				report.Reason ?? "(no reason)");
		}
	}
}
