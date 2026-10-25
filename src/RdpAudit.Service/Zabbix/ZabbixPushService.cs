/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// File   : ZabbixPushService.cs
// Project: RdpAudit.Service (RdpAudit.Service.Zabbix)
// Purpose: The push cycle itself: read the incidents that appeared since the acknowledged alert id,
//          build the item values, send them, and advance the position only when the server accepted
//          every value. Shared by the background worker and the "Push now" button, so the two can
//          never disagree about what was sent.
// Extends: System.Object

using System.Diagnostics;
using System.Globalization;
using System.Reflection;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using RdpAudit.Core.Config;
using RdpAudit.Core.Data;
using RdpAudit.Core.Ipc.Contracts;
using RdpAudit.Core.Models;
using RdpAudit.Core.Zabbix;

namespace RdpAudit.Service.Zabbix;

/// <summary>Push cycle, status, connection test and provisioning behind one object.</summary>
public sealed class ZabbixPushService : IDisposable
{
	/// <summary>How many incidents the tab list remembers.</summary>
	public const int RecentIncidentLimit = 20;

	private readonly IDbContextFactory<AuditDbContext> _factory;
	private readonly IOptionsMonitor<RdpAuditOptions> _options;
	private readonly IZabbixSender _sender;
	private readonly IZabbixApiClient _api;
	private readonly ZabbixPushStateStore _stateStore;
	private readonly ServiceMetrics _metrics;
	private readonly ILogger<ZabbixPushService> _logger;
	private readonly TimeProvider _time;
	private readonly SemaphoreSlim _gate = new(1, 1);

	/// <summary>Creates the service.</summary>
	/// <param name="factory">Database context factory.</param>
	/// <param name="options">Live options.</param>
	/// <param name="sender">Sender transport.</param>
	/// <param name="api">Provisioning client.</param>
	/// <param name="stateStore">Durable push position.</param>
	/// <param name="metrics">Service counters used for the machine summary.</param>
	/// <param name="logger">Logger.</param>
	/// <param name="time">Clock; tests substitute a fixed one.</param>
	public ZabbixPushService(
		IDbContextFactory<AuditDbContext> factory,
		IOptionsMonitor<RdpAuditOptions> options,
		IZabbixSender sender,
		IZabbixApiClient api,
		ZabbixPushStateStore stateStore,
		ServiceMetrics metrics,
		ILogger<ZabbixPushService> logger,
		TimeProvider? time = null)
	{
		ArgumentNullException.ThrowIfNull(factory);
		ArgumentNullException.ThrowIfNull(options);
		ArgumentNullException.ThrowIfNull(sender);
		ArgumentNullException.ThrowIfNull(api);
		ArgumentNullException.ThrowIfNull(stateStore);
		ArgumentNullException.ThrowIfNull(metrics);
		ArgumentNullException.ThrowIfNull(logger);
		_factory = factory;
		_options = options;
		_sender = sender;
		_api = api;
		_stateStore = stateStore;
		_metrics = metrics;
		_logger = logger;
		_time = time ?? TimeProvider.System;
	}

	/// <summary>Releases the re-entrancy gate. Registered as a singleton, so the container owns it.</summary>
	public void Dispose() => _gate.Dispose();

	/// <summary>Runs one push cycle.</summary>
	/// <param name="manual">True for an operator-triggered push, which runs even when the worker is
	/// disabled (the operator is asking explicitly) but still respects a missing endpoint.</param>
	/// <param name="ct">Cancellation token.</param>
	public async Task<ZabbixPushResultDto> PushAsync(bool manual, CancellationToken ct)
	{
		ZabbixOptions opts = _options.CurrentValue.Zabbix;
		ZabbixPushResultDto result = new() { PushedUtc = _time.GetUtcNow().UtcDateTime };

		if (string.IsNullOrWhiteSpace(opts.ServerHost))
		{
			result.Status = IpcResultStatus.Refused;
			result.Message = "The Zabbix server host is not configured.";
			return result;
		}

		if (!opts.Enabled && !manual)
		{
			result.Status = IpcResultStatus.Refused;
			result.Message = "The Zabbix integration is disabled.";
			return result;
		}

		if (!await _gate.WaitAsync(0, ct).ConfigureAwait(false))
		{
			result.Status = IpcResultStatus.Unavailable;
			result.Message = "A push is already in progress; this request was not queued.";
			return result;
		}

		try
		{
			return await PushCoreAsync(opts, result, ct).ConfigureAwait(false);
		}
		finally
		{
			_gate.Release();
		}
	}

	private async Task<ZabbixPushResultDto> PushCoreAsync(
		ZabbixOptions opts,
		ZabbixPushResultDto result,
		CancellationToken ct)
	{
		DateTime nowUtc = _time.GetUtcNow().UtcDateTime;
		ZabbixPushState state = _stateStore.Load();
		string hostName = ZabbixHostName.Resolve(opts.HostName, Environment.MachineName);
		int maxPerPush = opts.ResolveMaxIncidentsPerPush();
		int backlogCap = opts.ResolveMaxBacklogIncidents();
		long lastPushedId = state.LastPushedAlertId;
		long sequence = state.Sequence + 1;

		List<ZabbixIncident> incidents = new();
		int skipped = 0;
		int pending;
		int activeBlocks;

		await using (AuditDbContext db = await _factory.CreateDbContextAsync(ct).ConfigureAwait(false))
		{
			pending = await db.Alerts.AsNoTracking()
				.CountAsync(a => a.Id > lastPushedId, ct)
				.ConfigureAwait(false);

			activeBlocks = await db.ActiveBlocks.AsNoTracking()
				.CountAsync(b => b.Status == ActiveBlockStatus.Active, ct)
				.ConfigureAwait(false);

			List<Alert> batch;
			if (pending > backlogCap)
			{
				// The backlog outgrew its ceiling: keep the newest incidents, count the rest as skipped.
				// Dropping is reported, never silent, and the local database still holds every one.
				batch = await db.Alerts.AsNoTracking()
					.Where(a => a.Id > lastPushedId)
					.OrderByDescending(a => a.Id)
					.Take(maxPerPush)
					.ToListAsync(ct)
					.ConfigureAwait(false);
				batch.Reverse();
				skipped = pending - batch.Count;
			}
			else
			{
				batch = await db.Alerts.AsNoTracking()
					.Where(a => a.Id > lastPushedId)
					.OrderBy(a => a.Id)
					.Take(maxPerPush)
					.ToListAsync(ct)
					.ConfigureAwait(false);
			}

			foreach (Alert alert in batch)
			{
				if (alert.Severity < opts.MinimumSeverity)
				{
					// Below the operator's threshold: acknowledged by advancing the position, not forwarded.
					continue;
				}

				incidents.Add(new ZabbixIncident(
					alert.Id,
					alert.TimeUtc,
					alert.RuleId,
					alert.Severity,
					alert.SourceIp,
					alert.SourceIpDerived,
					alert.UserName,
					alert.Message));
			}

			ZabbixMachineSummary summary = new(
				Environment.MachineName,
				ResolveVersion(),
				ResolveUptime(),
				_metrics.EventsCaptured,
				_metrics.EventsDropped,
				_metrics.AlertsRaised,
				activeBlocks,
				Math.Max(0, pending - maxPerPush),
				skipped);

			ZabbixPayload payload = ZabbixIncidentPayloadBuilder.Build(hostName, incidents, summary, sequence, nowUtc);

			ZabbixSenderOutcome outcome = await _sender.SendAsync(
				opts.ServerHost,
				opts.ResolveServerPort(),
				payload.Values,
				TimeSpan.FromSeconds(opts.ResolveTimeoutSeconds()),
				ct).ConfigureAwait(false);

			result.Sequence = sequence;
			result.Processed = outcome.Processed;
			result.Failed = outcome.Failed;
			result.Total = outcome.Total;
			result.Delivered = outcome.Delivered;
			result.IncidentsInBatch = incidents.Count;
			result.Skipped = skipped;
			result.MaxSeverity = payload.MaxSeverity;
			result.Message = outcome.Message;

			state.Sequence = sequence;
			state.LastPushUtc = nowUtc;
			state.ValuesSent += Math.Max(0, outcome.Processed);
			state.ValuesFailed += Math.Max(0, outcome.Failed);

			if (outcome.Delivered)
			{
				long newestId = batch.Count == 0 ? lastPushedId : batch[^1].Id;
				state.LastPushedAlertId = Math.Max(lastPushedId, newestId);
				state.LastSuccessUtc = nowUtc;
				state.ConsecutiveFailures = 0;
				state.LastError = string.Empty;
				state.IncidentsSkipped += skipped;

				if (incidents.Count > 0)
				{
					state.RecentIncidents = BuildRecentList(incidents, nowUtc);
				}

				result.Status = IpcResultStatus.Success;
				_logger.LogInformation(
					"Zabbix push {Sequence} accepted: {Incidents} incident(s), {Processed}/{Total} value(s), {Skipped} skipped.",
					sequence,
					incidents.Count,
					outcome.Processed,
					outcome.Total,
					skipped);
			}
			else
			{
				// Position deliberately NOT advanced: the same incidents are retried next cycle.
				state.ConsecutiveFailures++;
				state.LastError = outcome.Message;
				result.Status = IpcResultStatus.Unavailable;
				_logger.LogWarning(
					"Zabbix push {Sequence} was not accepted ({Failures} consecutive failure(s)): {Message}",
					sequence,
					state.ConsecutiveFailures,
					outcome.Message);
			}
		}

		_stateStore.Save(state);
		return result;
	}

	private static List<ZabbixSentIncidentDto> BuildRecentList(IReadOnlyList<ZabbixIncident> incidents, DateTime deliveredUtc)
	{
		List<ZabbixSentIncidentDto> rows = new(incidents.Count);
		for (int i = incidents.Count - 1; i >= 0 && rows.Count < RecentIncidentLimit; i--)
		{
			ZabbixIncident incident = incidents[i];
			rows.Add(new ZabbixSentIncidentDto
			{
				AlertId = incident.AlertId,
				TimeUtc = incident.TimeUtc,
				RuleId = incident.RuleId,
				Severity = incident.Severity.ToString(),
				ZabbixSeverity = ZabbixSeverity.ToZabbix(incident.Severity),
				SourceIp = incident.SourceIp ?? string.Empty,
				UserName = incident.UserName ?? string.Empty,
				Message = incident.Message,
				SourceIpDerived = incident.SourceIpDerived,
				DeliveredUtc = deliveredUtc,
			});
		}

		return rows;
	}

	/// <summary>Reads the current state without touching the network.</summary>
	/// <param name="ct">Cancellation token.</param>
	public async Task<ZabbixStatusDto> GetStatusAsync(CancellationToken ct)
	{
		ZabbixOptions opts = _options.CurrentValue.Zabbix;
		ZabbixPushState state = _stateStore.Load();

		ZabbixStatusDto dto = new()
		{
			Enabled = opts.Enabled,
			HostName = ZabbixHostName.Resolve(opts.HostName, Environment.MachineName),
			Endpoint = string.Format(
				CultureInfo.InvariantCulture,
				"{0}:{1}",
				string.IsNullOrWhiteSpace(opts.ServerHost) ? "(not configured)" : opts.ServerHost,
				opts.ResolveServerPort()),
			LastPushUtc = state.LastPushUtc,
			LastSuccessUtc = state.LastSuccessUtc,
			Sequence = state.Sequence,
			ConsecutiveFailures = state.ConsecutiveFailures,
			ValuesSent = state.ValuesSent,
			ValuesFailed = state.ValuesFailed,
			LastError = state.LastError,
			IncidentsSkipped = state.IncidentsSkipped,
			RecentIncidents = state.RecentIncidents,
			ProblemsUrl = ZabbixLinks.BuildProblemsText(opts.ResolveFrontendOrigin()),
		};

		if (opts.Enabled)
		{
			dto.NextPushDueUtc = (state.LastPushUtc ?? _time.GetUtcNow().UtcDateTime)
				.AddSeconds(opts.ResolvePushIntervalSeconds());
		}

		try
		{
			await using AuditDbContext db = await _factory.CreateDbContextAsync(ct).ConfigureAwait(false);
			dto.PendingBacklog = await db.Alerts.AsNoTracking()
				.CountAsync(a => a.Id > state.LastPushedAlertId, ct)
				.ConfigureAwait(false);
		}
		catch (OperationCanceledException) when (ct.IsCancellationRequested)
		{
			throw;
		}
		catch (Exception ex)
		{
			_logger.LogWarning(ex, "The pending Zabbix backlog could not be counted.");
			dto.Status = IpcResultStatus.Unavailable;
			dto.Message = "The pending backlog could not be read from the database.";
			return dto;
		}

		dto.Message = !opts.Enabled
			? "The Zabbix integration is disabled; nothing is sent."
			: string.Format(
				CultureInfo.InvariantCulture,
				"Push every {0} s to {1}; {2} incident(s) pending, last success {3}.",
				opts.ResolvePushIntervalSeconds(),
				dto.Endpoint,
				dto.PendingBacklog,
				state.LastSuccessUtc?.ToString("u", CultureInfo.InvariantCulture) ?? "never");

		return dto;
	}

	/// <summary>Probes the sender port and the API endpoint independently.</summary>
	/// <param name="ct">Cancellation token.</param>
	public async Task<ZabbixTestResultDto> TestAsync(CancellationToken ct)
	{
		Stopwatch stopwatch = Stopwatch.StartNew();
		ZabbixOptions opts = _options.CurrentValue.Zabbix;
		ZabbixTestResultDto dto = new()
		{
			ApiEndpoint = opts.ResolveApiEndpoint(),
			HostName = ZabbixHostName.Resolve(opts.HostName, Environment.MachineName),
		};

		bool senderAttempted = false;
		bool apiAttempted = false;

		if (string.IsNullOrWhiteSpace(opts.ServerHost))
		{
			dto.SenderMessage = "The sender host is not configured.";
		}
		else
		{
			senderAttempted = true;
			ZabbixProbeResult probe = await _sender.ProbeAsync(
				opts.ServerHost,
				opts.ResolveServerPort(),
				TimeSpan.FromSeconds(opts.ResolveTimeoutSeconds()),
				ct).ConfigureAwait(false);
			dto.SenderReachable = probe.Reachable;
			dto.SenderMessage = probe.Message;
		}

		if (!opts.IsApiConfigured())
		{
			dto.Message = dto.SenderMessage + " The API URL or credential is not configured, so provisioning was not tested.";
		}
		else
		{
			apiAttempted = true;
			ZabbixApiProbe probe = await _api.ProbeAsync(ct).ConfigureAwait(false);
			dto.ApiReachable = probe.Reachable;
			dto.ApiVersion = probe.Version;
			dto.CredentialValid = probe.Authenticated;
			dto.Message = string.IsNullOrEmpty(dto.SenderMessage)
				? probe.Message
				: dto.SenderMessage + " " + probe.Message;
		}

		stopwatch.Stop();
		dto.ElapsedMilliseconds = (int)Math.Min(int.MaxValue, stopwatch.ElapsedMilliseconds);

		if (!senderAttempted && !apiAttempted)
		{
			dto.Status = IpcResultStatus.InvalidRequest;
		}
		else if (dto.SenderReachable || dto.ApiReachable)
		{
			// The push only needs the sender; a working API on its own is reported as partial success.
			dto.Status = dto.SenderReachable && (!apiAttempted || dto.ApiReachable)
				? IpcResultStatus.Success
				: IpcResultStatus.Unavailable;
		}
		else
		{
			dto.Status = IpcResultStatus.Unavailable;
		}

		return dto;
	}

	/// <summary>Ensures the host, items, triggers and dashboard exist in Zabbix.</summary>
	/// <param name="ct">Cancellation token.</param>
	public async Task<ZabbixProvisionResultDto> ProvisionAsync(CancellationToken ct)
	{
		ZabbixOptions opts = _options.CurrentValue.Zabbix;
		ZabbixProvisionResultDto dto = new()
		{
			ProblemsUrl = ZabbixLinks.BuildProblemsText(opts.ResolveFrontendOrigin()),
			FrontendUrl = ZabbixLinks.BuildDashboardText(opts.ResolveFrontendOrigin()),
		};

		if (!opts.IsApiConfigured())
		{
			dto.Status = IpcResultStatus.InvalidRequest;
			dto.Message = "Set the frontend URL and an API token (or user and password) before provisioning.";
			return dto;
		}

		try
		{
			ZabbixProvisionReport report = await _api
				.ProvisionAsync(opts.ProvisionTriggers, opts.CreateDashboard, ct)
				.ConfigureAwait(false);

			dto.Status = IpcResultStatus.Success;
			dto.GroupCreated = report.GroupCreated;
			dto.GroupExisted = report.GroupExisted;
			dto.HostCreated = report.HostCreated;
			dto.HostExisted = report.HostExisted;
			dto.ItemsCreated = report.ItemsCreated;
			dto.ItemsExisted = report.ItemsExisted;
			dto.ItemsUpdated = report.ItemsUpdated;
			dto.TriggersCreated = report.TriggersCreated;
			dto.TriggersExisted = report.TriggersExisted;
			dto.DashboardCreated = report.DashboardCreated;
			dto.DashboardExisted = report.DashboardExisted;
			dto.Message = report.Message
				+ " A freshly created host needs up to a minute of Zabbix configuration-cache sync before its trapper accepts values.";
			return dto;
		}
		catch (OperationCanceledException) when (ct.IsCancellationRequested)
		{
			throw;
		}
		catch (ZabbixApiException ex)
		{
			dto.Status = IpcResultStatus.Unavailable;
			dto.Message = "Provisioning failed: " + ex.Message;
			_logger.LogWarning("Zabbix provisioning failed: {Message}", ex.Message);
			return dto;
		}
		catch (HttpRequestException ex)
		{
			dto.Status = IpcResultStatus.Unavailable;
			dto.Message = "Provisioning failed: the API endpoint is unreachable (" + ex.Message + ").";
			return dto;
		}
	}

	private static string ResolveVersion()
	{
		Assembly assembly = typeof(ZabbixPushService).Assembly;
		string? informational = assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion;
		if (!string.IsNullOrWhiteSpace(informational))
		{
			int plus = informational.IndexOf('+', StringComparison.Ordinal);
			return plus > 0 ? informational[..plus] : informational;
		}

		return assembly.GetName().Version?.ToString() ?? "0.0.0";
	}

	private static TimeSpan ResolveUptime()
	{
		try
		{
			using Process process = Process.GetCurrentProcess();
			TimeSpan uptime = DateTime.UtcNow - process.StartTime.ToUniversalTime();
			return uptime > TimeSpan.Zero ? uptime : TimeSpan.Zero;
		}
		catch (Exception ex) when (ex is InvalidOperationException or NotSupportedException or System.ComponentModel.Win32Exception)
		{
			return TimeSpan.Zero;
		}
	}
}
