// File:    src/RdpAudit.Service/Workers/ProcessAlertAutoResponder.cs
// Module:  RdpAudit.Service.Workers
// Purpose: Background auto-close engine for PROCESS_NEW alerts. Each pass performs two
//          independent duties inside one concurrency gate. Arming: while
//          ProcessMonitoring.AutoCloseSessionOnNewProcess is enabled, fresh PROCESS_NEW
//          alerts (never older than ArmLookback) that have no persisted response row are armed
//          as Queued ProcessAlertResponses carrying the terminal-services session id parsed
//          from the alert's forensic Details JSON; alerts without a valid session id are never
//          armed (a doomed row is worse than no row). Execution: every Queued response with a
//          valid session id is finalised with one real logoff through RdpSessionManager,
//          bounded by the fixed per-minute rate limit MaxAutoCloseOperationsPerMinute, so a
//          burst of new-process alerts can never be amplified into an unlimited burst of
//          logoff operations. Responses with an invalid session id are finalised Failed without
//          spawning anything. The whole pass no-ops while ProcessMonitoring.Enabled is off and
//          defers (rows stay Queued) while SessionControl.Enabled / AllowLogoff are off, so
//          re-enabling configuration resumes work instead of losing it. Manual (IPC-armed)
//          jobs execute even when AutoCloseSessionOnNewProcess is off - the option gates only
//          automatic arming. Append-only: final states are never re-queued (the store refuses).
// Extends: Microsoft.Extensions.Hosting.BackgroundService
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using RdpAudit.Core.Config;
using RdpAudit.Core.Data;
using RdpAudit.Core.Ipc.Contracts;
using RdpAudit.Core.Models;
using RdpAudit.Core.ProcessMonitoring;
using RdpAudit.Core.Util;
using RdpAudit.Service.ProcessMonitoring;
using RdpAudit.Service.Services;

namespace RdpAudit.Service.Workers;

/// <summary>Background auto-close engine for PROCESS_NEW alerts (arming + rate-limited execution).</summary>
public sealed class ProcessAlertAutoResponder : BackgroundService
{
	/// <summary>Initial delay before the first pass - lets database migrations and the alert pipeline settle.</summary>
	internal static readonly TimeSpan StartupDelay = TimeSpan.FromMinutes(1);

	/// <summary>Arming look-back: only PROCESS_NEW alerts this fresh are armed automatically, so a
	/// late configuration switch never re-arms historic alerts against long-gone sessions.</summary>
	internal static readonly TimeSpan ArmLookback = TimeSpan.FromMinutes(5);

	/// <summary>Upper bound on alert rows armed per pass.</summary>
	internal const int MaxArmBatchPerPass = 200;

	/// <summary>Upper bound on queued jobs fetched per pass; the per-minute rate limit is the tighter real bound.</summary>
	internal const int MaxJobsPerPass = 50;

	/// <summary>Column bound for ProcessAlertResponses.ResultText.</summary>
	internal const int MaxResultTextLength = 2048;

	private const int NoSession = -1;

	private readonly KnownProcessStore _store;
	private readonly IDbContextFactory<AuditDbContext> _factory;
	private readonly IOptionsMonitor<RdpAuditOptions> _options;
	private readonly RdpSessionManager? _sessions;
	private readonly ILogger<ProcessAlertAutoResponder> _logger;
	private readonly TimeProvider _time;
	private readonly SemaphoreSlim _gate = new(1, 1);

	private readonly object _rateGate = new();
	private long _currentMinute;
	private int _logoffsInMinute;

	/// <summary>Creates the responder. <paramref name="sessions"/> is optional: hosts that cannot
	/// register RdpSessionManager (non-Windows) still drain the queue, finalising jobs Failed.</summary>
	public ProcessAlertAutoResponder(
		KnownProcessStore store,
		IDbContextFactory<AuditDbContext> factory,
		IOptionsMonitor<RdpAuditOptions> options,
		ILogger<ProcessAlertAutoResponder> logger,
		RdpSessionManager? sessions = null,
		TimeProvider? time = null)
	{
		ArgumentNullException.ThrowIfNull(store);
		ArgumentNullException.ThrowIfNull(factory);
		ArgumentNullException.ThrowIfNull(options);
		ArgumentNullException.ThrowIfNull(logger);
		_store = store;
		_factory = factory;
		_options = options;
		_sessions = sessions;
		_logger = logger;
		_time = time ?? TimeProvider.System;
	}

	protected override async Task ExecuteAsync(CancellationToken stoppingToken)
	{
		_logger.LogInformation("{Worker} starting", nameof(ProcessAlertAutoResponder));
		try
		{
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
				try
				{
					int finalized = await RunOnceAsync(stoppingToken).ConfigureAwait(false);
					_logger.LogDebug(
						"{Worker} pass finalised {Finalized} response(s)",
						nameof(ProcessAlertAutoResponder),
						finalized);
				}
				catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
				{
					break;
				}
				catch (Exception ex)
				{
					_logger.LogError(ex, "{Worker} pass failed", nameof(ProcessAlertAutoResponder));
				}

				TimeSpan period = TimeSpan.FromSeconds(
					_options.CurrentValue.ProcessMonitoring.ResolveAutoClosePollIntervalSeconds());
				try
				{
					await Task.Delay(period, stoppingToken).ConfigureAwait(false);
				}
				catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
				{
					break;
				}
			}
		}
		finally
		{
			_logger.LogInformation("{Worker} stopped", nameof(ProcessAlertAutoResponder));
		}
	}

	/// <summary>Runs one deterministic pass: arming scan first, then queued-job execution. Exposed
	/// for tests; honours the concurrency gate (a pass already running makes this one a no-op).
	/// Returns the number of response rows transitioned to a final state.</summary>
	public async Task<int> RunOnceAsync(CancellationToken ct)
	{
		if (!await _gate.WaitAsync(0, ct).ConfigureAwait(false))
		{
			_logger.LogDebug("{Worker} skipped: previous pass still running", nameof(ProcessAlertAutoResponder));
			return 0;
		}

		try
		{
			RdpAuditOptions options = _options.CurrentValue;
			if (!options.ProcessMonitoring.Enabled)
			{
				return 0;
			}

			DateTime nowUtc = _time.GetUtcNow().UtcDateTime;
			bool sessionControlOpen = options.SessionControl.Enabled && options.SessionControl.AllowLogoff;

			if (options.ProcessMonitoring.AutoCloseSessionOnNewProcess && sessionControlOpen)
			{
				await ArmFreshAlertsAsync(nowUtc, ct).ConfigureAwait(false);
			}

			return sessionControlOpen
				? await ProcessQueuedJobsAsync(nowUtc, options.ProcessMonitoring, ct).ConfigureAwait(false)
				: 0;
		}
		finally
		{
			_gate.Release();
		}
	}

	/// <summary>Arms fresh PROCESS_NEW alerts that still have no response row. A response row in ANY
	/// state (queued, completed, failed, operator-cancelled) permanently exempts the alert from
	/// automatic arming, so a previously decided alert can never come back to life.</summary>
	private async Task ArmFreshAlertsAsync(DateTime nowUtc, CancellationToken ct)
	{
		DateTime cutoff = nowUtc - ArmLookback;
		await using AuditDbContext db = await _factory.CreateDbContextAsync(ct).ConfigureAwait(false);
		List<Alert> fresh = await db.Alerts.AsNoTracking()
			.Where(a => a.RuleId == KnownProcessStore.ProcessNewRuleId
				&& a.TimeUtc >= cutoff
				&& !db.ProcessAlertResponses.Any(r => r.AlertId == a.Id))
			.OrderBy(a => a.TimeUtc)
			.ThenBy(a => a.Id)
			.Take(MaxArmBatchPerPass)
			.ToListAsync(ct)
			.ConfigureAwait(false);

		foreach (Alert alert in fresh)
		{
			ct.ThrowIfCancellationRequested();
			int sessionId = TryResolveSessionId(alert.Details);
			if (sessionId == NoSession)
			{
				continue;
			}

			KnownProcessStore.AutoCloseArmOutcome outcome = await _store
				.QueueAutoCloseAsync(alert.Id, sessionId, nowUtc, ct)
				.ConfigureAwait(false);
			if (outcome.Armed)
			{
				_logger.LogWarning(
					"Armed auto-close for PROCESS_NEW alert {AlertId} targeting session {SessionId}",
					alert.Id,
					sessionId);
			}
		}
	}

	/// <summary>Drains Queued response rows oldest-first. Each row with a valid target session
	/// costs one rate-limit slot and one real logoff; invalid rows are finalised Failed for free.
	/// When the limit is exhausted the remaining rows stay Queued for the next pass.</summary>
	private async Task<int> ProcessQueuedJobsAsync(
		DateTime nowUtc,
		ProcessMonitoringOptions pm,
		CancellationToken ct)
	{
		List<KnownProcessStore.QueuedAutoCloseJob> jobs = await _store
			.GetQueuedAutoCloseJobsAsync(MaxJobsPerPass, ct)
			.ConfigureAwait(false);
		int finalized = 0;

		foreach (KnownProcessStore.QueuedAutoCloseJob job in jobs)
		{
			ct.ThrowIfCancellationRequested();
			int sessionId = job.Response.SessionId;

			if (!SessionCommandBuilder.ValidateSessionId(sessionId).Ok)
			{
				await _store.FinalizeAutoCloseAsync(
					job.Response.AlertId,
					ProcessAutoCloseStatus.Failed,
					"Automated session close failed: the response has no valid target session id.",
					nowUtc,
					ct).ConfigureAwait(false);
				finalized++;
				LogInvalidSession(job.Response.AlertId);
				continue;
			}

			if (!CanLogoff(pm))
			{
				_logger.LogInformation(
					"{Worker} reached the MaxAutoCloseOperationsPerMinute limit; remaining queued jobs wait for the next pass",
					nameof(ProcessAlertAutoResponder));
				break;
			}

			(ProcessAutoCloseStatus status, string text) = await AttemptLogoffAsync(sessionId, ct).ConfigureAwait(false);
			RecordLogoff();
			await _store.FinalizeAutoCloseAsync(
				job.Response.AlertId,
				status,
				text,
				nowUtc,
				ct).ConfigureAwait(false);
			finalized++;
		}

		return finalized;
	}

	/// <summary>Performs one logoff attempt and maps the outcome onto the persisted final state.
	/// A missing session manager (non-Windows host) fails the job instead of leaving it queued
	/// forever.</summary>
	private async Task<(ProcessAutoCloseStatus Status, string Text)> AttemptLogoffAsync(
		int sessionId,
		CancellationToken ct)
	{
		if (_sessions is null)
		{
			return (ProcessAutoCloseStatus.Failed,
				"Automated session close failed: the RDP session manager is unavailable on this host.");
		}

		try
		{
			SessionActionResult result = await _sessions.LogoffAsync(sessionId, ct).ConfigureAwait(false);
			if (result.Status == IpcResultStatus.Success)
			{
				return (ProcessAutoCloseStatus.Completed,
					string.Format(System.Globalization.CultureInfo.InvariantCulture,
						"Session {0} logged off automatically.", sessionId));
			}

			string detail = string.IsNullOrWhiteSpace(result.Message)
				? "Logoff failed with status " + result.Status + "."
				: result.Message;
			return (ProcessAutoCloseStatus.Failed, ClampText(detail));
		}
		catch (OperationCanceledException) when (ct.IsCancellationRequested)
		{
			throw;
		}
		catch (Exception ex)
		{
			_logger.LogWarning(ex, "Automated logoff failed for session {SessionId}", sessionId);
			return (ProcessAutoCloseStatus.Failed, "Logoff failed: " + ex.GetType().Name);
		}
	}

	private void LogInvalidSession(long alertId)
	{
		_logger.LogWarning(
			"PROCESS_NEW alert {AlertId} has an auto-close response without a valid target session; finalised Failed",
			alertId);
	}

	/// <summary>Tests whether one more logoff may start now given the per-minute cap. Pure state
	/// read - nothing is consumed. The window keys on the whole wall-clock minute.</summary>
	private bool CanLogoff(ProcessMonitoringOptions pm)
	{
		int perMinute = pm.ResolveMaxAutoCloseOperationsPerMinute();
		long currentMinute = _time.GetUtcNow().ToUnixTimeSeconds() / 60;
		lock (_rateGate)
		{
			if (currentMinute != _currentMinute)
			{
				_currentMinute = currentMinute;
				_logoffsInMinute = 0;
			}

			return _logoffsInMinute < perMinute;
		}
	}

	/// <summary>Consumes one logoff slot for the current minute. Must be called only after
	/// <see cref="CanLogoff"/> returned true.</summary>
	private void RecordLogoff()
	{
		long currentMinute = _time.GetUtcNow().ToUnixTimeSeconds() / 60;
		lock (_rateGate)
		{
			if (currentMinute != _currentMinute)
			{
				_currentMinute = currentMinute;
				_logoffsInMinute = 0;
			}

			_logoffsInMinute++;
		}
	}

	/// <summary>Extracts a valid terminal-services session id (0..65535) from the alert's forensic
	/// Details JSON; returns <see cref="NoSession"/> for missing, malformed or out-of-range values.
	/// The Details payload is untrusted persisted data - it can never spawn anything.</summary>
	private static int TryResolveSessionId(string? detailsJson)
	{
		if (string.IsNullOrWhiteSpace(detailsJson))
		{
			return NoSession;
		}

		try
		{
			using JsonDocument doc = JsonDocument.Parse(detailsJson);
			if (doc.RootElement.ValueKind != JsonValueKind.Object
				|| !doc.RootElement.TryGetProperty("sessionId", out JsonElement sessionElement)
				|| !sessionElement.TryGetInt32(out int sessionId))
			{
				return NoSession;
			}

			return SessionCommandBuilder.ValidateSessionId(sessionId).Ok ? sessionId : NoSession;
		}
		catch (JsonException)
		{
			return NoSession;
		}
	}

	/// <summary>Bounds a result text to the ProcessAlertResponses.ResultText column length.</summary>
	private static string ClampText(string text)
	{
		if (text.Length <= MaxResultTextLength)
		{
			return text;
		}

		return text[..MaxResultTextLength];
	}
}
