// File:    src/RdpAudit.Service/Ipc/IpcDispatcher.ProcessMonitoring.cs
// Module:  RdpAudit.Service.Ipc
// Purpose: IPC handlers for the process-monitoring commands (ordinals 73..77): forced operator
//          observations, PROCESS_NEW alert listing/details, operator-managed auto-close state and
//          subsystem status. Session-control operations here are QUEUE/state changes only - the
//          actual logoff stays in ProcessAlertAutoResponder. MessagePack DTO keys are append-only.
// Extends: IpcDispatcher (partial)
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System.Linq;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using RdpAudit.Core.Config;
using RdpAudit.Core.Data;
using RdpAudit.Core.Ipc;
using RdpAudit.Core.Ipc.Contracts;
using RdpAudit.Core.Models;
using RdpAudit.Core.ProcessMonitoring;
using RdpAudit.Core.Util;
using RdpAudit.Service.ProcessMonitoring;

namespace RdpAudit.Service.Ipc;

/// <summary>Process-monitoring IPC handlers of the dispatcher.</summary>
public sealed partial class IpcDispatcher
{
	/// <summary>Parsed view of the identity fields carried by an Alert Details JSON document.</summary>
	private readonly record struct AlertDetailsView(
		string ProcessName,
		int? SessionId,
		DateTime FirstObservedUtc,
		int AlertWindowDays);

	private static T ParsePayload<T>(string? payload, string command)
		where T : class
	{
		try
		{
			return JsonSerializer.Deserialize<T>(payload ?? string.Empty, JsonOptions.Default)
				?? throw new IpcException(command + " payload is required.");
		}
		catch (JsonException ex)
		{
			throw new IpcException(command + " payload is not valid JSON: " + ex.Message, ex);
		}
	}

	/// <summary>Reads the identity fields NewProcessRule / ReportProcessObservation serialize into
	/// an alert's Details JSON. Never throws: malformed details degrade to safe defaults.</summary>
	private static AlertDetailsView ReadDetails(Alert alert)
	{
		string detailJson = alert.Details ?? string.Empty;
		AlertDetailsView fallback = new(string.Empty, null, alert.TimeUtc, 0);
		if (detailJson.Length == 0)
		{
			return fallback;
		}

		try
		{
			using JsonDocument doc = JsonDocument.Parse(detailJson);
			if (doc.RootElement.ValueKind != JsonValueKind.Object)
			{
				return fallback;
			}

			JsonElement root = doc.RootElement;
			string processName = root.TryGetProperty("processName", out JsonElement pn) && pn.ValueKind == JsonValueKind.String
				? pn.GetString() ?? string.Empty
				: string.Empty;
			int? sessionId = root.TryGetProperty("sessionId", out JsonElement sid)
				&& sid.ValueKind == JsonValueKind.Number
				&& sid.TryGetInt32(out int sidValue)
				? sidValue
				: null;
			DateTime firstObserved = root.TryGetProperty("firstObservedUtc", out JsonElement fo)
				&& fo.ValueKind == JsonValueKind.String
				&& fo.TryGetDateTime(out DateTime foValue)
				? foValue
				: alert.TimeUtc;
			int alertWindowDays = root.TryGetProperty("alertWindowDays", out JsonElement awd)
				&& awd.ValueKind == JsonValueKind.Number
				&& awd.TryGetInt32(out int awdValue)
				? awdValue
				: 0;
			return new AlertDetailsView(processName, sessionId, firstObserved, alertWindowDays);
		}
		catch (JsonException)
		{
			return fallback;
		}
	}

	private static ProcessAlertDto ToAlertDto(Alert alert, ProcessAlertResponse? response)
	{
		AlertDetailsView details = ReadDetails(alert);
		return new ProcessAlertDto
		{
			Id = alert.Id,
			RuleId = alert.RuleId,
			Severity = alert.Severity,
			TimeUtc = alert.TimeUtc,
			SourceIp = alert.SourceIp,
			UserName = alert.UserName,
			ProcessName = details.ProcessName,
			SessionId = details.SessionId,
			FirstObservedUtc = details.FirstObservedUtc,
			AlertWindowDays = details.AlertWindowDays,
			AutoCloseEnabled = response is not null && response.Status == (int)ProcessAutoCloseStatus.Queued,
			Acknowledged = alert.Acknowledged,
		};
	}

	private static ProcessAlertResponseDto? ToResponseDto(ProcessAlertResponse? response) => response is null
		? null
		: new ProcessAlertResponseDto
		{
			HasResponse = true,
			SessionId = response.SessionId,
			Status = response.Status,
			ResultText = response.ResultText,
			RequestedAtUtc = response.RequestedAtUtc,
			CompletedAtUtc = response.CompletedAtUtc,
		};

	/// <summary>Ordinal 73: forces one process identity through the same baseline evaluation
	/// NewProcessRule uses, records a bounded journal row and optionally arms auto-close.</summary>
	private async Task<ProcessObservationResult> ReportProcessObservationAsync(string? payload, CancellationToken ct)
	{
		ProcessObservationResult result = new();
		if (_processStore is null)
		{
			result.Status = IpcResultStatus.Unavailable;
			result.Message = "Process-monitoring store is not composed on this host.";
			return result;
		}

		ProcessObservationRequest req = ParsePayload<ProcessObservationRequest>(payload, "ReportProcessObservation");
		ProcessMonitoringOptions options = _options.CurrentValue.ProcessMonitoring;
		if (!options.Enabled)
		{
			result.Status = IpcResultStatus.Refused;
			result.Message = "Process monitoring is disabled.";
			return result;
		}

		KnownProcessKey key = KnownProcessKey.Build(req.ProcessName, req.UserName, req.Domain);
		if (key.IsEmpty)
		{
			result.Status = IpcResultStatus.InvalidRequest;
			result.Message = "A usable process name is required.";
			return result;
		}

		if (req.SessionId < -1 || req.SessionId > ushort.MaxValue)
		{
			result.Status = IpcResultStatus.InvalidRequest;
			result.Message = "SessionId must be -1 or a valid terminal-services session id.";
			return result;
		}

		if (req.AutoClose && req.SessionId < 0)
		{
			result.Status = IpcResultStatus.InvalidRequest;
			result.Message = "AutoClose requires a valid target session id.";
			return result;
		}

		if (req.AutoClose && (!_options.CurrentValue.SessionControl.Enabled || !_options.CurrentValue.SessionControl.AllowLogoff))
		{
			result.Status = IpcResultStatus.Refused;
			result.Message = "Session logoff is disabled by policy - the requested auto-close was refused.";
			return result;
		}

		DateTime nowUtc = DateTime.UtcNow;
		int alertWindowDays = options.ResolveAlertWindowDays();
		DateTime cutoff = nowUtc.AddDays(-alertWindowDays);
		KnownProcess? baseline = await _processStore.FindAsync(key, ct).ConfigureAwait(false);

		bool isSystem = key.UserCategory == ProcessUserCategory.System;
		bool isNew = baseline is null || baseline.LastObservedUtc < cutoff;
		bool willAlert = isNew && (!isSystem || options.EnableAlertOnSystemProcesses);

		long recordingId = await _processStore.RecordObservationAsync(
			key,
			nowUtc,
			req.SessionId,
			0,
			willAlert,
			true,
			options.ResolveMaxObservations(),
			ct)
			.ConfigureAwait(false);

		result.IsAlreadyKnown = baseline is not null;
		result.IsNew = isNew;
		result.RecordingId = recordingId;
		if (!willAlert)
		{
			return result;
		}

		DateTime firstObservedUtc = baseline?.FirstObservedUtc ?? nowUtc;
		string detailsJson = JsonSerializer.Serialize(new
		{
			ProcessName = key.ProcessName,
			SessionId = req.SessionId,
			FirstObservedUtc = firstObservedUtc,
			AlertWindowDays = alertWindowDays,
		}, JsonOptions.Default);

		Alert alert = new()
		{
			RuleId = KnownProcessStore.ProcessNewRuleId,
			Severity = AlertSeverity.High,
			TimeUtc = nowUtc,
			SourceIp = null,
			UserName = req.UserName,
			Message = "New process detected (operator observation): " + key.ProcessName + " by " + (req.UserName ?? "SYSTEM"),
			Details = detailsJson,
			TriggerEventId = 0,
		};

		await using (AuditDbContext db = await _factory.CreateDbContextAsync(ct).ConfigureAwait(false))
		{
			db.Alerts.Add(alert);
			await db.SaveChangesAsync(ct).ConfigureAwait(false);
		}

		_metrics.IncrementAlert();
		_logger.LogWarning(
			"Alert {RuleId} severity={Severity} user={UserName} message={Message}",
			alert.RuleId,
			alert.Severity,
			alert.UserName,
			alert.Message);
		result.Alert = ToAlertDto(alert, null);

		if (req.AutoClose)
		{
			KnownProcessStore.AutoCloseArmOutcome arm = await _processStore
				.QueueAutoCloseAsync(alert.Id, req.SessionId, nowUtc, ct)
				.ConfigureAwait(false);
			result.AutoCloseQueued = arm.Armed;
			if (!arm.Armed)
			{
				result.Message = "An automated response already exists for this alert.";
			}
			else
			{
				KnownProcessStore.ProcessAlertRow? armedRow = await _processStore
					.GetProcessAlertAsync(alert.Id, ct)
					.ConfigureAwait(false);
				if (armedRow is not null)
				{
					result.Alert = ToAlertDto(armedRow.Alert, armedRow.Response);
				}
			}
		}

		return result;
	}

	/// <summary>Ordinal 74: newest-first list of PROCESS_NEW alert projections (bounded).</summary>
	private async Task<ProcessAlertListDto> ListProcessAlertsAsync(string? payload, CancellationToken ct)
	{
		ProcessAlertListDto dto = new();
		if (_processStore is null)
		{
			dto.Status = IpcResultStatus.Unavailable;
			dto.Message = "Process-monitoring store is not composed on this host.";
			return dto;
		}

		ListProcessAlertsRequest req = ParsePayload<ListProcessAlertsRequest>(payload, "ListProcessAlerts");
		(int total, List<KnownProcessStore.ProcessAlertRow> rows) = await _processStore
			.ListProcessAlertsAsync(req.Limit, ct)
			.ConfigureAwait(false);

		dto.Total = total;
		foreach (KnownProcessStore.ProcessAlertRow row in rows)
		{
			dto.Items.Add(ToAlertDto(row.Alert, row.Response));
		}

		return dto;
	}

	/// <summary>Ordinal 75: one PROCESS_NEW alert with its raw Details JSON and response state.</summary>
	private async Task<ProcessAlertDetailsDto> GetProcessAlertDetailsAsync(string? payload, CancellationToken ct)
	{
		ProcessAlertDetailsDto dto = new();
		if (_processStore is null)
		{
			dto.Status = IpcResultStatus.Unavailable;
			dto.Message = "Process-monitoring store is not composed on this host.";
			return dto;
		}

		GetProcessAlertDetailsRequest req = ParsePayload<GetProcessAlertDetailsRequest>(payload, "GetProcessAlertDetails");
		if (req.AlertId <= 0)
		{
			dto.Status = IpcResultStatus.InvalidRequest;
			dto.Message = "AlertId must be a positive alert id.";
			return dto;
		}

		KnownProcessStore.ProcessAlertRow? row = await _processStore
			.GetProcessAlertAsync(req.AlertId, ct)
			.ConfigureAwait(false);
		if (row is null)
		{
			dto.Status = IpcResultStatus.NotFound;
			dto.Message = "PROCESS_NEW alert " + req.AlertId + " was not found.";
			return dto;
		}

		dto.Alert = ToAlertDto(row.Alert, row.Response);
		dto.DetailsJson = row.Alert.Details;
		dto.Response = ToResponseDto(row.Response);
		return dto;
	}

	/// <summary>Ordinal 76: arms or cancels the automated session close for one alert.
	/// Arming is append-only; a final response state can never be re-queued.</summary>
	private async Task<ProcessAutoCloseActionResult> SetProcessAutoCloseAsync(string? payload, CancellationToken ct)
	{
		ProcessAutoCloseActionResult result = new();
		if (_processStore is null)
		{
			result.Status = IpcResultStatus.Unavailable;
			result.Message = "Process-monitoring store is not composed on this host.";
			return result;
		}

		SetProcessAutoCloseRequest req = ParsePayload<SetProcessAutoCloseRequest>(payload, "SetProcessAutoClose");
		if (req.AlertId <= 0)
		{
			result.Status = IpcResultStatus.InvalidRequest;
			result.Message = "AlertId must be a positive alert id.";
			return result;
		}

		if (!_options.CurrentValue.SessionControl.Enabled || !_options.CurrentValue.SessionControl.AllowLogoff)
		{
			result.Status = IpcResultStatus.Refused;
			result.Message = "Session logoff is disabled by policy.";
			return result;
		}

		KnownProcessStore.ProcessAlertRow? current = await _processStore
			.GetProcessAlertAsync(req.AlertId, ct)
			.ConfigureAwait(false);
		if (current is null)
		{
			result.Status = IpcResultStatus.NotFound;
			result.Message = "PROCESS_NEW alert " + req.AlertId + " was not found.";
			return result;
		}

		DateTime nowUtc = DateTime.UtcNow;
		if (req.Enabled)
		{
			AlertDetailsView details = ReadDetails(current.Alert);
			if (details.SessionId is not int sessionId || sessionId < 0)
			{
				result.Status = IpcResultStatus.Refused;
				result.Message = "The alert carries no target session - auto-close cannot be armed.";
				return result;
			}

			KnownProcessStore.AutoCloseArmOutcome arm = await _processStore
				.QueueAutoCloseAsync(req.AlertId, sessionId, nowUtc, ct)
				.ConfigureAwait(false);
			if (!arm.Armed)
			{
				result.Status = IpcResultStatus.Refused;
				result.Message = arm.AlreadyQueuedOrFinal
					? "An automated response already exists for this alert and cannot be re-armed."
					: "Automated response could not be queued for this alert.";
			}
			else
			{
				LogOperation(OperationLogSeverity.Information, "ProcessAutoCloseArm",
					"Automated session close armed for PROCESS_NEW alert " + req.AlertId + " (session " + sessionId + ").");
			}
		}
		else if (current.Response is null)
		{
			result.Status = IpcResultStatus.Refused;
			result.Message = "No automated response is armed for this alert.";
			return result;
		}
		else if (current.Response.Status != (int)ProcessAutoCloseStatus.Queued)
		{
			result.Status = IpcResultStatus.Refused;
			result.Message = "The automated response has already finished and can no longer be cancelled.";
			return result;
		}
		else
		{
			KnownProcessStore.AutoCloseCancelOutcome cancel = await _processStore
				.CancelAutoCloseAsync(req.AlertId, nowUtc, req.Reason, ct)
				.ConfigureAwait(false);
			if (cancel.Cancelled)
			{
				LogOperation(OperationLogSeverity.Information, "ProcessAutoCloseCancel",
					"Automated session close cancelled for PROCESS_NEW alert " + req.AlertId + ".",
					JsonSerializer.Serialize(new { AlertId = req.AlertId, Reason = req.Reason }, JsonOptions.Default));
			}
			else if (!cancel.AlertFound)
			{
				result.Status = IpcResultStatus.NotFound;
				result.Message = "PROCESS_NEW alert " + req.AlertId + " was not found.";
				return result;
			}
			else if (cancel.WasFinal)
			{
				result.Status = IpcResultStatus.Refused;
				result.Message = "The automated response has already finished and can no longer be cancelled.";
			}
		}

		KnownProcessStore.ProcessAlertRow? refreshed = await _processStore
			.GetProcessAlertAsync(req.AlertId, ct)
			.ConfigureAwait(false);
		if (refreshed is not null)
		{
			result.Alert = ToAlertDto(refreshed.Alert, refreshed.Response);
			result.Response = ToResponseDto(refreshed.Response);
		}

		return result;
	}

	/// <summary>Ordinal 77: effective process-monitoring configuration plus persisted counters.</summary>
	private async Task<ProcessMonitoringStatusDto> GetProcessMonitoringStatusAsync(CancellationToken ct)
	{
		ProcessMonitoringStatusDto dto = new();
		if (_processStore is null)
		{
			dto.Status = IpcResultStatus.Unavailable;
			dto.Message = "Process-monitoring store is not composed on this host.";
			return dto;
		}

		ProcessMonitoringOptions options = _options.CurrentValue.ProcessMonitoring;
		KnownProcessStore.ProcessMonitoringCounts counts = await _processStore
			.GetStatusCountsAsync(ct)
			.ConfigureAwait(false);

		dto.Enabled = options.Enabled;
		dto.BaselineWindowsDays = options.ResolveBaselineWindowsDays().ToList();
		dto.AlertWindowDays = options.ResolveAlertWindowDays();
		dto.AutoCloseSessionDefault = options.AutoCloseSessionOnNewProcess;
		dto.EnableAlertOnSystemProcesses = options.EnableAlertOnSystemProcesses;
		dto.KnownProcessCount = counts.KnownProcessCount;
		dto.AlertsSinceStart = counts.AlertsTotal;
		dto.AutoCloseLogoffPending = counts.AutoClosePending;
		dto.AutoCloseLogoffCompleted = counts.AutoCloseCompleted;
		dto.AutoCloseLogoffFailed = counts.AutoCloseFailed;
		dto.LastAutoCloseUtc = counts.LastAutoCloseUtc;
		dto.ObservationCount = counts.ObservationCount;
		return dto;
	}
}
