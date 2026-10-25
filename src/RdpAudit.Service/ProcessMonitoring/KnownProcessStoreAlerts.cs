// File:    src/RdpAudit.Service/ProcessMonitoring/KnownProcessStoreAlerts.cs
// Module:  RdpAudit.Service.ProcessMonitoring
// Purpose: Second concern of the partial KnownProcessStore: the persisted PROCESS_NEW alert
//          reads and the ProcessAlertResponses auto-close lifecycle. Arming is append-only -
//          once a response row exists it is never deleted, only transitioned Queued ->
//          Completed/Failed - so IPC projections reflect the persisted row rather than a
//          boolean edge. The actual logoff attempt happens exclusively in
//          ProcessAlertAutoResponder via RdpSessionManager; this store never performs
//          session operations.
// Extends: KnownProcessStore (partial)
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using Microsoft.EntityFrameworkCore;
using RdpAudit.Core.Data;
using RdpAudit.Core.Models;
using RdpAudit.Core.ProcessMonitoring;

namespace RdpAudit.Service.ProcessMonitoring;

/// <summary>Alert-read and auto-close-lifecycle concern of the process-monitoring store.</summary>
public sealed partial class KnownProcessStore
{
	/// <summary>Outcome of an attempt to arm the automated session close for one alert.</summary>
	public sealed record AutoCloseArmOutcome(
		bool Armed,
		bool AlertFound,
		bool AlreadyQueuedOrFinal);

	/// <summary>Outcome of an attempt to cancel a still-queued automated session close.</summary>
	public sealed record AutoCloseCancelOutcome(
		bool Cancelled,
		bool AlertFound,
		bool WasFinal);

	/// <summary>One PROCESS_NEW alert together with its persisted response row (when present).</summary>
	public sealed record ProcessAlertRow(Alert Alert, ProcessAlertResponse? Response);

	/// <summary>One queued auto-close job for the responder: the response row plus its alert.</summary>
	public sealed record QueuedAutoCloseJob(ProcessAlertResponse Response, Alert Alert);

	/// <summary>Reads one PROCESS_NEW alert and its response row by alert id. Returns null for
	/// unknown ids and for alerts whose RuleId is not PROCESS_NEW (fail-closed projection).</summary>
	public async Task<ProcessAlertRow?> GetProcessAlertAsync(long alertId, CancellationToken ct = default)
	{
		await using AuditDbContext db = await _factory.CreateDbContextAsync(ct).ConfigureAwait(false);
		Alert? alert = await db.Alerts.AsNoTracking()
			.FirstOrDefaultAsync(a => a.Id == alertId && a.RuleId == ProcessNewRuleId, ct)
			.ConfigureAwait(false);
		if (alert is null)
		{
			return null;
		}

		ProcessAlertResponse? response = await db.ProcessAlertResponses.AsNoTracking()
			.FirstOrDefaultAsync(r => r.AlertId == alertId, ct)
			.ConfigureAwait(false);
		return new ProcessAlertRow(alert, response);
	}

	/// <summary>Lists PROCESS_NEW alerts newest-first, bounded by the clamped limit. Returns the
	/// total matching rows before the limit and the page rows together with their response state.</summary>
	public async Task<(int Total, List<ProcessAlertRow> Rows)> ListProcessAlertsAsync(
		int limit,
		CancellationToken ct = default)
	{
		int effective = limit <= 0 ? DefaultListLimit : Math.Min(limit, MaxListLimit);
		await using AuditDbContext db = await _factory.CreateDbContextAsync(ct).ConfigureAwait(false);

		int total = await db.Alerts.AsNoTracking()
			.CountAsync(a => a.RuleId == ProcessNewRuleId, ct)
			.ConfigureAwait(false);

		List<Alert> alerts = await db.Alerts.AsNoTracking()
			.Where(a => a.RuleId == ProcessNewRuleId)
			.OrderByDescending(a => a.TimeUtc)
			.ThenByDescending(a => a.Id)
			.Take(effective)
			.ToListAsync(ct)
			.ConfigureAwait(false);

		if (alerts.Count == 0)
		{
			return (total, new List<ProcessAlertRow>());
		}

		long[] ids = alerts.Select(a => a.Id).ToArray();
		Dictionary<long, ProcessAlertResponse> responses = await db.ProcessAlertResponses.AsNoTracking()
			.Where(r => ids.Contains(r.AlertId))
			.ToDictionaryAsync(r => r.AlertId, ct)
			.ConfigureAwait(false);

		List<ProcessAlertRow> rows = new(alerts.Count);
		foreach (Alert alert in alerts)
		{
			responses.TryGetValue(alert.Id, out ProcessAlertResponse? response);
			rows.Add(new ProcessAlertRow(alert, response));
		}

		return (total, rows);
	}

	/// <summary>Reads the persisted response row for one alert; null when none exists.</summary>
	public async Task<ProcessAlertResponse?> GetResponseAsync(long alertId, CancellationToken ct = default)
	{
		await using AuditDbContext db = await _factory.CreateDbContextAsync(ct).ConfigureAwait(false);
		return await db.ProcessAlertResponses.AsNoTracking()
			.FirstOrDefaultAsync(r => r.AlertId == alertId, ct)
			.ConfigureAwait(false);
	}

	/// <summary>Arms the automated session close for a PROCESS_NEW alert by creating a Queued
	/// response row. Append-only: a row already existing (queued or in a final state) is never
	/// replaced, so a completed or failed attempt can never be re-queued.</summary>
	public async Task<AutoCloseArmOutcome> QueueAutoCloseAsync(
		long alertId,
		int sessionId,
		DateTime requestedAtUtc,
		CancellationToken ct = default)
	{
		await using AuditDbContext db = await _factory.CreateDbContextAsync(ct).ConfigureAwait(false);

		bool alertFound = await db.Alerts.AsNoTracking()
			.AnyAsync(a => a.Id == alertId && a.RuleId == ProcessNewRuleId, ct)
			.ConfigureAwait(false);
		if (!alertFound)
		{
			return new AutoCloseArmOutcome(false, false, false);
		}

		bool exists = await db.ProcessAlertResponses
			.AnyAsync(r => r.AlertId == alertId, ct)
			.ConfigureAwait(false);
		if (exists)
		{
			return new AutoCloseArmOutcome(false, true, true);
		}

		ProcessAlertResponse row = new()
		{
			AlertId = alertId,
			SessionId = sessionId,
			Status = (int)ProcessAutoCloseStatus.Queued,
			RequestedAtUtc = requestedAtUtc,
			CompletedAtUtc = null,
		};
		db.ProcessAlertResponses.Add(row);
		await db.SaveChangesAsync(ct).ConfigureAwait(false);
		return new AutoCloseArmOutcome(true, true, false);
	}

	/// <summary>Cancels a still-queued auto-close response (operator action), transitioning it
	/// to Failed with a cancellation note. A response already in a final state is left untouched.</summary>
	public async Task<AutoCloseCancelOutcome> CancelAutoCloseAsync(
		long alertId,
		DateTime cancelledAtUtc,
		string? reason,
		CancellationToken ct = default)
	{
		await using AuditDbContext db = await _factory.CreateDbContextAsync(ct).ConfigureAwait(false);

		bool alertFound = await db.Alerts.AsNoTracking()
			.AnyAsync(a => a.Id == alertId && a.RuleId == ProcessNewRuleId, ct)
			.ConfigureAwait(false);
		if (!alertFound)
		{
			return new AutoCloseCancelOutcome(false, false, false);
		}

		ProcessAlertResponse? row = await db.ProcessAlertResponses
			.FirstOrDefaultAsync(r => r.AlertId == alertId, ct)
			.ConfigureAwait(false);
		if (row is null || row.Status != (int)ProcessAutoCloseStatus.Queued)
		{
			return new AutoCloseCancelOutcome(false, true, true);
		}

		row.Status = (int)ProcessAutoCloseStatus.Failed;
		row.ResultText = string.IsNullOrWhiteSpace(reason)
			? "Cancelled by operator."
			: "Cancelled by operator: " + reason.Trim();
		row.CompletedAtUtc = cancelledAtUtc;
		await db.SaveChangesAsync(ct).ConfigureAwait(false);
		return new AutoCloseCancelOutcome(true, true, false);
	}

	/// <summary>Reads up to <paramref name="max"/> queued auto-close jobs oldest-first, each with
	/// its PROCESS_NEW alert for the responder. Never touches session operations.</summary>
	public async Task<List<QueuedAutoCloseJob>> GetQueuedAutoCloseJobsAsync(
		int max,
		CancellationToken ct = default)
	{
		int effective = Math.Clamp(max, 1, MaxListLimit);
		await using AuditDbContext db = await _factory.CreateDbContextAsync(ct).ConfigureAwait(false);

		List<ProcessAlertResponse> queued = await db.ProcessAlertResponses.AsNoTracking()
			.Where(r => r.Status == (int)ProcessAutoCloseStatus.Queued)
			.OrderBy(r => r.RequestedAtUtc)
			.ThenBy(r => r.AlertId)
			.Take(effective)
			.ToListAsync(ct)
			.ConfigureAwait(false);

		if (queued.Count == 0)
		{
			return new List<QueuedAutoCloseJob>();
		}

		long[] alertIds = queued.Select(r => r.AlertId).ToArray();
		Dictionary<long, Alert> alerts = await db.Alerts.AsNoTracking()
			.Where(a => alertIds.Contains(a.Id))
			.ToDictionaryAsync(a => a.Id, ct)
			.ConfigureAwait(false);

		List<QueuedAutoCloseJob> jobs = new(queued.Count);
		foreach (ProcessAlertResponse response in queued)
		{
			if (!alerts.TryGetValue(response.AlertId, out Alert? alert))
			{
				continue;
			}

			jobs.Add(new QueuedAutoCloseJob(response, alert));
		}

		return jobs;
	}

	/// <summary>Finalizes one queued response with the logoff attempt's outcome. Only a Queued
	/// row is transitioned; an already-final row is left untouched (exactly one attempt per
	/// alert, first completion wins). Returns true when this call performed the transition.</summary>
	public async Task<bool> FinalizeAutoCloseAsync(
		long alertId,
		ProcessAutoCloseStatus status,
		string? resultText,
		DateTime completedAtUtc,
		CancellationToken ct = default)
	{
		if (status == ProcessAutoCloseStatus.Queued)
		{
			throw new ArgumentException("A finalization cannot leave a response Queued.", nameof(status));
		}

		await using AuditDbContext db = await _factory.CreateDbContextAsync(ct).ConfigureAwait(false);
		ProcessAlertResponse? row = await db.ProcessAlertResponses
			.FirstOrDefaultAsync(r => r.AlertId == alertId, ct)
			.ConfigureAwait(false);
		if (row is null || row.Status != (int)ProcessAutoCloseStatus.Queued)
		{
			return false;
		}

		row.Status = (int)status;
		row.ResultText = resultText;
		row.CompletedAtUtc = completedAtUtc;
		await db.SaveChangesAsync(ct).ConfigureAwait(false);
		return true;
	}
}
