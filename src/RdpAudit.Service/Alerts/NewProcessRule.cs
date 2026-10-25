// File:    src/RdpAudit.Service/Alerts/NewProcessRule.cs
// Module:  RdpAudit.Service.Alerts
// Purpose: PROCESS_NEW detection: flags a Windows Security 4688 process-creation event whose
//          normalized identity (ProcessName, UserCategory, UserName) has never been observed,
//          or was last observed before the configured alert window. Every 4688 candidate is
//          recorded in the persistent KnownProcesses baseline / ProcessObservations journal
//          (via KnownProcessStore) after evaluation, so the baseline grows monotonically.
//          System-account processes can be silenced with ProcessMonitoring.EnableAlertOnSystemProcesses
//          (their observations are still recorded). Enabled gating: ProcessMonitoring.Enabled.
// Extends: RdpAudit.Core.Events.AlertRuleBase
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using RdpAudit.Core.Config;
using RdpAudit.Core.Events;
using RdpAudit.Core.Models;
using RdpAudit.Core.ProcessMonitoring;
using RdpAudit.Service.ProcessMonitoring;

namespace RdpAudit.Service.Alerts;

/// <summary>Flags process-creation events whose identity is new relative to the persistent baseline.</summary>
public sealed class NewProcessRule : AlertRuleBase
{
	private readonly KnownProcessStore _store;

	public NewProcessRule(KnownProcessStore store)
	{
		ArgumentNullException.ThrowIfNull(store);
		_store = store;
	}

	public override string RuleId => KnownProcessStore.ProcessNewRuleId;

	public override string Name => "New Process Detected";

	public override AlertSeverity Severity => AlertSeverity.High;

	public override bool IsEnabled(RdpAuditOptions options) => options.ProcessMonitoring.Enabled;

	public override async Task<Alert?> EvaluateAsync(RawEvent evt, IAlertContext ctx, CancellationToken ct)
	{
		ArgumentNullException.ThrowIfNull(evt);
		ArgumentNullException.ThrowIfNull(ctx);

		if (evt.EventId != 4688)
		{
			return null;
		}

		KnownProcessKey key = KnownProcessKey.Build(evt.ProcessName, evt.UserName, evt.Domain);
		if (key.IsEmpty)
		{
			return null;
		}

		ProcessMonitoringOptions options = ctx.Options.ProcessMonitoring;
		if (!options.Enabled)
		{
			return null;
		}

		int alertWindowDays = options.ResolveAlertWindowDays();
		DateTime cutoff = evt.TimeUtc.AddDays(-alertWindowDays);

		KnownProcess? baseline = await _store.FindAsync(key, ct).ConfigureAwait(false);

		bool isSystem = key.UserCategory == ProcessUserCategory.System;
		bool isNew = baseline is null || baseline.LastObservedUtc < cutoff;
		bool willAlert = isNew && (!isSystem || options.EnableAlertOnSystemProcesses);

		// Record the observation regardless of the alert decision, so the baseline never
		// misses evidence from a silenced category. The journal's Alerted flag reflects
		// whether an Alert row will actually be raised for this observation.
		await _store.RecordObservationAsync(
			key,
			evt.TimeUtc,
			evt.SessionId,
			evt.Id,
			willAlert,
			false,
			options.ResolveMaxObservations(),
			ct)
			.ConfigureAwait(false);

		if (!isNew)
		{
			return null;
		}

		if (isSystem && !options.EnableAlertOnSystemProcesses)
		{
			return null;
		}

		DateTime firstObservedUtc = baseline?.FirstObservedUtc ?? evt.TimeUtc;
		return CreateAlert(
			evt,
			$"New process detected: {key.ProcessName} by {evt.UserName ?? "SYSTEM"}",
			new
			{
				ProcessName = key.ProcessName,
				SessionId = evt.SessionId,
				FirstObservedUtc = firstObservedUtc,
				AlertWindowDays = alertWindowDays,
			});
	}
}
