// File:    src/RdpAudit.Service/Alerts/TaskModifiedRule.cs
// Module:  RdpAudit.Service.Alerts
// Purpose: Flags Event 4702 (scheduled task updated) — possible re-purposing of an existing task.
// Extends: RdpAudit.Core.Events.AlertRuleBase
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using RdpAudit.Core.Config;
using RdpAudit.Core.Events;
using RdpAudit.Core.Models;

namespace RdpAudit.Service.Alerts;

/// <summary>Flags Event 4702 — scheduled task updated.</summary>
public sealed class TaskModifiedRule : AlertRuleBase
{
	public override string RuleId => "TASK_MODIFIED";

	public override string Name => "Scheduled Task Modified";

	public override AlertSeverity Severity => AlertSeverity.Medium;

	public override bool IsEnabled(RdpAuditOptions options) => options.Monitoring.TrackScheduledTasks;

	public override Task<Alert?> EvaluateAsync(RawEvent evt, IAlertContext ctx, CancellationToken ct)
	{
		if (evt.EventId != 4702)
		{
			return Task.FromResult<Alert?>(null);
		}

		return Task.FromResult<Alert?>(CreateAlert(evt,
			$"Scheduled task updated by {evt.UserName}",
			new { Mitre = "T1053" }));
	}
}
