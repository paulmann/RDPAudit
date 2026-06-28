// File:    src/RdpAudit.Service/Alerts/TaskPersistenceRule.cs
// Module:  RdpAudit.Service.Alerts
// Purpose: Flags Event 4698 (scheduled task created) — common persistence vector (T1053).
// Extends: RdpAudit.Core.Events.AlertRuleBase
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using RdpAudit.Core.Config;
using RdpAudit.Core.Events;
using RdpAudit.Core.Models;

namespace RdpAudit.Service.Alerts;

/// <summary>Flags Event 4698 — scheduled task created (persistence).</summary>
public sealed class TaskPersistenceRule : AlertRuleBase
{
	public override string RuleId => "TASK_PERSISTENCE";

	public override string Name => "Scheduled Task Created (Persistence)";

	public override AlertSeverity Severity => AlertSeverity.High;

	public override bool IsEnabled(RdpAuditOptions options) => options.Monitoring.TrackScheduledTasks;

	public override Task<Alert?> EvaluateAsync(RawEvent evt, IAlertContext ctx, CancellationToken ct)
	{
		if (evt.EventId != 4698)
		{
			return Task.FromResult<Alert?>(null);
		}

		return Task.FromResult<Alert?>(CreateAlert(evt,
			$"Scheduled task created by {evt.UserName}",
			new { Mitre = "T1053" }));
	}
}
