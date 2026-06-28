// File:    src/RdpAudit.Service/Alerts/NewAccountRule.cs
// Module:  RdpAudit.Service.Alerts
// Purpose: Flags Event 4720 — user account created (T1136).
// Extends: RdpAudit.Core.Events.AlertRuleBase
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using RdpAudit.Core.Config;
using RdpAudit.Core.Events;
using RdpAudit.Core.Models;

namespace RdpAudit.Service.Alerts;

/// <summary>Flags Event 4720 — user account created.</summary>
public sealed class NewAccountRule : AlertRuleBase
{
	public override string RuleId => "NEW_ACCOUNT";

	public override string Name => "New User Account Created";

	public override AlertSeverity Severity => AlertSeverity.High;

	public override bool IsEnabled(RdpAuditOptions options) => options.Monitoring.TrackAccountChanges;

	public override Task<Alert?> EvaluateAsync(RawEvent evt, IAlertContext ctx, CancellationToken ct)
	{
		if (evt.EventId != 4720)
		{
			return Task.FromResult<Alert?>(null);
		}

		return Task.FromResult<Alert?>(CreateAlert(evt,
			$"New user account created: {evt.UserName} (by {evt.Domain})",
			new { Mitre = "T1136" }));
	}
}
