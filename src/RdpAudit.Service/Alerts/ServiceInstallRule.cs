// File:    src/RdpAudit.Service/Alerts/ServiceInstallRule.cs
// Module:  RdpAudit.Service.Alerts
// Purpose: Flags Event 4697 — new service installed (T1543).
// Extends: RdpAudit.Core.Events.AlertRuleBase
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using RdpAudit.Core.Events;
using RdpAudit.Core.Models;

namespace RdpAudit.Service.Alerts;

/// <summary>Flags Event 4697 — new service installed.</summary>
public sealed class ServiceInstallRule : AlertRuleBase
{
	public override string RuleId => "SERVICE_INSTALL";

	public override string Name => "Service Installed";

	public override AlertSeverity Severity => AlertSeverity.High;

	public override Task<Alert?> EvaluateAsync(RawEvent evt, IAlertContext ctx, CancellationToken ct)
	{
		if (evt.EventId != 4697)
		{
			return Task.FromResult<Alert?>(null);
		}

		return Task.FromResult<Alert?>(CreateAlert(evt,
			$"New service installed by {evt.UserName}",
			new { Mitre = "T1543" }));
	}
}
