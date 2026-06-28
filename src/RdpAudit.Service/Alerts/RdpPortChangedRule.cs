// File:    src/RdpAudit.Service/Alerts/RdpPortChangedRule.cs
// Module:  RdpAudit.Service.Alerts
// Purpose: Detects modification of the Terminal Server RDP-Tcp PortNumber registry value.
// Extends: RdpAudit.Core.Events.AlertRuleBase
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using RdpAudit.Core.Events;
using RdpAudit.Core.Models;

namespace RdpAudit.Service.Alerts;

/// <summary>Detects modification of the Terminal Server RDP-Tcp PortNumber registry value.</summary>
public sealed class RdpPortChangedRule : AlertRuleBase
{
	public override string RuleId => "RDP_PORT_CHANGED";

	public override string Name => "RDP Listener Port Changed";

	public override AlertSeverity Severity => AlertSeverity.Critical;

	public override Task<Alert?> EvaluateAsync(RawEvent evt, IAlertContext ctx, CancellationToken ct)
	{
		if (evt.EventId != 4657 || evt.ObjectName is null)
		{
			return Task.FromResult<Alert?>(null);
		}

		string lower = evt.ObjectName.ToLowerInvariant();
		bool match = lower.Contains("terminal server\\winstations\\rdp-tcp", StringComparison.Ordinal)
			&& lower.Contains("portnumber", StringComparison.Ordinal);
		if (!match)
		{
			return Task.FromResult<Alert?>(null);
		}

		return Task.FromResult<Alert?>(CreateAlert(evt,
			$"RDP listener PortNumber registry value modified by {evt.UserName}",
			new { Path = evt.ObjectName, Mitre = "T1572" }));
	}
}
