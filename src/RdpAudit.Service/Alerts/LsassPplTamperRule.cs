// File:    src/RdpAudit.Service/Alerts/LsassPplTamperRule.cs
// Module:  RdpAudit.Service.Alerts
// Purpose: Detects modification of the LSA RunAsPPL registry value (T1003 PPL bypass).
// Extends: RdpAudit.Core.Events.AlertRuleBase
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using RdpAudit.Core.Events;
using RdpAudit.Core.Models;

namespace RdpAudit.Service.Alerts;

/// <summary>Detects modification of the LSA RunAsPPL registry value.</summary>
public sealed class LsassPplTamperRule : AlertRuleBase
{
	public override string RuleId => "LSASS_PPL_TAMPER";

	public override string Name => "LSASS PPL Registry Tamper";

	public override AlertSeverity Severity => AlertSeverity.Critical;

	public override Task<Alert?> EvaluateAsync(RawEvent evt, IAlertContext ctx, CancellationToken ct)
	{
		if (evt.EventId != 4657 || evt.ObjectName is null)
		{
			return Task.FromResult<Alert?>(null);
		}

		string lower = evt.ObjectName.ToLowerInvariant();
		bool match = lower.Contains("\\lsa", StringComparison.Ordinal)
			&& lower.Contains("runasppl", StringComparison.Ordinal);
		if (!match)
		{
			return Task.FromResult<Alert?>(null);
		}

		return Task.FromResult<Alert?>(CreateAlert(evt,
			$"LSA RunAsPPL registry value modified by {evt.UserName}",
			new { Path = evt.ObjectName, Mitre = "T1003" }));
	}
}
