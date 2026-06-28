// File:    src/RdpAudit.Service/Alerts/UnknownIpSuccessRule.cs
// Module:  RdpAudit.Service.Alerts
// Purpose: Flags first successful logon from an IP that previously had ≥ N failures.
// Extends: RdpAudit.Core.Events.AlertRuleBase
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using RdpAudit.Core.Events;
using RdpAudit.Core.Models;

namespace RdpAudit.Service.Alerts;

/// <summary>Flags first successful logon from an IP that previously had ≥ N failures.</summary>
public sealed class UnknownIpSuccessRule : AlertRuleBase
{
	public override string RuleId => "UNKNOWN_IP_SUCCESS";

	public override string Name => "Successful Logon from Previously-Failing IP";

	public override AlertSeverity Severity => AlertSeverity.Low;

	public override async Task<Alert?> EvaluateAsync(RawEvent evt, IAlertContext ctx, CancellationToken ct)
	{
		if (evt.EventId != 4624 || string.IsNullOrEmpty(evt.SourceIp))
		{
			return null;
		}

		if (ctx.Options.Alerts.WhitelistIps.Contains(evt.SourceIp, StringComparer.OrdinalIgnoreCase))
		{
			return null;
		}

		Address? address = await ctx.GetAddressAsync(evt.SourceIp, ct).ConfigureAwait(false);
		int threshold = Math.Max(1, ctx.Options.Alerts.UnknownIpSuccessFailureThreshold);
		if (address is null || address.FailCount < threshold || address.SuccessCount > 1)
		{
			return null;
		}

		return CreateAlert(evt,
			$"Successful logon by {evt.UserName} from {evt.SourceIp} after {address.FailCount} prior failures",
			new { address.FailCount, address.SuccessCount, Mitre = "T1021.001" });
	}
}
