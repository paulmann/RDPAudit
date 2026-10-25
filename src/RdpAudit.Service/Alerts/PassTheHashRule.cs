// File:    src/RdpAudit.Service/Alerts/PassTheHashRule.cs
// Module:  RdpAudit.Service.Alerts
// Purpose: Detects Pass-the-Hash lateral movement via NTLM logon without preceding 4648.
// Extends: RdpAudit.Core.Events.AlertRuleBase
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using RdpAudit.Core.Events;
using RdpAudit.Core.Models;

namespace RdpAudit.Service.Alerts;

/// <summary>Detects Pass-the-Hash lateral movement via NTLM logon without preceding 4648.</summary>
public sealed class PassTheHashRule : AlertRuleBase
{
	public override string RuleId => "PASS_THE_HASH";

	public override string Name => "Pass the Hash — NTLM Lateral Movement";

	public override AlertSeverity Severity => AlertSeverity.High;

	public override async Task<Alert?> EvaluateAsync(RawEvent evt, IAlertContext ctx, CancellationToken ct)
	{
		if (evt.EventId != 4624)
		{
			return null;
		}

		if (evt.LogonType is not (3 or 9))
		{
			return null;
		}

		if (!string.Equals(evt.AuthPackage, "NTLM", StringComparison.OrdinalIgnoreCase))
		{
			return null;
		}

		if (string.IsNullOrEmpty(evt.SourceIp))
		{
			return null;
		}

		if (ctx.Options.Alerts.WhitelistIps.Contains(evt.SourceIp, StringComparer.OrdinalIgnoreCase))
		{
			return null;
		}

		// Anchor the 5 s window to the EVENT time, not the wall clock: the alert may be processed
		// up to AlertEventMaxAgeMinutes after the event, and UtcNow-anchoring made the legitimate
		// preceding 4648 invisible under any backlog, producing false PASS_THE_HASH alerts.
		IReadOnlyList<RawEvent> preceding = await ctx.GetRecentByUserAroundAsync(
			evt.UserName ?? string.Empty,
			50,
			evt.TimeUtc,
			TimeSpan.FromSeconds(5),
			TimeSpan.Zero,
			ct).ConfigureAwait(false);

		bool hasExplicit = preceding.Any(e =>
			e.EventId == 4648
			&& string.Equals(e.LogonId, evt.LogonId, StringComparison.OrdinalIgnoreCase));
		if (hasExplicit)
		{
			return null;
		}

		return CreateAlert(evt,
			$"Possible Pass-the-Hash: NTLM LogonType {evt.LogonType} from {evt.SourceIp} with no preceding 4648",
			new { Heuristic = true, evt.LogonType, evt.AuthPackage, Mitre = "T1550.002" });
	}
}
