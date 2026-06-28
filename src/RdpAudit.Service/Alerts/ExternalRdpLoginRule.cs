// File:    src/RdpAudit.Service/Alerts/ExternalRdpLoginRule.cs
// Module:  RdpAudit.Service.Alerts
// Purpose: Flags RDP logons originating from a public (non-RFC1918) IP address.
// Extends: RdpAudit.Core.Events.AlertRuleBase
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using RdpAudit.Core.Events;
using RdpAudit.Core.Models;
using RdpAudit.Core.Util;

namespace RdpAudit.Service.Alerts;

/// <summary>Flags RDP logons originating from a public IP address.</summary>
public sealed class ExternalRdpLoginRule : AlertRuleBase
{
	public override string RuleId => "EXTERNAL_RDP_LOGIN";

	public override string Name => "External (Public IP) RDP Login";

	public override AlertSeverity Severity => AlertSeverity.Medium;

	public override Task<Alert?> EvaluateAsync(RawEvent evt, IAlertContext ctx, CancellationToken ct)
	{
		bool isCandidate = evt.EventId == 1149 || (evt.EventId == 4624 && evt.LogonType == 10);
		if (!isCandidate || string.IsNullOrEmpty(evt.SourceIp))
		{
			return Task.FromResult<Alert?>(null);
		}

		if (ctx.Options.Alerts.WhitelistIps.Contains(evt.SourceIp, StringComparer.OrdinalIgnoreCase))
		{
			return Task.FromResult<Alert?>(null);
		}

		if (!IpClassifier.IsPublicIp(evt.SourceIp))
		{
			return Task.FromResult<Alert?>(null);
		}

		string message = BuildMessage(evt.SourceIp, evt.UserName);
		return Task.FromResult<Alert?>(CreateAlert(evt, message, new { evt.SourceIp, Mitre = "T1133" }));
	}

	/// <summary>Render the alert message safely. When the username is blank/unknown we omit the
	/// "as &lt;user&gt;" clause entirely rather than emit a trailing blank "as " — the v1.2.0
	/// task brief required this fix because operators were seeing messages literally ending in
	/// "as ".</summary>
	internal static string BuildMessage(string? sourceIp, string? userName)
	{
		string ip = string.IsNullOrWhiteSpace(sourceIp) ? "(unknown IP)" : sourceIp;
		string trimmedUser = userName?.Trim() ?? string.Empty;
		bool hasUser = !string.IsNullOrEmpty(trimmedUser)
			&& !string.Equals(trimmedUser, "-", StringComparison.Ordinal)
			&& !string.Equals(trimmedUser, "N/A", StringComparison.OrdinalIgnoreCase);

		return hasUser
			? "External RDP login from public IP " + ip + " as " + trimmedUser
			: "External RDP login from public IP " + ip;
	}
}
