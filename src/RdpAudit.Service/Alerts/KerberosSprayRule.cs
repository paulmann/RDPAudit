// File:    src/RdpAudit.Service/Alerts/KerberosSprayRule.cs
// Module:  RdpAudit.Service.Alerts
// Purpose: Detects high-volume Kerberos pre-auth failures from a single IP (Event 4771).
// Extends: RdpAudit.Core.Events.AlertRuleBase
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using RdpAudit.Core.Config;
using RdpAudit.Core.Events;
using RdpAudit.Core.Models;

namespace RdpAudit.Service.Alerts;

/// <summary>Detects high-volume Kerberos pre-auth failures from a single IP (Event 4771).</summary>
public sealed class KerberosSprayRule : AlertRuleBase
{
	private readonly AlertCooldownTracker? _cooldown;

	public KerberosSprayRule()
	{
	}

	public KerberosSprayRule(AlertCooldownTracker cooldown)
	{
		_cooldown = cooldown;
	}

	public override string RuleId => "KERBEROS_SPRAY";

	public override string Name => "Kerberos Pre-Auth Spray";

	public override AlertSeverity Severity => AlertSeverity.High;

	public override bool IsEnabled(RdpAuditOptions options) => options.Monitoring.TrackKerberos;

	public override async Task<Alert?> EvaluateAsync(RawEvent evt, IAlertContext ctx, CancellationToken ct)
	{
		if (evt.EventId != 4771 || string.IsNullOrEmpty(evt.SourceIp))
		{
			return null;
		}

		if (ctx.Options.Alerts.WhitelistIps.Contains(evt.SourceIp, StringComparer.OrdinalIgnoreCase))
		{
			return null;
		}

		TimeSpan window = TimeSpan.FromMinutes(Math.Max(1, ctx.Options.Alerts.BruteForceWindowMinutes));
		IReadOnlyList<RawEvent> recent = await ctx.GetRecentByIpAsync(evt.SourceIp, 500, window, ct).ConfigureAwait(false);
		int fails = recent.Count(e => e.EventId == 4771);
		int threshold = Math.Max(1, ctx.Options.Alerts.KerberosSprayThreshold);
		if (fails < threshold)
		{
			return null;
		}

		if (_cooldown is not null)
		{
			TimeSpan cooldown = TimeSpan.FromMinutes(Math.Max(1, ctx.Options.Alerts.ThresholdCooldownMinutes));
			if (!_cooldown.TryRegister(RuleId, evt.SourceIp, cooldown))
			{
				return null;
			}
		}

		return CreateAlert(evt,
			$"Kerberos pre-auth spray from {evt.SourceIp}: {fails} failures in {window.TotalMinutes:0} min",
			new { FailCount = fails, WindowMinutes = window.TotalMinutes, Mitre = "T1110" });
	}
}
