// File:    src/RdpAudit.Service/Alerts/BruteForceRule.cs
// Module:  RdpAudit.Service.Alerts
// Purpose: Detects classic brute-force password guessing on Event ID 4625.
//          Uses AlertCooldownTracker to avoid one alert per offending event after threshold.
// Extends: RdpAudit.Core.Events.AlertRuleBase
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using RdpAudit.Core.Config;
using RdpAudit.Core.Events;
using RdpAudit.Core.Models;

namespace RdpAudit.Service.Alerts;

/// <summary>Detects classic brute-force password guessing on Event ID 4625.</summary>
public sealed class BruteForceRule : AlertRuleBase
{
	private readonly AlertCooldownTracker? _cooldown;

	public BruteForceRule()
	{
	}

	public BruteForceRule(AlertCooldownTracker cooldown)
	{
		_cooldown = cooldown;
	}

	public override string RuleId => "BRUTE_FORCE_01";

	public override string Name => "Brute Force Password Guessing";

	public override AlertSeverity Severity => AlertSeverity.High;

	public override bool IsEnabled(RdpAuditOptions options) => options.Alerts.EnableBruteForceDetection;

	public override async Task<Alert?> EvaluateAsync(RawEvent evt, IAlertContext ctx, CancellationToken ct)
	{
		if (evt.EventId != 4625)
		{
			return null;
		}

		// Stage 6: a 4625 whose source IP was never parseable still represents brute-force
		// pressure on the named account. Detect it through a per-username stream instead of
		// the per-IP one so the alert is preserved without false attribution to a synthetic
		// address.
		if (evt.SourceIpUnresolved && !string.IsNullOrEmpty(evt.UserName))
		{
			return await EvaluateUnresolvedAsync(evt, ctx, ct).ConfigureAwait(false);
		}

		if (string.IsNullOrEmpty(evt.SourceIp))
		{
			return null;
		}

		if (ctx.Options.Alerts.WhitelistIps.Contains(evt.SourceIp, StringComparer.OrdinalIgnoreCase))
		{
			return null;
		}

		TimeSpan window = TimeSpan.FromMinutes(Math.Max(1, ctx.Options.Alerts.BruteForceWindowMinutes));
		IReadOnlyList<RawEvent> recent = await ctx.GetRecentByIpAsync(evt.SourceIp, 500, window, ct).ConfigureAwait(false);
		int fails = recent.Count(e => e.EventId == 4625);
		int threshold = Math.Max(1, ctx.Options.Alerts.BruteForceThreshold);
		if (fails < threshold)
		{
			return null;
		}

		// De-dup: at most one alert per (rule, source IP) in the configured cooldown window.
		if (_cooldown is not null)
		{
			TimeSpan cooldown = TimeSpan.FromMinutes(Math.Max(1, ctx.Options.Alerts.ThresholdCooldownMinutes));
			if (!_cooldown.TryRegister(RuleId, evt.SourceIp, cooldown))
			{
				return null;
			}
		}

		return CreateAlert(evt,
			$"Brute force from {evt.SourceIp}: {fails} failures in {window.TotalMinutes:0} min",
			new { FailCount = fails, WindowMinutes = window.TotalMinutes, Mitre = "T1110" });
	}

	private async Task<Alert?> EvaluateUnresolvedAsync(RawEvent evt, IAlertContext ctx, CancellationToken ct)
	{
		string user = evt.UserName!;
		TimeSpan window = TimeSpan.FromMinutes(Math.Max(1, ctx.Options.Alerts.BruteForceWindowMinutes));
		IReadOnlyList<RawEvent> recent = await ctx.GetRecentByUserAsync(user, 500, window, ct).ConfigureAwait(false);
		int fails = recent.Count(e => e.EventId == 4625 && e.SourceIpUnresolved);
		int threshold = Math.Max(1, ctx.Options.Alerts.BruteForceThreshold);
		if (fails < threshold)
		{
			return null;
		}

		string cooldownKey = "user:" + user;
		if (_cooldown is not null)
		{
			TimeSpan cooldown = TimeSpan.FromMinutes(Math.Max(1, ctx.Options.Alerts.ThresholdCooldownMinutes));
			if (!_cooldown.TryRegister(RuleId, cooldownKey, cooldown))
			{
				return null;
			}
		}

		return CreateAlert(evt,
			$"Brute force from (unresolved) against {user}: {fails} failures in {window.TotalMinutes:0} min",
			new { FailCount = fails, WindowMinutes = window.TotalMinutes, Mitre = "T1110", SourceIp = "(unresolved)" });
	}
}
