// File:    src/RdpAudit.Service/Alerts/BruteForceNtlmRule.cs
// Module:  RdpAudit.Service.Alerts
// Purpose: Detects brute-force NTLM credential validation failures (Event 4776).
// Extends: RdpAudit.Core.Events.AlertRuleBase
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using RdpAudit.Core.Config;
using RdpAudit.Core.Events;
using RdpAudit.Core.Models;

namespace RdpAudit.Service.Alerts;

/// <summary>Detects brute-force NTLM credential validation failures (Event 4776).</summary>
public sealed class BruteForceNtlmRule : AlertRuleBase
{
	private readonly AlertCooldownTracker? _cooldown;

	public BruteForceNtlmRule()
	{
	}

	public BruteForceNtlmRule(AlertCooldownTracker cooldown)
	{
		_cooldown = cooldown;
	}

	public override string RuleId => "BRUTE_FORCE_NTLM";

	public override string Name => "Brute Force — NTLM Credential Validation";

	public override AlertSeverity Severity => AlertSeverity.Medium;

	public override bool IsEnabled(RdpAuditOptions options) => options.Alerts.EnableBruteForceDetection;

	public override async Task<Alert?> EvaluateAsync(RawEvent evt, IAlertContext ctx, CancellationToken ct)
	{
		if (evt.EventId != 4776)
		{
			return null;
		}

		if (string.Equals(evt.Status, "0x0", StringComparison.OrdinalIgnoreCase)
			|| string.IsNullOrEmpty(evt.Status))
		{
			return null;
		}

		string? workstation = evt.SourceIp ?? evt.UserName;
		if (string.IsNullOrEmpty(workstation))
		{
			return null;
		}

		if (ctx.Options.Alerts.WhitelistIps.Contains(workstation, StringComparer.OrdinalIgnoreCase))
		{
			return null;
		}

		TimeSpan window = TimeSpan.FromMinutes(Math.Max(1, ctx.Options.Alerts.BruteForceWindowMinutes));
		IReadOnlyList<RawEvent> recent = await ctx.GetRecentByIpAsync(workstation, 500, window, ct).ConfigureAwait(false);
		int fails = recent.Count(e => e.EventId == 4776);
		int threshold = Math.Max(1, ctx.Options.Alerts.BruteForceNtlmThreshold);
		if (fails < threshold)
		{
			return null;
		}

		if (_cooldown is not null)
		{
			TimeSpan cooldown = TimeSpan.FromMinutes(Math.Max(1, ctx.Options.Alerts.ThresholdCooldownMinutes));
			if (!_cooldown.TryRegister(RuleId, workstation, cooldown))
			{
				return null;
			}
		}

		return CreateAlert(evt,
			$"NTLM brute force from {workstation}: {fails} failures in {window.TotalMinutes:0} min",
			new { FailCount = fails, WindowMinutes = window.TotalMinutes, Mitre = "T1110" });
	}
}
