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

		// 4776 carries the NTSTATUS in Status; a zero code means the credential validation
		// succeeded, so only failures count. IsZero accepts every canonical textual form
		// (0x0 / 0x00000000 / signed decimal) and treats a missing Status as "nothing to
		// detect"; the old literal "0x0" comparison could never match the canonicalized form.
		if (NtStatusFormatter.IsZero(evt.Status))
		{
			return null;
		}

		// 4776 has no IP field at all: its source is a NetBIOS Workstation name, which the
		// parser deliberately never maps to RawEvent.SourceIp (PerEventIpResolver). The only
		// stable identity the event carries is the TARGET account, so the brute-force window
		// is keyed on that account. The previous key (SourceIp ?? UserName used as an IP) could
		// never match a row, so this rule was dead and NTLM brute force was never detected.
		string? targetUser = evt.UserName?.Trim();
		if (string.IsNullOrEmpty(targetUser))
		{
			return null;
		}

		if (!string.IsNullOrEmpty(evt.SourceIp)
			&& ctx.Options.Alerts.WhitelistIps.Contains(evt.SourceIp, StringComparer.OrdinalIgnoreCase))
		{
			return null;
		}

		TimeSpan window = TimeSpan.FromMinutes(Math.Max(1, ctx.Options.Alerts.BruteForceWindowMinutes));
		IReadOnlyList<RawEvent> recent = await ctx.GetRecentByUserAsync(targetUser, 500, window, ct).ConfigureAwait(false);
		int fails = recent.Count(e => e.EventId == 4776 && !NtStatusFormatter.IsZero(e.Status));
		int threshold = Math.Max(1, ctx.Options.Alerts.BruteForceNtlmThreshold);
		if (fails < threshold)
		{
			return null;
		}

		if (_cooldown is not null)
		{
			TimeSpan cooldown = TimeSpan.FromMinutes(Math.Max(1, ctx.Options.Alerts.ThresholdCooldownMinutes));
			if (!_cooldown.TryRegister(RuleId, targetUser, cooldown))
			{
				return null;
			}
		}

		return CreateAlert(evt,
			$"NTLM brute force against {targetUser}: {fails} failures in {window.TotalMinutes:0} min",
			new { FailCount = fails, WindowMinutes = window.TotalMinutes, Mitre = "T1110" });
	}
}
