// File:    src/RdpAudit.Service/Alerts/PrivilegedGroupChangeRule.cs
// Module:  RdpAudit.Service.Alerts
// Purpose: Flags Event 4732 — addition to privileged groups (T1098.002).
// Extends: RdpAudit.Core.Events.AlertRuleBase
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System.Text.Json;
using RdpAudit.Core.Config;
using RdpAudit.Core.Events;
using RdpAudit.Core.Models;

namespace RdpAudit.Service.Alerts;

/// <summary>Flags Event 4732 — addition to privileged groups.</summary>
public sealed class PrivilegedGroupChangeRule : AlertRuleBase
{
	public override string RuleId => "PRIVILEGED_GROUP_CHANGE";

	public override string Name => "Privileged Group Membership Change";

	public override AlertSeverity Severity => AlertSeverity.High;

	public override bool IsEnabled(RdpAuditOptions options) => options.Monitoring.TrackAccountChanges;

	public override Task<Alert?> EvaluateAsync(RawEvent evt, IAlertContext ctx, CancellationToken ct)
	{
		if (evt.EventId is not (4728 or 4732 or 4756))
		{
			return Task.FromResult<Alert?>(null);
		}

		string group = ExtractGroupName(evt.Details);
		if (string.IsNullOrEmpty(group))
		{
			return Task.FromResult<Alert?>(null);
		}

		bool privileged = ctx.Options.Alerts.PrivilegedGroups
			.Any(p => string.Equals(p, group, StringComparison.OrdinalIgnoreCase));
		if (!privileged)
		{
			return Task.FromResult<Alert?>(null);
		}

		return Task.FromResult<Alert?>(CreateAlert(evt,
			$"Member added to privileged group {group} by {evt.UserName}",
			new { Group = group, Mitre = "T1098.002" }));
	}

	private static string ExtractGroupName(string? json)
	{
		if (string.IsNullOrEmpty(json))
		{
			return string.Empty;
		}

		try
		{
			using JsonDocument doc = JsonDocument.Parse(json);
			if (doc.RootElement.TryGetProperty("TargetUserName", out JsonElement v))
			{
				return v.GetString() ?? string.Empty;
			}
		}
		catch (JsonException)
		{
		}

		return string.Empty;
	}
}
