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

		string group = ExtractField(evt.Details, "TargetUserName");
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

		// The actor is SubjectUserName. EventNormalizer maps RawEvent.UserName to
		// TargetUserName first, which for 4728/4732/4756 is the GROUP being modified, so the
		// alert used to name the group as the identity that made the change.
		string actor = ExtractField(evt.Details, "SubjectUserName");
		if (string.IsNullOrEmpty(actor))
		{
			actor = evt.UserName ?? "(unknown)";
		}

		Alert? alert = CreateAlert(evt,
			$"Member added to privileged group {group} by {actor}",
			new { Group = group, Actor = actor, Mitre = "T1098.002" });
		if (alert is not null)
		{
			alert.UserName = actor;
		}

		return Task.FromResult(alert);
	}

	private static string ExtractField(string? json, string fieldName)
	{
		if (string.IsNullOrEmpty(json))
		{
			return string.Empty;
		}

		try
		{
			using JsonDocument doc = JsonDocument.Parse(json);
			if (doc.RootElement.TryGetProperty(fieldName, out JsonElement v))
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
