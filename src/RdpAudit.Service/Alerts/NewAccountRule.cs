// File:    src/RdpAudit.Service/Alerts/NewAccountRule.cs
// Module:  RdpAudit.Service.Alerts
// Purpose: Flags Event 4720 — user account created (T1136).
// Extends: RdpAudit.Core.Events.AlertRuleBase
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using RdpAudit.Core.Config;
using RdpAudit.Core.Events;
using RdpAudit.Core.Models;

namespace RdpAudit.Service.Alerts;

/// <summary>Flags Event 4720 — user account created.</summary>
public sealed class NewAccountRule : AlertRuleBase
{
	public override string RuleId => "NEW_ACCOUNT";

	public override string Name => "New User Account Created";

	public override AlertSeverity Severity => AlertSeverity.High;

	public override bool IsEnabled(RdpAuditOptions options) => options.Monitoring.TrackAccountChanges;

	public override Task<Alert?> EvaluateAsync(RawEvent evt, IAlertContext ctx, CancellationToken ct)
	{
		if (evt.EventId != 4720)
		{
			return Task.FromResult<Alert?>(null);
		}

		// The creator is SubjectUserName. EventNormalizer maps RawEvent.UserName to
		// TargetUserName first, which for 4720 is the NEW account, so the old message reported the
		// new account's domain as the actor ("by <domain>").
		string actor = ExtractField(evt.Details, "SubjectUserName");
		string message = string.IsNullOrEmpty(actor)
			? $"New user account created: {evt.UserName}"
			: $"New user account created: {evt.UserName} by {actor}";

		return Task.FromResult<Alert?>(CreateAlert(
			evt,
			message,
			new { Actor = actor, Mitre = "T1136" }));
	}

	private static string ExtractField(string? json, string fieldName)
	{
		if (string.IsNullOrEmpty(json))
		{
			return string.Empty;
		}

		try
		{
			using System.Text.Json.JsonDocument doc = System.Text.Json.JsonDocument.Parse(json);
			if (doc.RootElement.TryGetProperty(fieldName, out System.Text.Json.JsonElement value))
			{
				return value.GetString() ?? string.Empty;
			}
		}
		catch (System.Text.Json.JsonException)
		{
		}

		return string.Empty;
	}
}
