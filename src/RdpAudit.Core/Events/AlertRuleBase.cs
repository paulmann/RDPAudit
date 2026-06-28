// File:    src/RdpAudit.Core/Events/AlertRuleBase.cs
// Module:  RdpAudit.Core.Events
// Purpose: Convenience base class for IAlertRule implementations.
// Extends: RdpAudit.Core.Events.IAlertRule
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System.Text.Json;
using RdpAudit.Core.Config;
using RdpAudit.Core.Models;
using RdpAudit.Core.Util;

namespace RdpAudit.Core.Events;

/// <summary>Convenience base class for IAlertRule implementations.</summary>
public abstract class AlertRuleBase : IAlertRule
{
	public abstract string RuleId { get; }

	public abstract string Name { get; }

	public abstract AlertSeverity Severity { get; }

	public virtual bool IsEnabled(RdpAuditOptions options) => true;

	public abstract Task<Alert?> EvaluateAsync(RawEvent evt, IAlertContext ctx, CancellationToken ct);

	protected Alert CreateAlert(RawEvent trigger, string message, object? details = null) => new()
	{
		RuleId = RuleId,
		Severity = Severity,
		TimeUtc = DateTime.UtcNow,
		SourceIp = trigger.SourceIp,
		UserName = trigger.UserName,
		Message = message,
		Details = details is null ? null : JsonSerializer.Serialize(details, JsonOptions.Default),
		TriggerEventId = trigger.Id,
		Acknowledged = false,
	};
}
