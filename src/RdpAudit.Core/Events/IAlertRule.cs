// File:    src/RdpAudit.Core/Events/IAlertRule.cs
// Module:  RdpAudit.Core.Events
// Purpose: Contract every alert detection rule must implement.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using RdpAudit.Core.Config;
using RdpAudit.Core.Models;

namespace RdpAudit.Core.Events;

/// <summary>Contract every alert detection rule must implement.</summary>
public interface IAlertRule
{
	/// <summary>Stable, unique SCREAMING_SNAKE_CASE identifier persisted on Alert rows.</summary>
	string RuleId { get; }

	/// <summary>Human-readable rule name shown in UI / logs.</summary>
	string Name { get; }

	/// <summary>Severity emitted by this rule.</summary>
	AlertSeverity Severity { get; }

	/// <summary>Returns true when the rule should run for the supplied options.</summary>
	bool IsEnabled(RdpAuditOptions options);

	/// <summary>Evaluates the supplied event and optionally returns an Alert.</summary>
	Task<Alert?> EvaluateAsync(RawEvent evt, IAlertContext ctx, CancellationToken ct);
}
