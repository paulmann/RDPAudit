// File:    src/RdpAudit.Core/Models/Alert.cs
// Module:  RdpAudit.Core.Models
// Purpose: Output of an alert rule evaluation; persisted and surfaced via IPC.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

namespace RdpAudit.Core.Models;

/// <summary>Output of an alert rule evaluation; persisted and surfaced via IPC.</summary>
public sealed class Alert
{
	public long Id { get; set; }

	public string RuleId { get; set; } = string.Empty;

	public AlertSeverity Severity { get; set; }

	public DateTime TimeUtc { get; set; }

	public string? SourceIp { get; set; }

	public string? UserName { get; set; }

	public string Message { get; set; } = string.Empty;

	public string? Details { get; set; }

	public bool Acknowledged { get; set; }

	public long TriggerEventId { get; set; }
}
