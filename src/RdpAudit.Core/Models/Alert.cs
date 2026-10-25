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

	/// <summary>
	/// True when <see cref="SourceIp"/> was correlated from context instead of read from the
	/// event. A correlation guess is good enough to show, never good enough to block: on
	/// 23.10.2026 an NTLM alert (Security 4776, which carries no address at all) blamed a private
	/// admin workstation and the auto-block cut that workstation off the whole branch network.
	/// </summary>
	public bool SourceIpDerived { get; set; }

	public string? UserName { get; set; }

	public string Message { get; set; } = string.Empty;

	public string? Details { get; set; }

	public bool Acknowledged { get; set; }

	public long TriggerEventId { get; set; }
}
