// File:    src/RdpAudit.Core/Ipc/Contracts/AlertEntryDto.cs
// Module:  RdpAudit.Core.Ipc.Contracts
// Purpose: Bounded per-IP alert projection returned by GetAlertsForIp (ordinal 70) and consumed
//          by the Configurator SIEM export mapper. Deliberately omits the alert Details field so
//          no raw forensic or error detail leaves the service through the export path.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using MessagePack;
using RdpAudit.Core.Models;

namespace RdpAudit.Core.Ipc.Contracts;

/// <summary>Bounded alert projection returned by the GetAlertsForIp read command.</summary>
[MessagePackObject(keyAsPropertyName: false)]
public sealed class AlertEntryDto
{
	/// <summary>Alert row id (stable external identifier).</summary>
	[Key(0)]
	public long Id { get; set; }

	/// <summary>Alert rule id (CEF signature id).</summary>
	[Key(1)]
	public string RuleId { get; set; } = string.Empty;

	/// <summary>Alert severity classification.</summary>
	[Key(2)]
	public AlertSeverity Severity { get; set; }

	/// <summary>UTC time the alert was raised.</summary>
	[Key(3)]
	public DateTime TimeUtc { get; set; }

	/// <summary>Correlated source IP; null when the alert carries no IP.</summary>
	[Key(4)]
	public string? SourceIp { get; set; }

	/// <summary>User name attached to the alert, when available.</summary>
	[Key(5)]
	public string? UserName { get; set; }

	/// <summary>Alert message text.</summary>
	[Key(6)]
	public string Message { get; set; } = string.Empty;

	/// <summary>True when the alert has been acknowledged by an operator.</summary>
	[Key(7)]
	public bool Acknowledged { get; set; }

	/// <summary>Id of the raw event that triggered the alert.</summary>
	[Key(8)]
	public long TriggerEventId { get; set; }
}
