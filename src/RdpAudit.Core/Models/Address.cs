// File:    src/RdpAudit.Core/Models/Address.cs
// Module:  RdpAudit.Core.Models
// Purpose: IP reputation and aggregated activity counters per source address.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

namespace RdpAudit.Core.Models;

/// <summary>IP reputation and aggregated activity counters per source address.</summary>
public sealed class Address
{
	public long Id { get; set; }

	public string Ip { get; set; } = string.Empty;

	public int FailCount { get; set; }

	public int SuccessCount { get; set; }

	public DateTime FirstSeen { get; set; }

	public DateTime LastSeen { get; set; }

	public double ThreatScore { get; set; }

	public bool IsBlocked { get; set; }

	public string? BlockReason { get; set; }

	public string? UserNames { get; set; }

	public bool IsPublicIp { get; set; }
}
