// File:    src/RdpAudit.Core/Firewall/FirewallBlockEntry.cs
// Module:  RdpAudit.Core.Firewall
// Purpose: DTO returned by IFirewallProvider.ListBlocksAsync describing one active block rule.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

namespace RdpAudit.Core.Firewall;

/// <summary>DTO returned by <c>IFirewallProvider.ListBlocksAsync</c> describing one active block rule.</summary>
public sealed class FirewallBlockEntry
{
	public string Ip { get; init; } = string.Empty;

	public string RuleId { get; init; } = string.Empty;

	public string ProviderId { get; init; } = string.Empty;

	public DateTime? CreatedUtc { get; init; }

	public DateTime? ExpiresUtc { get; init; }

	public string? Reason { get; init; }
}
