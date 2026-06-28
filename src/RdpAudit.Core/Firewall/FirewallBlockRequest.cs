// File:    src/RdpAudit.Core/Firewall/FirewallBlockRequest.cs
// Module:  RdpAudit.Core.Firewall
// Purpose: Safe request DTO carried into IFirewallProvider.BlockAsync. Captures the source IP,
//          base rule name, optional duration, and operator-supplied reason text.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

namespace RdpAudit.Core.Firewall;

/// <summary>Request DTO carried into <c>IFirewallProvider.BlockAsync</c>.</summary>
public sealed class FirewallBlockRequest
{
	public FirewallBlockRequest(string ip, string ruleName)
	{
		ArgumentException.ThrowIfNullOrWhiteSpace(ip);
		ArgumentException.ThrowIfNullOrWhiteSpace(ruleName);
		Ip = ip;
		RuleName = ruleName;
	}

	/// <summary>Source IP or CIDR to block. Must be syntactically valid; provider re-validates defensively.</summary>
	public string Ip { get; }

	/// <summary>Base rule name (e.g. "RdpAudit-Block"). Providers may suffix it per-IP.</summary>
	public string RuleName { get; }

	/// <summary>Optional duration; null or non-positive means "until manually removed".</summary>
	public TimeSpan? Duration { get; init; }

	/// <summary>Operator-supplied free-text reason. Stored in the block journal for audit trails.</summary>
	public string? Reason { get; init; }
}
