// File:    src/RdpAudit.Core/MikroTik/MikroTikRule.cs
// Module:  RdpAudit.Core.MikroTik
// Purpose: Plain-data DTOs describing a MikroTik RouterOS v7 firewall filter rule from the
//          service's perspective: the request supplied to AddBlockAsync, and the projected row
//          returned by ListBlocksAsync. Neither shape carries credentials.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

namespace RdpAudit.Core.MikroTik;

/// <summary>Request fed into <see cref="IMikroTikClient.AddBlockAsync"/>.</summary>
public sealed class MikroTikBlockRequest
{
	/// <summary>Attacker source IP literal to block.</summary>
	public string Ip { get; init; } = string.Empty;

	/// <summary>Firewall filter chain (e.g. "input", "forward").</summary>
	public string Chain { get; init; } = "input";

	/// <summary>Firewall filter action (e.g. "drop", "reject").</summary>
	public string Action { get; init; } = "drop";

	/// <summary>Comment text — already prefixed with the RdpAudit recognition marker.</summary>
	public string Comment { get; init; } = string.Empty;

	/// <summary>UTC timestamp recorded in the comment when the block was created.</summary>
	public DateTime CreatedUtc { get; init; }

	/// <summary>Optional UTC expiration timestamp recorded in the comment.</summary>
	public DateTime? ExpiresUtc { get; init; }

	/// <summary>Optional address-list name. When set, the provider also adds an /ip/firewall/address-list entry.</summary>
	public string? AddressList { get; init; }
}

/// <summary>Projection of an existing /ip/firewall/filter row attributable to RdpAudit.</summary>
public sealed class MikroTikRule
{
	public string Id { get; init; } = string.Empty;
	public string Ip { get; init; } = string.Empty;
	public string Chain { get; init; } = string.Empty;
	public string Action { get; init; } = string.Empty;
	public string Comment { get; init; } = string.Empty;
}
