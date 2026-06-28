// File:    src/RdpAudit.Core/Config/FirewallBlockScope.cs
// Module:  RdpAudit.Core.Config
// Purpose: Identifies how broadly a firewall block rule restricts traffic from the attacker IP.
//          RdpPortOnly limits the inbound block to the resolved RDP listener port (least
//          disruptive, lets other services keep talking to that host); AllInbound blocks every
//          inbound protocol/port from the remote IP (strongest, default for hostile sources).
// Extends: System.Enum
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

namespace RdpAudit.Core.Config;

/// <summary>Identifies how broadly a firewall block rule restricts traffic from the attacker IP.</summary>
/// <remarks>
/// Append-only enum: ordinals are persisted into rule descriptions / diagnostics and MUST NEVER be
/// reused or reordered. New scopes receive a new ordinal at the end of the list.
/// </remarks>
public enum FirewallBlockScope
{
	/// <summary>Block only inbound traffic to the resolved RDP listener TCP port from the remote IP.</summary>
	RdpPortOnly = 0,

	/// <summary>Block all inbound traffic (every protocol and port) from the remote IP.</summary>
	AllInbound = 1,
}
