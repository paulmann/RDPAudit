// File:    src/RdpAudit.Core/Config/FirewallEnforcementBackend.cs
// Module:  RdpAudit.Core.Config
// Purpose: Selects HOW the local Windows host realises a block beyond the database blocklist row.
//          WindowsFirewall installs an inbound block rule (fully implemented); RouteBlackhole adds
//          an experimental per-IP host route to an unreachable next-hop (implemented, but labelled
//          experimental because Windows has no native Linux-style blackhole route — it mainly
//          drops outbound replies to the IP); IPsecPolicy is an advanced inbound block filter
//          surfaced as a clean interface with an explicit status so the UI can disable it cleanly
//          until the full implementation lands.
// Extends: System.Enum
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

namespace RdpAudit.Core.Config;

/// <summary>Selects how the local Windows host realises a block beyond the DB blocklist row.</summary>
/// <remarks>
/// Append-only enum: ordinals are persisted into ActiveBlock journalling / diagnostics and MUST
/// NEVER be reused or reordered. New backends receive a new ordinal at the end of the list.
/// </remarks>
public enum FirewallEnforcementBackend
{
	/// <summary>Windows Advanced Firewall inbound block rule (netsh advfirewall). Fully implemented.</summary>
	WindowsFirewall = 0,

	/// <summary>Experimental per-IP host route to an unreachable blackhole gateway (route add).</summary>
	/// <remarks>
	/// Windows has no native Linux-style discard/blackhole route. This backend points the attacker
	/// IP at an unreachable next-hop so outbound replies are dropped; inbound SYNs may still arrive
	/// at the listener, so it is a defence-in-depth supplement, not a replacement for the firewall.
	/// </remarks>
	RouteBlackhole = 1,

	/// <summary>Advanced IPsec block filter for the remote IP. Interface present; status reported.</summary>
	/// <remarks>
	/// A full IPsec implementation must never overwrite unrelated local/domain IPsec policies, so it
	/// is delivered behind a stable interface that reports <c>NotImplemented</c> until the gated
	/// implementation lands rather than risking a partial, policy-clobbering write.
	/// </remarks>
	IPsecPolicy = 2,
}
