// File:    src/RdpAudit.Core/Firewall/FirewallProviderRouting.cs
// Module:  RdpAudit.Core.Firewall
// Purpose: Pure mapping from the configured provider kind + local enforcement backend to the
//          stable IFirewallProvider.ProviderId string. Centralises the routing so the auto-block
//          and expiration workers agree on which provider services a given block, and so the
//          mapping is unit-testable without DI. The "local" host provider (FirewallProviderKind
//          Windows) is dispatched to WindowsFirewall / RouteBlackhole / IPsec by the backend;
//          MikroTik is always the external RouterOS provider regardless of backend.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using RdpAudit.Core.Config;

namespace RdpAudit.Core.Firewall;

/// <summary>Pure mapping from provider kind + enforcement backend to the provider id string.</summary>
public static class FirewallProviderRouting
{
	/// <summary>Stable provider id for the Windows Advanced Firewall backend.</summary>
	public const string WindowsProviderId = "Windows";

	/// <summary>Stable provider id for the external MikroTik RouterOS backend.</summary>
	public const string MikroTikProviderId = "MikroTik";

	/// <summary>Stable provider id for the experimental route-blackhole backend.</summary>
	public const string RouteBlackholeProviderId = "RouteBlackhole";

	/// <summary>Stable provider id for the IPsec block backend.</summary>
	public const string IPsecProviderId = "IPsec";

	/// <summary>Resolves the provider id for a single (non-fan-out) provider kind, honouring the
	/// local enforcement backend when the kind targets the local Windows host. Returns an empty
	/// string for kinds that drive nothing (None / Both — callers fan Both out beforehand).</summary>
	public static string ResolveProviderId(FirewallProviderKind kind, FirewallEnforcementBackend backend)
	{
		return kind switch
		{
			FirewallProviderKind.Windows => backend switch
			{
				FirewallEnforcementBackend.WindowsFirewall => WindowsProviderId,
				FirewallEnforcementBackend.RouteBlackhole => RouteBlackholeProviderId,
				FirewallEnforcementBackend.IPsecPolicy => IPsecProviderId,
				_ => WindowsProviderId,
			},
			FirewallProviderKind.MikroTik => MikroTikProviderId,
			_ => string.Empty,
		};
	}
}
