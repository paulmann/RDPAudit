// File:    src/RdpAudit.Core/Firewall/FirewallProviderStatus.cs
// Module:  RdpAudit.Core.Firewall
// Purpose: Discriminator for the operational state of a single firewall provider implementation.
// Extends: System.Enum
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

namespace RdpAudit.Core.Firewall;

/// <summary>Discriminator for the operational state of a firewall provider.</summary>
/// <remarks>Append-only enum: values must never be reused or reordered.</remarks>
public enum FirewallProviderStatus
{
	/// <summary>The provider is healthy and can service block / unblock / list requests.</summary>
	Available = 0,

	/// <summary>The provider is configured but cannot be reached right now (network, auth, ...).</summary>
	Unreachable = 1,

	/// <summary>The provider is disabled by configuration.</summary>
	Disabled = 2,

	/// <summary>The provider is not configured (missing endpoint / credentials).</summary>
	NotConfigured = 3,

	/// <summary>The provider is recognised but its implementation is not present in this build.</summary>
	NotImplemented = 4,
}
