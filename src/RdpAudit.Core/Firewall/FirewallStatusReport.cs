// File:    src/RdpAudit.Core/Firewall/FirewallStatusReport.cs
// Module:  RdpAudit.Core.Firewall
// Purpose: Snapshot of a firewall provider's current readiness, returned by IFirewallProvider.GetStatusAsync.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

namespace RdpAudit.Core.Firewall;

/// <summary>Snapshot of a firewall provider's current readiness.</summary>
public sealed class FirewallStatusReport
{
	public FirewallProviderStatus Status { get; init; } = FirewallProviderStatus.NotImplemented;

	/// <summary>Provider identifier (e.g. "Windows", "MikroTik"). Stable for logging / metrics.</summary>
	public string ProviderId { get; init; } = string.Empty;

	/// <summary>Approximate count of currently active block rules attributable to this provider.</summary>
	public int ActiveBlockCount { get; init; }

	/// <summary>Operator-facing message. MUST NOT contain secret values.</summary>
	public string? Message { get; init; }
}
