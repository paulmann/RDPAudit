// File:    src/RdpAudit.Core/Ipc/Contracts/FirewallStatusDto.cs
// Module:  RdpAudit.Core.Ipc.Contracts
// Purpose: DTO returned by GetFirewallStatus describing provider availability and counters.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using MessagePack;
using RdpAudit.Core.Config;

namespace RdpAudit.Core.Ipc.Contracts;

/// <summary>Overall firewall enforcement health derived from live reconciliation, not DB rows alone.</summary>
public enum FirewallEnforcementHealth
{
	/// <summary>No enabled blocklist rows; nothing to enforce.</summary>
	Idle = 0,

	/// <summary>Enabled blocklist rows exist and verified enforcement covers them.</summary>
	Healthy = 1,

	/// <summary>Enabled blocklist rows exist but zero RdpAudit firewall rules / verified enforcement were found.</summary>
	MissingRule = 2,

	/// <summary>Enforcement was attempted but reconciliation could not verify it (partial / failed).</summary>
	Failed = 3,

	/// <summary>Reconciliation service unavailable; enforcement state cannot be verified.</summary>
	Unknown = 4,
}

/// <summary>DTO returned by <c>GetFirewallStatus</c> describing provider availability and counters.</summary>
[MessagePackObject(keyAsPropertyName: false)]
public sealed class FirewallStatusDto
{
	[Key(0)]
	public IpcResultStatus Status { get; set; } = IpcResultStatus.Success;

	[Key(1)]
	public FirewallProviderKind ConfiguredProvider { get; set; } = FirewallProviderKind.None;

	[Key(2)]
	public bool WindowsAvailable { get; set; }

	[Key(3)]
	public bool MikroTikAvailable { get; set; }

	[Key(4)]
	public int ActiveBlockCount { get; set; }

	[Key(5)]
	public int WhitelistCount { get; set; }

	[Key(6)]
	public int BlacklistCount { get; set; }

	/// <summary>Operator-facing message; never contains secret material.</summary>
	[Key(7)]
	public string? Message { get; set; }

	/// <summary>Count of enabled blocklist rows (the enforcement that SHOULD exist).</summary>
	[Key(8)]
	public int EnabledBlocklistRows { get; set; }

	/// <summary>Count of RdpAudit-owned firewall rules discovered by reconciliation.</summary>
	[Key(9)]
	public int RdpAuditFirewallRuleCount { get; set; }

	/// <summary>Count of blocks whose enforcement was VERIFIED present by live reconciliation.</summary>
	[Key(10)]
	public int VerifiedEnforcedCount { get; set; }

	/// <summary>Derived enforcement health; drives the actionable status header in the Firewall tab.</summary>
	[Key(11)]
	public FirewallEnforcementHealth EnforcementHealth { get; set; } = FirewallEnforcementHealth.Unknown;
}
