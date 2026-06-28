// File:    src/RdpAudit.Core/Config/FirewallProviderKind.cs
// Module:  RdpAudit.Core.Config
// Purpose: Identifies which firewall provider(s) RdpAudit should drive when applying block actions.
// Extends: System.Enum
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

namespace RdpAudit.Core.Config;

/// <summary>Identifies which firewall provider(s) RdpAudit should drive when applying block actions.</summary>
/// <remarks>
/// Append-only enum: values must NEVER be reused or reordered. New providers receive a new ordinal.
/// </remarks>
public enum FirewallProviderKind
{
	/// <summary>No firewall integration; block actions are recorded in the database only.</summary>
	None = 0,

	/// <summary>Windows Advanced Firewall (netsh advfirewall) on the local host.</summary>
	Windows = 1,

	/// <summary>External MikroTik RouterOS device driven via the REST API.</summary>
	MikroTik = 2,

	/// <summary>Both Windows and MikroTik providers are driven in sequence.</summary>
	Both = 3,
}
