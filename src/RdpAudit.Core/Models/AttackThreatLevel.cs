// File:    src/RdpAudit.Core/Models/AttackThreatLevel.cs
// Module:  RdpAudit.Core.Models
// Purpose: Cameyo / rdpmon-style threat-level classification used by the Attack Statistics tab.
//          Ordinals are append-only and mirror green / yellow / red dashboard semantics.
// Extends: System.Enum
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

namespace RdpAudit.Core.Models;

/// <summary>Cameyo-style threat classification derived from <see cref="AttackStat.ThreatScore"/>.</summary>
/// <remarks>
/// APPEND-ONLY ABI: ordinals must NEVER be reused, reordered, or renumbered. Future severities
/// are appended at the next ordinal so deployed Configurator / Service builds across version
/// skew never disagree on the meaning of a value sent over IPC.
/// </remarks>
public enum AttackThreatLevel
{
	/// <summary>Legitimate or low-risk activity — render green.</summary>
	Green = 0,

	/// <summary>Low-intensity failed connections — render yellow.</summary>
	Yellow = 1,

	/// <summary>High-intensity failures or likely brute force — render red.</summary>
	Red = 2,
}
