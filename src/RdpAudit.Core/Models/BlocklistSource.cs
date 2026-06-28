// File:    src/RdpAudit.Core/Models/BlocklistSource.cs
// Module:  RdpAudit.Core.Models
// Purpose: Identifies the origin of a BlocklistEntry / WhitelistEntry / LoginRule record so the
//          source of truth (manual operator action vs automatic rule evaluation vs external feed)
//          is auditable across upgrades.
// Extends: System.Enum
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

namespace RdpAudit.Core.Models;

/// <summary>Origin of a blocklist / whitelist / login-rule record.</summary>
/// <remarks>
/// Append-only enum: ordinals are persisted to SQLite and MUST NEVER be reused or reordered.
/// New sources receive a new ordinal at the end of the list.
/// </remarks>
public enum BlocklistSource
{
	/// <summary>Unknown / unset source. Reserved for migrations that cannot infer the real source.</summary>
	Unknown = 0,

	/// <summary>Created manually by an operator via the Configurator UI or IPC.</summary>
	Manual = 1,

	/// <summary>Created automatically by an internal rule (threshold, threat-score, etc.).</summary>
	Auto = 2,

	/// <summary>Imported from a Windows Advanced Firewall rule discovered on the host.</summary>
	Firewall = 3,

	/// <summary>Imported from an AbuseIPDB lookup response.</summary>
	AbuseIpDb = 4,

	/// <summary>Imported from a MikroTik RouterOS address-list synchronisation pass.</summary>
	MikroTik = 5,

	/// <summary>Created from the LiveEvents context menu in the Configurator.</summary>
	LiveEvents = 6,
}
