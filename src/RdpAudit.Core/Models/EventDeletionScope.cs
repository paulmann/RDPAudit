/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 2.0.0
// File   : EventDeletionScope.cs
// Project: RdpAudit.Core (RdpAudit.Core.Models)
// Purpose: Classifies how broadly an audited deletion ranged over source addresses, so a reader of
//          EventDeletionLedger can tell a host-wide compression pass from a per-attacker one.
// Depends: System.Enum
// Extends: Ordinals are append-only and persisted as integers - never reuse or reorder a value.

namespace RdpAudit.Core.Models;

/// <summary>Scope of an audited evidence deletion.</summary>
public enum EventDeletionScope
{
	/// <summary>One code for the whole host: <c>(EventId, Channel)</c>. <c>IpBinary16</c> is null.</summary>
	Global = 0,

	/// <summary>One code per source address: <c>(EventId, Channel, source IP)</c>. <c>IpBinary16</c>
	/// carries the canonical 16-byte key.</summary>
	PerIp = 1,
}
