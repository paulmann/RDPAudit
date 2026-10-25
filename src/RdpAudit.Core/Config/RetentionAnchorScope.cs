/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 2.0.0
// File   : RetentionAnchorScope.cs
// Project: RdpAudit.Core (RdpAudit.Core.Config)
// Purpose: Selects how an information-density retention "code" is identified, and therefore what the
//          never-deletable anchor of that code means for an investigator.
// Depends: System.Enum
// Extends: Add a new scope only together with its planner key projection and its persistence scope
//          mapping in EventDeletionLedger.

namespace RdpAudit.Core.Config;

/// <summary>Identifies the granularity of an information-density retention code.</summary>
public enum RetentionAnchorScope
{
	/// <summary>
	/// One code per <c>(EventId, Channel)</c>. The single oldest record of that code on this host is
	/// the anchor, so first-ever observation of an event class is never lost. This is the default:
	/// it protects the smallest, most stable set of unique evidence.
	/// </summary>
	PerCode = 0,

	/// <summary>
	/// One code per <c>(EventId, Channel, source IP)</c>. Every source address keeps its own anchor,
	/// so first contact from each attacker survives pressure deletion. Costs more shared retention
	/// budget than <see cref="PerCode"/> because anchors and tails multiply by the source count.
	/// </summary>
	PerCodeAndIp = 1,
}
