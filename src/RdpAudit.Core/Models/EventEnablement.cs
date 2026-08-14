/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 2.0.0
// File   : EventEnablement.cs
// Project: RdpAudit.Core (RdpAudit.Core.Models)
// Purpose: Stores an explicit enabled or disabled override for a Windows event identifier.
// Depends: (none)
// Extends: Add source-channel scope only if enablement becomes channel-specific.

namespace RdpAudit.Core.Models;

/// <summary>Explicit collection enablement override for a Windows event identifier.</summary>
public sealed class EventEnablement
{
	/// <summary>Windows event identifier and primary key.</summary>
	public int EventId { get; set; }
	/// <summary>Whether collection of the event is enabled.</summary>
	public bool IsEnabled { get; set; }
	/// <summary>UTC ticks of the latest update.</summary>
	public long UpdatedUtc { get; set; }
}
