/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 2.0.0
// File   : EventRetention.cs
// Project: RdpAudit.Core (RdpAudit.Core.Models)
// Purpose: Stores a per-event retention override consumed by the retention worker.
// Depends: (none)
// Extends: Add scope metadata only if retention overrides become channel-specific.

namespace RdpAudit.Core.Models;

/// <summary>Retention override for a Windows event identifier.</summary>
public sealed class EventRetention
{
	/// <summary>Windows event identifier and primary key.</summary>
	public int EventId { get; set; }
	/// <summary>Number of days to retain; zero means retain forever.</summary>
	public int RetentionDays { get; set; }
	/// <summary>UTC ticks of the latest update.</summary>
	public long UpdatedUtc { get; set; }
}
