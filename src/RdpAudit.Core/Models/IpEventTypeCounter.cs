/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 2.0.0
// File   : IpEventTypeCounter.cs
// Project: RdpAudit.Core (RdpAudit.Core.Models)
// Purpose: Stores a durable counter for each canonical IP and Windows event identifier pair.
// Depends: (none)
// Extends: Keep the composite key stable when adding event classification metadata.

namespace RdpAudit.Core.Models;

/// <summary>Per-event identifier aggregate for one canonical source IP.</summary>
public sealed class IpEventTypeCounter
{
	/// <summary>Canonical 16-byte IPv6-mapped binary IP key.</summary>
	public byte[] IpBinary16 { get; set; } = [];
	/// <summary>Windows event identifier.</summary>
	public int EventId { get; set; }
	/// <summary>Total number of matching events.</summary>
	public long Count { get; set; }
	/// <summary>UTC ticks of the first matching event.</summary>
	public long FirstUtc { get; set; }
	/// <summary>UTC ticks of the most recent matching event.</summary>
	public long LastUtc { get; set; }
}
