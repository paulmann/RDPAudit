/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 2.0.0
// File   : IngestionSequence.cs
// Project: RdpAudit.Core (RdpAudit.Core.Models)
// Purpose: Holds the durable monotonic ingestion sequence sidecar used by transactional event writers.
// Depends: (none)
// Extends: Preserve the singleton key and update allocation logic if sequence ownership changes.

namespace RdpAudit.Core.Models;

/// <summary>Singleton sidecar containing the next durable ingestion sequence value.</summary>
public sealed class IngestionSequence
{
	/// <summary>Singleton primary key, always one.</summary>
	public int Id { get; set; }
	/// <summary>Next sequence value to allocate.</summary>
	public long NextValue { get; set; }
}
