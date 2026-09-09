/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 2.0.0
// File   : EventCollectionAudit.cs
// Project: RdpAudit.Core (RdpAudit.Core.Models)
// Purpose: Persists SOC2-relevant changes to event collection and retention settings.
// Depends: (none)
// Extends: Append new audit kinds without renumbering existing persisted values.

namespace RdpAudit.Core.Models;

/// <summary>Audit record for a collection-policy or event-enablement change.</summary>
public sealed class EventCollectionAudit
{
	/// <summary>Surrogate primary key.</summary>
	public long Id { get; set; }
	/// <summary>UTC ticks when the change occurred.</summary>
	public long OccurredUtc { get; set; }
	/// <summary>Security identifier of the account that invoked the change.</summary>
	public string InvokerSid { get; set; } = string.Empty;
	/// <summary>Account name of the invoker.</summary>
	public string InvokerAccount { get; set; } = string.Empty;
	/// <summary>Persisted change kind.</summary>
	public int Kind { get; set; }
	/// <summary>Event identifier affected by the change, if applicable.</summary>
	public int? EventId { get; set; }
	/// <summary>Previous value, if applicable.</summary>
	public string? OldValue { get; set; }
	/// <summary>New value, if applicable.</summary>
	public string? NewValue { get; set; }
	/// <summary>Optional operator note.</summary>
	public string? Note { get; set; }
}
