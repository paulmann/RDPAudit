/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 2.0.0
// File   : EventCriticality.cs
// Project: RdpAudit.Core (RdpAudit.Core.Events)
// Purpose: Ordered severity classification for a monitored Windows event id. Drives Configurator
//          colour-coding, default alert routing, and forensic retention floors. Values are
//          numerically ordered so callers can compare with <, > without a lookup table.
// Depends: (none)
// Extends: When a new severity level is required, insert it in numeric order and shift the
//          higher values. Never renumber existing values — persisted rows compare against them.

using System.Diagnostics.CodeAnalysis;

namespace RdpAudit.Core.Events;

/// <summary>Severity classification for a monitored Windows event id.</summary>
[SuppressMessage("Design", "CA1028:Enum storage should be Int32", Justification =
	"The narrow underlying type is a storage contract, not an oversight: values are persisted verbatim into fixed-size shard records and audit rows, where widening to Int32 would inflate every record and break binary compatibility with shards already on disk.")]
public enum EventCriticality : byte
{
	/// <summary>Non-security telemetry. Retained for context; never fires an alert by itself.</summary>
	Informational = 0,

	/// <summary>Routine security-relevant event; useful for context but not for standalone alerts.</summary>
	Low = 1,

	/// <summary>Notable event. May fire an alert when combined with correlated context.</summary>
	Medium = 2,

	/// <summary>Strong indicator on its own; deserves an alert unless whitelisted.</summary>
	High = 3,

	/// <summary>Highest severity: tampering, forensic-critical, or post-compromise footprint.
	/// First occurrence per source MUST be retained forever regardless of prune policy.</summary>
	Critical = 4,
}
