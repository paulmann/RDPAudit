/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 2.0.0
// File   : EventDescriptor.cs
// Project: RdpAudit.Core (RdpAudit.Core.Events)
// Purpose: Static metadata about a single Windows event id we monitor. Positional signature is
//          kept intact so every existing `new(id, channel, description, layer)` call in the
//          codebase continues to compile; new fields are init-only properties with defaults.
// Depends: EventPreset, EventCriticality
// Extends: When adding a new descriptor field, add it as an init-only property with a
//          conservative default so unqualified `new(id, channel, desc, layer)` calls stay valid.

using System.Collections.Immutable;

namespace RdpAudit.Core.Events;

/// <summary>Static metadata about a single Windows event id we monitor. Constructed positionally
/// with (id, channel, description, layer) for backward compatibility; extended attributes are
/// set through an object initializer, e.g.
/// <c>new(4625, ChannelSecurity, "Failed logon", "Authentication") { Criticality = High }</c>.</summary>
public sealed record EventDescriptor(
	int EventId,
	string Channel,
	string Description,
	string Layer)
{
	/// <summary>Bitfield of the named presets this event participates in. Default: no preset
	/// membership, meaning the event is only collected when the operator opts in by hand.</summary>
	public EventPreset Preset { get; init; } = EventPreset.None;

	/// <summary>Severity classification. Default: <see cref="EventCriticality.Low"/> — a routine
	/// security-relevant event that is useful for context but not for standalone alerts.</summary>
	public EventCriticality Criticality { get; init; } = EventCriticality.Low;

	/// <summary>Event ids that must also be enabled for this event to be useful. For example,
	/// a rule keyed on 4778/4779 needs 4624/4625 alongside them to correlate the session.
	/// Empty when the event stands alone.</summary>
	public ImmutableArray<int> RequiredEventIds { get; init; } = ImmutableArray<int>.Empty;

	/// <summary>Default retention window in days for detail rows. <c>0</c> means "keep forever"
	/// (never pruned by <c>RetentionWorker</c>). The operator can override this per event id
	/// through the Configurator; the override is stored in the <c>EventRetention</c> table.</summary>
	public int DefaultRetentionDays { get; init; } = 180;

	/// <summary>Longer-form purpose text surfaced by the Configurator "Event Collection" tab.
	/// Defaults to <see cref="Description"/> so unqualified constructions still render.</summary>
	public string Purpose { get; init; } = string.Empty;

	/// <summary>Effective purpose: explicit <see cref="Purpose"/> if set, otherwise
	/// <see cref="Description"/>.</summary>
	public string EffectivePurpose
		=> string.IsNullOrEmpty(Purpose) ? Description : Purpose;

	/// <summary>True when the event is included in the given preset.</summary>
	public bool IsInPreset(EventPreset preset)
		=> (Preset & preset) != 0;
}
