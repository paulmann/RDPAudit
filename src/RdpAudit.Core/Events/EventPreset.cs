/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 2.0.0
// File   : EventPreset.cs
// Project: RdpAudit.Core (RdpAudit.Core.Events)
// Purpose: [Flags] set of preset memberships for a monitored event id. A single event may
//          participate in several presets (e.g. 4625 is in Minimal, Essential, and Full).
//          Each preset is one bit, so preset intersection and union are single AND/OR ops.
// Depends: System
// Extends: When a new preset is introduced (e.g. Compliance), add a new power-of-two value
//          below Custom. Never renumber existing values — appsettings and audit rows carry them.

using System.Diagnostics.CodeAnalysis;

namespace RdpAudit.Core.Events;

/// <summary>Bitfield describing which named presets a given event id participates in.
/// Multiple bits may be set at once; <see cref="Custom"/> is a UI-only marker that means
/// "the current active set does not match any named preset".</summary>
[Flags]
[SuppressMessage("Design", "CA1028:Enum storage should be Int32", Justification =
	"The narrow underlying type is a storage contract, not an oversight: values are persisted verbatim into fixed-size shard records and audit rows, where widening to Int32 would inflate every record and break binary compatibility with shards already on disk.")]
public enum EventPreset : byte
{
	/// <summary>Not part of any named preset. Included only when the operator adds it by hand.</summary>
	None = 0,

	/// <summary>Smallest useful set: successful logon, failed logon, and lockout.
	/// The operator has explicitly asked for the minimum forensic surface.</summary>
	Minimal = 1 << 0,

	/// <summary>Recommended balanced default: the Minimal set plus session lifecycle, RDP
	/// pre-auth network events, and account-tampering evidence.</summary>
	Essential = 1 << 1,

	/// <summary>Everything the catalog knows about, including process creation and object access
	/// events. Requires that SACL / auditpol prerequisites be satisfied on the host.</summary>
	Full = 1 << 2,

	/// <summary>UI marker: the active enablement set diverges from every named preset.
	/// Never persisted alongside events; only surfaces in the Configurator's preset combo.</summary>
	Custom = 1 << 7,
}
