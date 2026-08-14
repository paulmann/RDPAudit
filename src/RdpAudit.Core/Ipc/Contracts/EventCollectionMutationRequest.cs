/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 2.0.0
// File   : EventCollectionMutationRequest.cs
// Project: RdpAudit.Core (RdpAudit.Core.Ipc.Contracts)
// Purpose: Carries explicit event settings or a server-expanded named preset for Event Collection IPC writes.
// Depends: MessagePack, EventCollectionSettingsDto, EventPreset
// Extends: Append fields only when a new Event Collection mutation needs persisted parameters.

using MessagePack;
using RdpAudit.Core.Events;

namespace RdpAudit.Core.Ipc.Contracts;

/// <summary>Request payload for saving Event Collection settings or applying a named preset.</summary>
[MessagePackObject(keyAsPropertyName: false)]
public sealed class EventCollectionMutationRequest
{
	/// <summary>Explicit rows to save when <see cref="Preset"/> is <see cref="EventPreset.Custom"/>.</summary>
	[Key(0)]
	public List<EventCollectionSettingsDto> Settings { get; set; } = new();

	/// <summary>Named preset to expand on the service from <see cref="EventCatalog"/>.</summary>
	[Key(1)]
	public EventPreset Preset { get; set; } = EventPreset.Custom;
}
