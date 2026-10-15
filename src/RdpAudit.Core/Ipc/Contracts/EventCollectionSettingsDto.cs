/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 2.0.0
// File   : EventCollectionSettingsDto.cs
// Project: RdpAudit.Core (RdpAudit.Core.Ipc.Contracts)
// Purpose: Transfers one catalog event and its effective collection and retention settings over IPC.
// Depends: MessagePack, EventCriticality
// Extends: Append fields only when the Event Collection page requires additional catalog metadata.

using MessagePack;
using RdpAudit.Core.Events;

namespace RdpAudit.Core.Ipc.Contracts;

/// <summary>Effective collection and retention settings for one catalog event.</summary>
[MessagePackObject(keyAsPropertyName: false)]
public sealed class EventCollectionSettingsDto
{
	[Key(0)]
	public int EventId { get; set; }

	[Key(1)]
	public string Channel { get; set; } = string.Empty;

	[Key(2)]
	public string DisplayName { get; set; } = string.Empty;

	[Key(3)]
	public string Description { get; set; } = string.Empty;

	[Key(4)]
	public EventCriticality Criticality { get; set; }

	[Key(5)]
	public string Layer { get; set; } = string.Empty;

	[Key(6)]
	public bool IsEnabled { get; set; }

	/// <summary>Retention duration in days; zero means retain the event forever.</summary>
	[Key(7)]
	public int RetentionDays { get; set; }
}
