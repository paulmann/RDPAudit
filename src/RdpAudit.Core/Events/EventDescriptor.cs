// File:    src/RdpAudit.Core/Events/EventDescriptor.cs
// Module:  RdpAudit.Core.Events
// Purpose: Static metadata about a single Windows event id we monitor.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

namespace RdpAudit.Core.Events;

/// <summary>Static metadata about a single Windows event id we monitor.</summary>
public sealed record EventDescriptor(
	int EventId,
	string Channel,
	string Description,
	string Layer);
