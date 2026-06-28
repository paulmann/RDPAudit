// File:    src/RdpAudit.Core/Events/RawEventDto.cs
// Module:  RdpAudit.Core.Events
// Purpose: In-memory DTO carrying captured EventRecord data through the processing channel.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

namespace RdpAudit.Core.Events;

/// <summary>In-memory DTO carrying captured EventRecord data through the channel.</summary>
public sealed class RawEventDto
{
	public int EventId { get; set; }

	public string Channel { get; set; } = string.Empty;

	public DateTime TimeUtc { get; set; }

	public string XmlPayload { get; set; } = string.Empty;

	public string? SourceIp { get; set; }

	public string? UserName { get; set; }

	public string? Domain { get; set; }
}
