// File:    src/RdpAudit.Core/Siem/ISiemEventSerializer.cs
// Module:  RdpAudit.Core.Siem
// Purpose: Single entry contract for the SIEM renderers: one format method that turns the neutral
//          SiemEvent sequence into the complete export text. Implementations are pure and must
//          neutralise embedded CR / LF / TAB before any external field reaches the output.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

namespace RdpAudit.Core.Siem;

/// <summary>SIEM export format kinds supported by the Core serializers.</summary>
public enum SiemFormat
{
	Cef = 0,
	Leef = 1,
	JsonNdjson = 2,
}

/// <summary>Contract of a pure SIEM event serializer. One model, three formats.</summary>
public interface ISiemEventSerializer
{
	/// <summary>Renders the whole event sequence into the format-specific text. An empty
	/// sequence yields an empty string. Implementations never write to disk.</summary>
	string Format(IEnumerable<SiemEvent> events);
}
