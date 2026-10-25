// File:    src/RdpAudit.Core/Siem/SiemJsonSerializer.cs
// Module:  RdpAudit.Core.Siem
// Purpose: Pure NDJSON renderer for the neutral SiemEvent stream: one JSON object per line.
//          Uses camelCase property names, camelCase enum strings ("event" / "alert"), null
//          properties omitted, uncompressed output. DateTimes always render as an explicit
//          UTC instant (trailing Z): Kind=Unspecified values produced by the SQLite round-trip
//          are re-marked as UTC without any local time-zone shift. The default JavaScriptEncoder
//          is the strict encoder: embedded CR / LF / TAB and control characters are escaped as
//          JSON escapes, so an external value can never inject a record boundary or corrupt a
//          consumer. The final record has no trailing newline. No I/O.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace RdpAudit.Core.Siem;

/// <summary>Pure NDJSON renderer. One JSON object per line, LF line endings, no trailing newline.</summary>
public sealed class SiemJsonSerializer : ISiemEventSerializer
{
	private static readonly JsonSerializerOptions Options = new()
	{
		PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
		DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
		Converters =
		{
			new UtcNormalizingDateTimeConverter(),
			new JsonStringEnumConverter(JsonNamingPolicy.CamelCase),
		},
		WriteIndented = false,
		PropertyNameCaseInsensitive = true,
	};

	/// <inheritdoc />
	public string Format(IEnumerable<SiemEvent> events)
	{
		ArgumentNullException.ThrowIfNull(events);

		StringBuilder sb = new();
		foreach (SiemEvent e in events)
		{
			ArgumentNullException.ThrowIfNull(e);
			sb.Append(JsonSerializer.Serialize(e, Options)).Append('\n');
		}

		return sb.Length == 0 ? string.Empty : sb.ToString(0, sb.Length - 1);
	}
}
