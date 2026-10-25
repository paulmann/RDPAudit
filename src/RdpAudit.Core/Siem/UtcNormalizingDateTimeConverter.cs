// File:    src/RdpAudit.Core/Siem/UtcNormalizingDateTimeConverter.cs
// Module:  RdpAudit.Core.Siem
// Purpose: System.Text.Json converter that renders every DateTime as an explicit UTC instant.
//          SQLite does not persist Kind, so rows read back from the database arrive as
//          Kind=Unspecified; RdpAudit stores only UTC instants, therefore Unspecified is
//          re-interpreted as UTC (no local time-zone shift) and Local instants are converted
//          to UTC. Output keeps the default ISO-8601 shape (trailing Z, trimming-zero
//          fractions) so existing golden records stay byte-identical. The static ToUtc helper
//          is also used by the CEF / LEEF serializers which must honour the same UTC semantics.
// Extends: System.Text.Json.Serialization.JsonConverter<DateTime>
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System.Text.Json;
using System.Text.Json.Serialization;

namespace RdpAudit.Core.Siem;

/// <summary>Serializes DateTime values as explicit UTC (trailing Z); Unspecified is treated
/// as UTC rather than being shifted by the local time zone.</summary>
public sealed class UtcNormalizingDateTimeConverter : JsonConverter<DateTime>
{
	/// <summary>Converts the value to UTC: Local values are converted, Unspecified values are
	/// already UTC instants (SQLite round-trip) and are re-marked as UTC without any shift.</summary>
	public static DateTime ToUtc(DateTime value)
	{
		return value.Kind switch
		{
			DateTimeKind.Utc => value,
			DateTimeKind.Local => value.ToUniversalTime(),
			_ => DateTime.SpecifyKind(value, DateTimeKind.Utc),
		};
	}

	/// <inheritdoc />
	public override DateTime Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
	{
		if (reader.TokenType != JsonTokenType.String)
		{
			throw new JsonException("Expected a string DateTime value.");
		}

		return ToUtc(reader.GetDateTime());
	}

	/// <inheritdoc />
	public override void Write(Utf8JsonWriter writer, DateTime value, JsonSerializerOptions options)
	{
		writer.WriteStringValue(ToUtc(value));
	}
}
