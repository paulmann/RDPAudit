/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// File   : ZabbixSenderProtocol.cs
// Project: RdpAudit.Core (RdpAudit.Core.Zabbix)
// Purpose: Encode and decode the Zabbix sender protocol without any I/O, so the frame layout, the
//          JSON escaping and the response accounting can be tested without a server. Measured on
//          2026-10-25 against Zabbix 8.0.0: the server answers
//          {"response":"success","info":"processed: 1; failed: 0; total: 1; seconds spent: ..."}
//          and answers exactly the same shape when every value was rejected - the envelope says
//          success while nothing was stored. Delivery therefore means failed == 0 and total > 0.
// Extends: System.Object

using System.Buffers.Binary;
using System.Globalization;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;

namespace RdpAudit.Core.Zabbix;

/// <summary>One key/value pair addressed to a Zabbix host.</summary>
/// <param name="Host">Technical host name, exactly as it is spelled in Zabbix.</param>
/// <param name="Key">Item key.</param>
/// <param name="Value">Item value as text; the server parses it according to the item's value type.</param>
public sealed record ZabbixValue(string Host, string Key, string Value);

/// <summary>Result of one sender round-trip.</summary>
/// <param name="ProtocolAccepted">True when the server answered in the sender envelope at all. This
/// does <b>not</b> mean the values were stored.</param>
/// <param name="Processed">Values the server accepted.</param>
/// <param name="Failed">Values the server rejected (unknown host, unknown key, wrong value type).</param>
/// <param name="Total">Values in the batch.</param>
/// <param name="Message">Human-readable summary, safe to log and to show.</param>
/// <param name="Raw">Raw response body, truncated, for diagnostics.</param>
public sealed record ZabbixSenderOutcome(
	bool ProtocolAccepted,
	int Processed,
	int Failed,
	int Total,
	string Message,
	string Raw)
{
	/// <summary>True only when the server accepted every value in the batch.</summary>
	public bool Delivered => ProtocolAccepted && Total > 0 && Failed == 0 && Processed == Total;
}

/// <summary>Encoder and response parser for the Zabbix sender protocol.</summary>
public static partial class ZabbixSenderProtocol
{
	/// <summary>Frame header: <c>ZBXD</c> plus the flags byte, <c>0x01</c> for uncompressed JSON.</summary>
	public static ReadOnlySpan<byte> Header => "ZBXD\x01"u8;

	/// <summary>Length of the frame prefix: 4 magic bytes, 1 flags byte and 8 length bytes.</summary>
	public const int HeaderLength = 13;

	/// <summary>Upper bound on the response body accepted from the server (1 MiB).</summary>
	public const int MaxResponseBytes = 1024 * 1024;

	/// <summary>Upper bound on one pushed value; Zabbix stores up to 64 KiB of text per item.</summary>
	public const int MaxValueLength = 60_000;

	/// <summary>Serializes the request that follows the header.</summary>
	/// <param name="values">Values to send; an empty list is refused, because an empty batch would be
	/// reported by the server as <c>total: 0</c> and look like a successful push.</param>
	/// <param name="clockUtc">Moment the batch was built; the server uses it unless it arrives without
	/// one. Second resolution is enough: duplicates collide only inside the same second.</param>
	public static string BuildRequestJson(IReadOnlyList<ZabbixValue> values, DateTime clockUtc)
	{
		ArgumentNullException.ThrowIfNull(values);
		if (values.Count == 0)
		{
			throw new ArgumentException("A sender batch must contain at least one value.", nameof(values));
		}

		ZabbixSenderRequest request = new()
		{
			Request = "sender data",
			Clock = new DateTimeOffset(clockUtc, TimeSpan.Zero).ToUnixTimeSeconds(),
			Data = new List<ZabbixSenderValue>(values.Count),
		};

		foreach (ZabbixValue value in values)
		{
			request.Data.Add(new ZabbixSenderValue { Host = value.Host, Key = value.Key, Value = value.Value });
		}

		return JsonSerializer.Serialize(request, ZabbixJson.Options);
	}

	/// <summary>Builds the complete frame: header, little-endian payload length, payload.</summary>
	/// <param name="requestJson">Payload produced by <see cref="BuildRequestJson"/>.</param>
	public static byte[] BuildFrame(string requestJson)
	{
		ArgumentException.ThrowIfNullOrEmpty(requestJson);
		byte[] payload = Encoding.UTF8.GetBytes(requestJson);
		byte[] frame = new byte[HeaderLength + payload.Length];
		Header.CopyTo(frame);
		BinaryPrimitives.WriteUInt64LittleEndian(frame.AsSpan(5, 8), (ulong)payload.Length);
		payload.CopyTo(frame, HeaderLength);
		return frame;
	}

	/// <summary>Validates the 13-byte answer prefix and extracts the body length.</summary>
	/// <param name="prefix">Exactly <see cref="HeaderLength"/> bytes read from the socket.</param>
	/// <param name="length">Body length announced by the server.</param>
	/// <returns>False when the server did not answer in the sender envelope (for example an HTTP error
	/// page served on the wrong port, or a proxy banner).</returns>
	public static bool TryReadHeader(ReadOnlySpan<byte> prefix, out int length)
	{
		length = 0;
		if (prefix.Length < HeaderLength)
		{
			return false;
		}

		if (!prefix[..4].SequenceEqual("ZBXD"u8))
		{
			return false;
		}

		ulong raw = BinaryPrimitives.ReadUInt64LittleEndian(prefix[5..13]);
		if (raw == 0 || raw > MaxResponseBytes)
		{
			return false;
		}

		length = (int)raw;
		return true;
	}

	/// <summary>Parses a response body into processed/failed/total counters.</summary>
	/// <param name="body">Body read after the header.</param>
	public static ZabbixSenderOutcome ParseResponse(string? body)
	{
		if (string.IsNullOrWhiteSpace(body))
		{
			return new ZabbixSenderOutcome(false, 0, 0, 0, "The server closed the connection without an answer.", string.Empty);
		}

		string trimmed = body.Trim();
		string raw = trimmed.Length <= 400 ? trimmed : trimmed[..400];

		bool responseSuccess = trimmed.Contains("\"response\":\"success\"", StringComparison.Ordinal)
			|| trimmed.Contains("\"response\": \"success\"", StringComparison.Ordinal);
		if (!responseSuccess)
		{
			return new ZabbixSenderOutcome(false, 0, 0, 0, "The server refused the batch: " + raw, raw);
		}

		Match match = InfoPattern().Match(trimmed);
		if (!match.Success)
		{
			// "success" without counters is not a delivery: without the numbers there is no evidence
			// that any value was stored, so it is reported as accepted-but-unaccounted.
			return new ZabbixSenderOutcome(true, 0, 0, 0,
				"The server accepted the request but reported no counters; delivery is unconfirmed.", raw);
		}

		int processed = ParseCounter(match.Groups["processed"].Value);
		int failed = ParseCounter(match.Groups["failed"].Value);
		int total = ParseCounter(match.Groups["total"].Value);

		string message = failed == 0 && total > 0
			? string.Format(CultureInfo.InvariantCulture, "Accepted {0} of {1} value(s).", processed, total)
			: string.Format(CultureInfo.InvariantCulture,
				"Server rejected {0} of {1} value(s); unknown host or item key, or a value that does not match the item type.",
				failed, total);

		return new ZabbixSenderOutcome(true, processed, failed, total, message, raw);
	}

	private static int ParseCounter(string raw)
		=> int.TryParse(raw, NumberStyles.Integer, CultureInfo.InvariantCulture, out int parsed) ? parsed : 0;

	/// <summary>Extracts the counters from the <c>info</c> string of the sender answer.</summary>
	[GeneratedRegex(
		@"processed:\s*(?<processed>\d+);\s*failed:\s*(?<failed>\d+);\s*total:\s*(?<total>\d+)",
		RegexOptions.CultureInvariant)]
	private static partial Regex InfoPattern();

	/// <summary>Wire shape of the sender request; property names are part of the protocol.</summary>
	private sealed class ZabbixSenderRequest
	{
		[JsonPropertyName("request")]
		public string Request { get; set; } = "sender data";

		[JsonPropertyName("data")]
		public List<ZabbixSenderValue> Data { get; set; } = new();

		[JsonPropertyName("clock")]
		public long Clock { get; set; }
	}

	/// <summary>Wire shape of one value in the sender request.</summary>
	private sealed class ZabbixSenderValue
	{
		[JsonPropertyName("host")]
		public string Host { get; set; } = string.Empty;

		[JsonPropertyName("key")]
		public string Key { get; set; } = string.Empty;

		[JsonPropertyName("value")]
		public string Value { get; set; } = string.Empty;
	}

	/// <summary>Serializer settings for the protocol payload: no naming policy, no enum converters,
	/// no indentation — the server parses exactly what the documented format says.</summary>
	private static class ZabbixJson
	{
		internal static readonly JsonSerializerOptions Options = new()
		{
			WriteIndented = false,
			DefaultIgnoreCondition = JsonIgnoreCondition.Never,
		};
	}
}
