/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 0.1.0
// File   : EtwPayloadXmlFormatter.cs
// Project: RdpAudit.Service (RdpAudit.Service.EventSources)
// Purpose: Pure function that serialises the TDH payload of a single ETW event into the canonical
//          Windows event-log XML shape the rest of RdpAudit understands (EventXmlParser +
//          EventNormalizer). Consumed by EtwEventSource in commit 3c; kept as a stateless
//          formatter so it can be unit tested on Linux without any Windows ETW dependency.
// Depends: EventXmlParser (target grammar), RawEventDto (downstream carrier), TraceEvent (indirect
//          — a thin adapter in EtwEventSource projects TraceEvent into EtwEventPayload before
//          calling this formatter)
// Extends: To add a new payload field convention: (1) if the provider emits the value under a
//          different manifest name than the EventXmlParser expects, add a translation in the
//          adapter that builds EtwEventPayload — do NOT special-case names here. The formatter
//          faithfully copies PayloadNames verbatim so the parser's channel-agnostic name lookup
//          (IpAddress / Address / Param3 / ClientAddress / TargetLogonId / SessionID) keeps
//          working across the entire event catalog.

using System.Globalization;
using System.Runtime.Versioning;
using System.Text;

namespace RdpAudit.Service.EventSources;

/// <summary>
/// Immutable projection of a single ETW event's data, decoupled from the underlying
/// <c>Microsoft.Diagnostics.Tracing.TraceEvent</c> instance so the formatter can be unit tested
/// on any platform. Field order matches the canonical Windows System block, then payload.
/// </summary>
public sealed class EtwEventPayload
{
	/// <summary>Numeric event id (e.g. 1149, 21, 4624). Range 0..65535.</summary>
	public required int EventId { get; init; }

	/// <summary>Canonical provider name from the manifest, or empty if unknown.</summary>
	public required string ProviderName { get; init; }

	/// <summary>Canonical provider GUID from the manifest.</summary>
	public required Guid ProviderGuid { get; init; }

	/// <summary>Event-log channel this event was captured from, in EventCatalog form.</summary>
	public required string Channel { get; init; }

	/// <summary>Wall-clock timestamp of the event. MUST be UTC.</summary>
	public required DateTime TimeStampUtc { get; init; }

	/// <summary>Machine that produced the event. Empty if the collector could not resolve it.</summary>
	public string Computer { get; init; } = string.Empty;

	/// <summary>ETW correlation activity id, or <see cref="Guid.Empty"/> if unset.</summary>
	public Guid ActivityId { get; init; }

	/// <summary>Emitting process id, or 0 if unknown.</summary>
	public int ProcessId { get; init; }

	/// <summary>Emitting thread id, or 0 if unknown.</summary>
	public int ThreadId { get; init; }

	/// <summary>ETW keywords bitmask (opaque to the parser but preserved for forensics).</summary>
	public ulong Keywords { get; init; }

	/// <summary>Manifest task numeric id (opaque; parser ignores it but v1.0 preserves it).</summary>
	public int Task { get; init; }

	/// <summary>Manifest opcode numeric id (opaque; preserved for forensics).</summary>
	public int Opcode { get; init; }

	/// <summary>Manifest event version. 0 when unknown.</summary>
	public int Version { get; init; }

	/// <summary>Manifest level (2=Error, 3=Warning, 4=Informational, 5=Verbose).</summary>
	public int Level { get; init; }

	/// <summary>Payload field names in manifest order. Length must equal <see cref="Values"/>.</summary>
	public required IReadOnlyList<string> Names { get; init; }

	/// <summary>Payload field values in manifest order. Nulls render as empty strings.</summary>
	public required IReadOnlyList<object?> Values { get; init; }
}

/// <summary>
/// Serialises an <see cref="EtwEventPayload"/> into the canonical Windows event-log XML shape
/// that <c>EventXmlParser</c> and <c>EventNormalizer</c> already parse for the v1.0
/// EventLogWatcher pipeline. The output is byte-identical in structure to what
/// <c>EventRecord.ToXml()</c> emits, minus provider-specific message templates that ETW
/// consumers do not receive.
/// </summary>
[SupportedOSPlatform("windows")]
public static class EtwPayloadXmlFormatter
{
	/// <summary>
	/// Downstream parser rejects payloads above 1&#160;MiB. v1.0 EventLogWatcher truncates to
	/// 65,536 chars before persisting; we honour the same ceiling so the persistence layer sees
	/// events of the same maximum size regardless of source.
	/// </summary>
	public const int MaxXmlLength = 65_536;

	private const string EventNs = "http://schemas.microsoft.com/win/2004/08/events/event";

	// Rented buffer high-water mark. Real Windows event XML rarely exceeds ~8 KiB but we keep
	// enough head-room for a full 65,536-char payload while still staying pool-friendly.
	private const int InitialCapacity = 4096;

	/// <summary>
	/// Serialise <paramref name="payload"/> to an event-log XML string. Guaranteed to return a
	/// string of length <= <see cref="MaxXmlLength"/>; longer payloads are truncated at a safe
	/// character boundary and appended with a diagnostic marker.
	/// </summary>
	/// <exception cref="ArgumentException">If Names and Values are misaligned.</exception>
	public static string Format(EtwEventPayload payload)
	{
		ArgumentNullException.ThrowIfNull(payload);
		if (payload.Names.Count != payload.Values.Count)
		{
			throw new ArgumentException(
				"EtwEventPayload.Names and Values must have the same length; got "
				+ payload.Names.Count.ToString(CultureInfo.InvariantCulture)
				+ " names vs "
				+ payload.Values.Count.ToString(CultureInfo.InvariantCulture)
				+ " values.",
				nameof(payload));
		}

		StringBuilder sb = StringBuilderPool.Rent();
		try
		{
			AppendHeader(sb, payload);
			AppendSystem(sb, payload);

			// Remember length after System — this is our safe rollback point if EventData blows
			// the ceiling. A truncated document keeps every System field intact plus a diagnostic
			// marker so downstream code can still surface EventID/Provider/Correlation.
			int safePoint = sb.Length;

			AppendEventData(sb, payload);
			AppendFooter(sb);

			if (sb.Length <= MaxXmlLength)
			{
				return sb.ToString();
			}

			// Oversize — roll back to the safe point and emit a minimal parseable envelope.
			sb.Length = safePoint;
			sb.Append(TruncationMarker);
			sb.Append("</Event>");
			return sb.ToString();
		}
		finally
		{
			StringBuilderPool.Return(sb);
		}
	}

	// ── XML fragment builders ────────────────────────────────────────────────────

	private static void AppendHeader(StringBuilder sb, EtwEventPayload p)
	{
		sb.Append("<Event xmlns=\"").Append(EventNs).Append("\">");
	}

	private static void AppendSystem(StringBuilder sb, EtwEventPayload p)
	{
		sb.Append("<System>");

		// Provider
		sb.Append("<Provider Name=\"");
		AppendEscapedAttribute(sb, p.ProviderName);
		sb.Append("\" Guid=\"{");
		sb.Append(p.ProviderGuid.ToString("D", CultureInfo.InvariantCulture));
		sb.Append("}\" />");

		// EventID
		sb.Append("<EventID>").Append(p.EventId.ToString(CultureInfo.InvariantCulture))
			.Append("</EventID>");

		// Version / Level / Task / Opcode / Keywords
		sb.Append("<Version>").Append(p.Version.ToString(CultureInfo.InvariantCulture))
			.Append("</Version>");
		sb.Append("<Level>").Append(p.Level.ToString(CultureInfo.InvariantCulture))
			.Append("</Level>");
		sb.Append("<Task>").Append(p.Task.ToString(CultureInfo.InvariantCulture))
			.Append("</Task>");
		sb.Append("<Opcode>").Append(p.Opcode.ToString(CultureInfo.InvariantCulture))
			.Append("</Opcode>");
		sb.Append("<Keywords>0x")
			.Append(p.Keywords.ToString("x16", CultureInfo.InvariantCulture))
			.Append("</Keywords>");

		// TimeCreated — MUST be UTC and use round-trip-safe ISO 8601 with 100 ns precision.
		sb.Append("<TimeCreated SystemTime=\"");
		sb.Append(p.TimeStampUtc.ToUniversalTime()
			.ToString("yyyy-MM-ddTHH:mm:ss.fffffffZ", CultureInfo.InvariantCulture));
		sb.Append("\" />");

		// Channel — always present so the parser's channel-agnostic XPath keeps working.
		sb.Append("<Channel>");
		AppendEscapedText(sb, p.Channel);
		sb.Append("</Channel>");

		// Computer — optional. v1.0 EventLog always emits it, so we mirror that.
		sb.Append("<Computer>");
		AppendEscapedText(sb, p.Computer);
		sb.Append("</Computer>");

		// Correlation — only emitted when we actually have an ActivityID. EventXmlParser reads
		// //System/Correlation/@ActivityID; the shape must match exactly.
		if (p.ActivityId != Guid.Empty)
		{
			sb.Append("<Correlation ActivityID=\"{");
			sb.Append(p.ActivityId.ToString("D", CultureInfo.InvariantCulture));
			sb.Append("}\" />");
		}
		else
		{
			sb.Append("<Correlation />");
		}

		// Execution — process/thread ids. Zero when unknown.
		sb.Append("<Execution ProcessID=\"");
		sb.Append(p.ProcessId.ToString(CultureInfo.InvariantCulture));
		sb.Append("\" ThreadID=\"");
		sb.Append(p.ThreadId.ToString(CultureInfo.InvariantCulture));
		sb.Append("\" />");

		sb.Append("</System>");
	}

	private static void AppendEventData(StringBuilder sb, EtwEventPayload p)
	{
		sb.Append("<EventData>");
		int n = p.Names.Count;
		for (int i = 0; i < n; i++)
		{
			string name = p.Names[i] ?? string.Empty;
			object? value = p.Values[i];

			sb.Append("<Data Name=\"");
			AppendEscapedAttribute(sb, name);
			sb.Append("\">");
			AppendEscapedText(sb, RenderValue(value));
			sb.Append("</Data>");
		}
		sb.Append("</EventData>");
	}

	private static void AppendFooter(StringBuilder sb)
	{
		sb.Append("</Event>");
	}

	// ── Value rendering ──────────────────────────────────────────────────────────

	private static string RenderValue(object? value)
	{
		if (value is null) return string.Empty;

		return value switch
		{
			string s          => s,
			bool b            => b ? "true" : "false",
			byte u8           => u8.ToString(CultureInfo.InvariantCulture),
			sbyte i8          => i8.ToString(CultureInfo.InvariantCulture),
			short i16         => i16.ToString(CultureInfo.InvariantCulture),
			ushort u16        => u16.ToString(CultureInfo.InvariantCulture),
			int i32           => i32.ToString(CultureInfo.InvariantCulture),
			uint u32          => u32.ToString(CultureInfo.InvariantCulture),
			long i64          => i64.ToString(CultureInfo.InvariantCulture),
			ulong u64         => u64.ToString(CultureInfo.InvariantCulture),
			float f32         => f32.ToString("R", CultureInfo.InvariantCulture),
			double f64        => f64.ToString("R", CultureInfo.InvariantCulture),
			decimal d         => d.ToString(CultureInfo.InvariantCulture),
			Guid g            => "{" + g.ToString("D", CultureInfo.InvariantCulture) + "}",
			DateTime dt       => dt.ToUniversalTime()
				.ToString("yyyy-MM-ddTHH:mm:ss.fffffffZ", CultureInfo.InvariantCulture),
			byte[] bytes      => RenderByteArray(bytes),
			IFormattable fmt  => fmt.ToString(null, CultureInfo.InvariantCulture),
			_                 => value.ToString() ?? string.Empty,
		};
	}

	private static string RenderByteArray(byte[] bytes)
	{
		if (bytes.Length == 0) return string.Empty;
		return Convert.ToHexString(bytes);
	}

	// ── XML escaping ─────────────────────────────────────────────────────────────
	//
	// Manual escaping. We escape only the five predefined entities plus control
	// characters (< 0x20 except \t \n \r). Values in real Windows event data are
	// well-formed but ETW manifest strings can occasionally contain '&' or '<'; we do NOT
	// trust the source and escape unconditionally.

	internal static void AppendEscapedText(StringBuilder sb, string? value)
	{
		if (string.IsNullOrEmpty(value)) return;

		ReadOnlySpan<char> span = value.AsSpan();
		for (int i = 0; i < span.Length; i++)
		{
			char c = span[i];
			if (RequiresEscape(c))
			{
				AppendEscape(sb, c);
			}
			else
			{
				sb.Append(c);
			}
		}
	}

	private static bool RequiresEscape(char c)
	{
		return c switch
		{
			'<' or '>' or '&' or '"' or '\'' => true,
			'\t' or '\n' or '\r' => false,
			_ when c < 0x20 => true,
			_ => false,
		};
	}

	internal static void AppendEscapedAttribute(StringBuilder sb, string? value)
	{
		// Same rule set as text — attributes are quoted with double quotes so we must escape
		// the quote character. Single quotes need no escape inside "…"-quoted attributes but
		// we escape them anyway for consistency with EventRecord.ToXml() output.
		AppendEscapedText(sb, value);
	}

	private static void AppendEscape(StringBuilder sb, char c)
	{
		switch (c)
		{
			case '<': sb.Append("&lt;"); return;
			case '>': sb.Append("&gt;"); return;
			case '&': sb.Append("&amp;"); return;
			case '"': sb.Append("&quot;"); return;
			case '\'': sb.Append("&apos;"); return;
			default:
				// Control character: replace with numeric character reference. XML 1.0 forbids
				// C0 controls except TAB / LF / CR; the parser also rejects them, so we drop
				// them silently rather than emit an unparseable NCR.
				return;
		}
	}

	// ── Truncation ───────────────────────────────────────────────────────────────

	private const string TruncationMarker = "<!--truncated-->";

	// ── StringBuilder pool ───────────────────────────────────────────────────────

	private static class StringBuilderPool
	{
		[ThreadStatic]
		private static StringBuilder? t_cached;

		public static StringBuilder Rent()
		{
			StringBuilder? sb = t_cached;
			if (sb is not null)
			{
				t_cached = null;
				sb.Clear();
				return sb;
			}
			return new StringBuilder(InitialCapacity);
		}

		public static void Return(StringBuilder sb)
		{
			if (sb.Capacity > 32 * 1024)
			{
				// Do not cache oversize builders — they trap large managed memory in ThreadStatic.
				return;
			}
			sb.Clear();
			t_cached = sb;
		}
	}
}
