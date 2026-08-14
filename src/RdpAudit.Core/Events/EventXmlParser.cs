/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 2.0.1
// File   : EventXmlParser.cs
// Project: RdpAudit.Core (RdpAudit.Core.Events)
// Purpose: Hardened, back-compatible XML parser for Windows EventRecord serialized payloads.
//          Public surface (ParseSafe / GetData / GetInt / GetDataAt) is preserved 1:1 so
//          every existing caller (EventNormalizer, PerEventIpResolver, SecurityAuthProbeService,
//          existing tests) keeps working. Internal handling is hardened against XXE, entity
//          expansion, oversized documents, DTD injection, IO faults and malformed encoding.
//          Adds a new 2.0 helper set (ExtractSourceIp, ExtractLogonId, ExtractSessionId,
//          ExtractActivityId, PopulateFrom) that fills the new RawEventDto correlation fields
//          from event payloads. All heap allocations stay confined to the (documented) XmlDocument
//          construction — DOM is required by the legacy contract; the new helpers avoid it.
// Depends: EventCatalog, RawEventDto, EventLayer
// Extends: When adding parsers for new event ids, extend the switch in ExtractSourceIp /
//          PopulateFrom. Never widen XmlReaderSettings; if a legitimate payload trips a limit,
//          raise the limit deliberately in one place and document the reason.

using System.Globalization;
using System.Xml;

namespace RdpAudit.Core.Events;

/// <summary>Safe XML parser for Windows EventRecord serialized payloads. Read-only, thread-safe:
/// every method is stateless and reentrant.</summary>
public static class EventXmlParser
{
	// ── Hardening budgets ────────────────────────────────────────────────────────
	// These are intentionally generous for real Windows event payloads and hostile
	// for adversarial ones. A well-formed 4624 sits comfortably under 8 KiB; anything
	// larger than 1 MiB should not reach us because the collector already truncates
	// to MaxEventXmlLength (currently 256 KiB). The 1 MiB ceiling here is a second
	// line of defence in case that clip is bypassed.

	/// <summary>Hard ceiling on total characters processed by the reader. Anything larger
	/// short-circuits with a null result — never allocates a growing document.</summary>
	private const long MaxCharactersInDocument = 1L * 1024 * 1024;

	/// <summary>Hard ceiling on characters produced by entity expansion. DTD is prohibited so
	/// this is defence-in-depth — a malformed DOCTYPE that slips through still cannot bloat.</summary>
	private const long MaxCharactersInEntities = 4L * 1024;

	/// <summary>Maximum <see cref="XmlReader.Depth"/> accepted (inclusive) before parsing aborts.
	/// Real Windows event payloads nest at most 6 levels — <c>Event/EventData/Data/text()</c> reaches
	/// depth 3, and the deepest live payload (<c>UserData/EventXML/…</c>) reaches depth 4.
	/// <para>
	/// Semantics: any node observed with <c>reader.Depth &gt; MaxDepth</c> aborts the parse. Depth
	/// is 0 for the root element and increments per nested element and per text node inside it, so a
	/// document with <c>N</c> element levels reaches depth <c>N</c> on the innermost text. Values are
	/// chosen so a legitimate payload never trips the cap while adversarial payloads (~thousands of
	/// levels) are refused before any DOM allocation. 64 is an ample forensic margin.
	/// </para></summary>
	private const int MaxDepth = 64;

	/// <summary>Text lengths above this in a single field are treated as attacker input and
	/// truncated to null. Prevents an oversized IpAddress from poisoning the pipeline.</summary>
	private const int MaxFieldLength = 4 * 1024;

	private static readonly XmlReaderSettings XmlSettings = BuildHardenedSettings();

	private static XmlReaderSettings BuildHardenedSettings()
	{
		XmlReaderSettings s = new()
		{
			IgnoreWhitespace = true,
			IgnoreComments = true,
			IgnoreProcessingInstructions = true,
			DtdProcessing = DtdProcessing.Prohibit,
			ConformanceLevel = ConformanceLevel.Document,
			Async = false,
			CloseInput = true,
			XmlResolver = null,
			MaxCharactersInDocument = MaxCharactersInDocument,
			MaxCharactersFromEntities = MaxCharactersInEntities,
		};
		return s;
	}

	// ── Legacy public API (kept identical to 1.0) ────────────────────────────────

	/// <summary>Loads an EventRecord XML payload safely; returns <c>null</c> on malformed
	/// input, oversize documents, DTD injection attempts, encoding faults, IO faults, or any
	/// node whose <see cref="XmlReader.Depth"/> exceeds <see cref="MaxDepth"/> (i.e. depths
	/// <c>0..MaxDepth</c> inclusive are permitted; <c>MaxDepth + 1</c> and above are refused).
	/// Never throws.</summary>
	public static XmlDocument? ParseSafe(string xml)
	{
		if (string.IsNullOrEmpty(xml))
		{
			return null;
		}

		// First-line size gate — cheaper than instantiating XmlReader on a 5 MiB blob.
		if ((long)xml.Length > MaxCharactersInDocument)
		{
			return null;
		}

		try
		{
			XmlDocument doc = new() { XmlResolver = null };
			using StringReader sr = new(xml);
			using XmlReader reader = XmlReader.Create(sr, XmlSettings);

			// Manual descent so we can enforce MaxDepth: XmlReader itself has no depth cap.
			// XmlDocument.Load(reader) internally walks the same reader, so we validate depth
			// while walking, then abort the parse instead of allowing runaway recursion.
			if (!ValidateDepth(reader))
			{
				return null;
			}

			// Re-open on a fresh reader: XmlReader is forward-only, so the depth walk consumed it.
			using StringReader sr2 = new(xml);
			using XmlReader reader2 = XmlReader.Create(sr2, XmlSettings);
			doc.Load(reader2);
			return doc;
		}
		catch (XmlException) { return null; }
		catch (IOException) { return null; }
		catch (InvalidOperationException) { return null; }
		catch (NotSupportedException) { return null; }
		catch (ArgumentException) { return null; }
	}

	/// <summary>Reads a named <c>EventData/UserData</c> value, normalising blank Windows
	/// sentinels (<c>""</c>, <c>"-"</c>, <c>"N/A"</c>) to <c>null</c>. Returns <c>null</c>
	/// when the field is missing or the value exceeds <see cref="MaxFieldLength"/> —
	/// oversize values are attacker-controlled and refused.</summary>
	public static string? GetData(XmlDocument? doc, string name)
	{
		if (doc is null || string.IsNullOrEmpty(name))
		{
			return null;
		}

		// XPath argument is validated before interpolation to avoid injection into the query.
		if (!IsSafeXmlName(name))
		{
			return null;
		}

		XmlNode? node = doc.SelectSingleNode(
			$"//*[local-name()='EventData']/*[local-name()='Data' and @Name='{name}']")
			?? doc.SelectSingleNode($"//*[local-name()='UserData']//*[local-name()='{name}']");

		return NormaliseField(node?.InnerText);
	}

	/// <summary>Reads a named field as int (decimal or 0x-prefixed hex) or returns <c>null</c>
	/// when missing / unparseable / oversize.</summary>
	public static int? GetInt(XmlDocument? doc, string name)
	{
		string? raw = GetData(doc, name);
		if (raw is null)
		{
			return null;
		}

		if (raw.StartsWith("0x", StringComparison.OrdinalIgnoreCase)
			&& int.TryParse(raw.AsSpan(2), NumberStyles.HexNumber, CultureInfo.InvariantCulture, out int hex))
		{
			return hex;
		}

		return int.TryParse(raw, NumberStyles.Integer, CultureInfo.InvariantCulture, out int v) ? v : null;
	}

	/// <summary>Reads the Nth child of <c>EventData</c> by ordinal position (zero-based),
	/// matching cameyo rdpmon's <c>EventRecord.Properties[N]</c> compatibility semantics. Used
	/// only as a defensive fallback when an event payload omits the standard <c>@Name</c>
	/// attributes on its Data elements (older Windows builds and stripped event sources) —
	/// Windows still emits the values in a stable positional order. Returns <c>null</c> when
	/// the index is out of range, the value is blank, or one of the Windows sentinels
	/// (<c>"-"</c> / <c>"N/A"</c>).</summary>
	public static string? GetDataAt(XmlDocument? doc, int index)
	{
		if (doc is null || index < 0)
		{
			return null;
		}

		XmlNodeList? nodes = doc.SelectNodes("//*[local-name()='EventData']/*[local-name()='Data']");
		if (nodes is null || index >= nodes.Count)
		{
			return null;
		}

		return NormaliseField(nodes[index]?.InnerText);
	}

	// ── 2.0 public API: correlation-field extraction ────────────────────────────
	// These helpers understand the per-event field naming conventions and populate the
	// new RawEventDto fields (LogonId, SessionId, ActivityId, SourceIp) without callers
	// having to know per-id quirks.

	/// <summary>Extracts the source IP from an event payload, respecting per-event id field
	/// naming conventions. Returns <c>null</c> when unresolved. Never allocates beyond
	/// the underlying XmlDocument DOM. New event ids (22, 39, 40, 1150, 1158, 4778, 4779)
	/// are covered here — extend the switch to teach the parser about new ones.</summary>
	public static string? ExtractSourceIp(XmlDocument? doc, int eventId) => eventId switch
	{
		// TerminalServices-LocalSessionManager
		21 or 22 or 24 or 25 or 39 or 40 => GetData(doc, "Address"),
		23                                => GetData(doc, "Address") ?? GetData(doc, "IpAddress"),

		// TerminalServices-RemoteConnectionManager
		1149                              => GetData(doc, "Param3"),
		1150                              => GetData(doc, "Param3") ?? GetData(doc, "IpAddress"),
		1158                              => GetData(doc, "Address") ?? GetData(doc, "IpAddress")
		                                     ?? GetData(doc, "ClientAddress"),
		261                               => GetData(doc, "Address") ?? GetData(doc, "IpAddress")
		                                     ?? GetData(doc, "ClientAddress"),

		// RemoteDesktopServices-RdpCoreTS
		131                               => GetData(doc, "ClientIP") ?? GetData(doc, "ConnectionName"),
		140                               => GetData(doc, "IPString"),

		// Security channel: Window Station reconnect / disconnect
		4778 or 4779                      => GetData(doc, "ClientAddress"),

		// Security channel: canonical auth events
		4625                              => GetData(doc, "IpAddress") ?? GetDataAt(doc, 19),
		4648                              => GetData(doc, "IpAddress") ?? GetDataAt(doc, 12),
		4624 or 4768 or 4769
			or 4770 or 4771               => GetData(doc, "IpAddress"),
		4634 or 4647                      => GetData(doc, "IpAddress"),

		// Fallback: try every documented name.
		_                                 => GetData(doc, "IpAddress")
		                                     ?? GetData(doc, "ClientAddress")
		                                     ?? GetData(doc, "SourceNetworkAddress"),
	};

	/// <summary>Extracts the Windows logon session id (LUID) as a signed long, or <c>null</c>
	/// when the event does not carry one or the value is malformed.</summary>
	public static long? ExtractLogonId(XmlDocument? doc)
	{
		string? raw = GetData(doc, "TargetLogonId") ?? GetData(doc, "SubjectLogonId");
		if (raw is null)
		{
			return null;
		}

		// Windows emits LUIDs as 0x-prefixed hex — usually 0x1234_5678.
		if (raw.StartsWith("0x", StringComparison.OrdinalIgnoreCase)
			&& long.TryParse(raw.AsSpan(2), NumberStyles.HexNumber, CultureInfo.InvariantCulture, out long hex))
		{
			return hex;
		}

		return long.TryParse(raw, NumberStyles.Integer, CultureInfo.InvariantCulture, out long dec) ? dec : null;
	}

	/// <summary>Extracts the Terminal Services session id as an <c>int</c>. Accepts both
	/// <c>SessionID</c> (Security channel casing) and <c>SessionId</c> (TerminalServices
	/// channel casing).</summary>
	public static int? ExtractSessionId(XmlDocument? doc)
		=> GetInt(doc, "SessionID") ?? GetInt(doc, "SessionId");

	/// <summary>Extracts the Windows correlation <c>ActivityID</c> from the
	/// <c>&lt;Correlation ActivityID='{…}'/&gt;</c> element under <c>System</c>.
	/// Returns <c>null</c> when absent or malformed.</summary>
	public static Guid? ExtractActivityId(XmlDocument? doc)
	{
		if (doc is null)
		{
			return null;
		}

		XmlNode? node = doc.SelectSingleNode("//*[local-name()='System']/*[local-name()='Correlation']");
		string? raw = node?.Attributes?["ActivityID"]?.Value?.Trim();
		if (string.IsNullOrEmpty(raw))
		{
			return null;
		}

		// Trim surrounding braces which Windows may or may not emit.
		if (raw.Length >= 2 && raw[0] == '{' && raw[^1] == '}')
		{
			raw = raw[1..^1];
		}

		return Guid.TryParseExact(raw, "D", out Guid g) ? g : null;
	}

	/// <summary>Fills the correlation-related fields on an existing <see cref="RawEventDto"/>
	/// from a parsed document. Idempotent and null-safe: fields already set by an earlier
	/// stage are not clobbered when the payload does not contain a fresh value.</summary>
	public static void PopulateFrom(XmlDocument? doc, RawEventDto dto)
	{
		ArgumentNullException.ThrowIfNull(dto);
		if (doc is null)
		{
			return;
		}

		dto.ActivityId ??= ExtractActivityId(doc);
		dto.LogonId    ??= ExtractLogonId(doc);
		dto.SessionId  ??= ExtractSessionId(doc);

		// SourceIp: only overwrite when we currently have nothing, because upstream may have
		// resolved it via a more specific per-event resolver.
		if (string.IsNullOrEmpty(dto.SourceIp))
		{
			dto.SourceIp = ExtractSourceIp(doc, dto.EventId);
		}
	}

	// ── Internal helpers ─────────────────────────────────────────────────────────

	/// <summary>Walks the reader once, aborting when any node's depth exceeds <see cref="MaxDepth"/>.
	/// <see cref="XmlReader.Depth"/> is 0 on the root element and increments for each nested element
	/// and for text nodes inside them, so a document with <c>N</c> element levels reaches depth
	/// <c>N</c> on the innermost text node. The strict-greater comparison is intentional: depths
	/// <c>0..MaxDepth</c> pass; the first node observed at <c>MaxDepth + 1</c> aborts the parse.
	/// Returns <c>true</c> when every node stayed at or below the budget.</summary>
	private static bool ValidateDepth(XmlReader reader)
	{
		while (reader.Read())
		{
			if (reader.Depth > MaxDepth)
			{
				return false;
			}
		}
		return true;
	}

	/// <summary>Trims, normalises Windows blank sentinels to null, and refuses oversize values.</summary>
	private static string? NormaliseField(string? raw)
	{
		if (raw is null)
		{
			return null;
		}

		if (raw.Length > MaxFieldLength)
		{
			// Attacker-controlled overflow. Refuse rather than silently truncate.
			return null;
		}

		string trimmed = raw.Trim();
		return trimmed switch
		{
			"" or "-" or "N/A" => null,
			_ => trimmed,
		};
	}

	/// <summary>Validates that a supplied field name only contains characters legal for a
	/// Windows event data name — letters, digits and underscore. This is defence in depth
	/// against callers that build the name from untrusted input; the current callers all
	/// pass literals, but the XPath is composed via string interpolation so the invariant
	/// must be enforced here.</summary>
	private static bool IsSafeXmlName(string name)
	{
		if (name.Length == 0 || name.Length > 128)
		{
			return false;
		}

		for (int i = 0; i < name.Length; i++)
		{
			char c = name[i];
			bool ok = (c >= 'A' && c <= 'Z')
				|| (c >= 'a' && c <= 'z')
				|| (c >= '0' && c <= '9')
				|| c == '_';
			if (!ok)
			{
				return false;
			}
		}
		return true;
	}
}
