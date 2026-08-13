/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 2.0.1
// File   : RawEventDto.cs
// Project: RdpAudit.Core (RdpAudit.Core.Events)
// Purpose: In-memory DTO carrying a captured EventRecord through the ingestion pipeline. Extended
//          in 2.0 with correlation ids (ActivityId / LogonId / SessionId), an IngestionSequence for
//          exactly-once accounting, a typed EventLayer, and a 16-byte SourceIpBinary for the IPv4-
//          in-IPv6 sharding path. Every new field carries a safe default so all existing
//          `new RawEventDto { ... }` object-initialiser calls continue to compile unchanged.
// Depends: EventLayer
// Extends: When adding a new field, keep it optional (nullable or with a default) and update the
//          shard record layout / EF configuration in parallel. Never mutate a DTO after it has
//          been handed off to the processor channel — treat instances as write-once.

namespace RdpAudit.Core.Events;

/// <summary>In-memory DTO carrying captured EventRecord data through the processor channel.
/// The DTO is intentionally a class (not a struct) so it flows through <c>Channel&lt;T&gt;</c>
/// without copies. Instances are treated as write-once after the collector hands them off.</summary>
public sealed class RawEventDto
{
	// ── v1.0 fields ──────────────────────────────────────────────────────────────
	// The four fields below existed in RDPAudit 1.0. Do not rename or remove them —
	// they are set by name in EventCollectorWorker.TryCaptureDto and are read from
	// EventProcessorWorker.PersistBatchAsync.

	/// <summary>Windows event id (e.g. 4624, 1149). Never zero for a valid capture.</summary>
	public int EventId { get; set; }

	/// <summary>Channel/log name the event was captured from (e.g. "Security").</summary>
	public string Channel { get; set; } = string.Empty;

	/// <summary>UTC timestamp of the event as reported by Windows (record.TimeCreated in UTC).</summary>
	public DateTime TimeUtc { get; set; }

	/// <summary>Raw XML payload (already truncated to <c>MaxEventXmlLength</c> by the collector).
	/// The processor normalises fields out of it via <c>EventXmlParser</c>; kept for forensics.</summary>
	public string XmlPayload { get; set; } = string.Empty;

	/// <summary>Text form of the source IP once it has been resolved (either directly from the
	/// event data or by fallback heuristic). Null while unresolved.</summary>
	public string? SourceIp { get; set; }

	/// <summary>Account name once extracted from the event payload. Null when unavailable.</summary>
	public string? UserName { get; set; }

	/// <summary>Account domain / workgroup once extracted from the event payload.</summary>
	public string? Domain { get; set; }

	// ── v2.0 extensions ──────────────────────────────────────────────────────────

	/// <summary>Windows correlation ActivityId (from <c>EVENT_HEADER.ActivityId</c> or the
	/// <c>&lt;Correlation ActivityID=…/&gt;</c> element in the rendered XML). Enables joining
	/// events emitted by the same asynchronous operation across channels.</summary>
	public Guid? ActivityId { get; set; }

	/// <summary>Windows logon session id (LUID, e.g. from 4624 <c>TargetLogonId</c>).
	/// Persisted as a signed long because SQLite has no unsigned 64-bit type. Null when the
	/// event has no logon session context (e.g. pre-auth 1158).</summary>
	public long? LogonId { get; set; }

	/// <summary>Terminal Services session id (SessionId from LocalSessionManager events,
	/// or the SessionID column on RemoteConnectionManager events). Null when unknown.</summary>
	public int? SessionId { get; set; }

	/// <summary>Monotonic sequence number stamped by the collector when it commits the event
	/// to the pipeline. Ensures deterministic ordering across a restart: the bookmark, the
	/// batch flush, and the shard append share a single durability boundary keyed on this
	/// value. Zero means "not yet stamped".</summary>
	public long IngestionSequence { get; set; }

	/// <summary>Typed layer classification for this event. Derived from
	/// <c>EventCatalog.LayerKindOf(EventId)</c> at capture time; kept on the DTO so downstream
	/// stages don't have to re-hit the catalog dictionary.</summary>
	public EventLayer EventLayer { get; set; } = EventLayer.Unknown;

	/// <summary>Canonical binary form of the source IP: exactly 16 bytes, always IPv6-mapped
	/// (::ffff:a.b.c.d for IPv4). Null when the source IP is unresolved or intentionally
	/// omitted. Used as the shard-selector key.</summary>
	public byte[]? SourceIpBinary { get; set; }

	/// <summary>Address family of the resolved source IP: 4 (IPv4-in-IPv6) or 6 (native IPv6).
	/// Zero when the IP has not been resolved. Byte-sized so it fits in the shard record.</summary>
	public byte SourceIpAddressFamily { get; set; }

	/// <summary>Confidence in the resolved source IP, 0..100. 100 = pulled directly from an
	/// authoritative event field (e.g. IpAddress on 4624). Lower values indicate heuristic
	/// resolution (e.g. deduced from a nearby event on the same channel). Zero when unresolved.</summary>
	public byte SourceIpConfidence { get; set; }

	/// <summary>
	/// Serialized <c>EventLogWatcher</c> bookmark XML captured for this event. Set on the
	/// captured DTO by <c>EventCollectorWorker.TryCaptureDto</c> so the bookmark can cross the
	/// same durability boundary as the event insert in <c>EventProcessorWorker.PersistBatchAsync</c>
	/// (via <c>BookmarkStore.SaveBatchInSameTransactionAsync</c>). Null when bookmark serialisation
	/// failed or when the source did not produce a bookmark (e.g. synthetic backfill DTOs). Only
	/// the LAST bookmark per channel in a batch is written; older bookmarks in the same batch are
	/// intentionally shadowed because Windows event bookmarks are monotonically increasing per
	/// channel and older values would only rewind the read position.
	/// </summary>
	public string? BookmarkXml { get; set; }
}
