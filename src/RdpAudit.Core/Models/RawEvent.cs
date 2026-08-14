/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 2.0.0
// File   : RawEvent.cs
// Project: RdpAudit.Core (RdpAudit.Core.Models)
// Purpose: Persists a normalized Windows event and its durable ingestion metadata.
// Depends: Address, Session
// Extends: Add persisted event metadata with a matching RawEventConfiguration mapping.

namespace RdpAudit.Core.Models;

/// <summary>
/// Persisted, normalized representation of a single Windows event captured from
/// one of the monitored channels.
/// </summary>
public sealed class RawEvent
{
	/// <summary>Surrogate primary key.</summary>
	public long Id { get; set; }

	/// <summary>Windows event identifier.</summary>
	public int EventId { get; set; }

	/// <summary>Windows event channel name.</summary>
	public string Channel { get; set; } = string.Empty;

	/// <summary>UTC timestamp reported by Windows.</summary>
	public DateTime TimeUtc { get; set; }

	/// <summary>Monotonic ingestion sequence assigned by the collector.</summary>
	public long IngestionSequence { get; set; }

	/// <summary>Persisted numeric event-layer classification.</summary>
	public int EventLayer { get; set; }

	/// <summary>Canonical 16-byte IPv6-mapped binary source IP, when resolved.</summary>
	public byte[]? SourceIpBinary { get; set; }

	/// <summary>Resolved textual source IP, when available.</summary>
	public string? SourceIp { get; set; }

	/// <summary>
	/// True when <see cref="SourceIp"/> was attached by in-memory session correlation rather than
	/// being read directly from the event payload. Direct-extraction events leave this false.
	/// </summary>
	public bool SourceIpDerived { get; set; }

	/// <summary>
	/// True when the event semantically carried a source IP slot (typically Security 4625) but the
	/// payload value was missing, blank, "-", or otherwise unparseable, AND no in-memory session
	/// correlation could supply one either. The row is still persisted so failed-logon evidence is
	/// preserved, but downstream consumers must treat <see cref="SourceIp"/> as legitimately
	/// unknown rather than substituting a placeholder.
	/// </summary>
	public bool SourceIpUnresolved { get; set; }

	public string? UserName { get; set; }

	public string? Domain { get; set; }

	public int? SessionId { get; set; }

	public int? LogonType { get; set; }

	public string? LogonId { get; set; }

	public string? AuthPackage { get; set; }

	public string? Status { get; set; }

	public string? ProcessName { get; set; }

	public string? CommandLine { get; set; }

	public string? ObjectName { get; set; }

	public string? AccessMask { get; set; }

	public string? Details { get; set; }

	public bool Processed { get; set; }

	public long? AddressId { get; set; }

	public Address? Address { get; set; }

	public long? SessionRefId { get; set; }

	public Session? SessionRef { get; set; }
}
