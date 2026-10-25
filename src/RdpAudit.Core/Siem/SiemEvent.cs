// File:    src/RdpAudit.Core/Siem/SiemEvent.cs
// Module:  RdpAudit.Core.Siem
// Purpose: Neutral SIEM record shared by the CEF / LEEF 2.0 / NDJSON serializers. Every field is
//          populated by SiemEventMapper from IPC projections; serializers only render, never map.
//          All external data is treated as untrusted: serializers must neutralise CR / LF / TAB
//          and apply per-format escaping before any field reaches the output stream.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

namespace RdpAudit.Core.Siem;

/// <summary>Kind of SIEM record carried by a SiemEvent.</summary>
public enum SiemEventType
{
	Event = 0,
	Alert = 1,
}

/// <summary>Neutral SIEM record shared by all three serializers (one model, three renders).</summary>
public sealed class SiemEvent
{
	/// <summary>Record kind: raw-event observation or correlated alert.</summary>
	public SiemEventType Type { get; set; }

	/// <summary>Signature id: event colon EventId for events, alert RuleId for alerts.</summary>
	public string SignatureId { get; set; } = string.Empty;

	/// <summary>Short human-readable name (EventCatalog description or alert message).</summary>
	public string Name { get; set; } = string.Empty;

	/// <summary>Numeric severity on the CEF/LEEF 0..10 scale.</summary>
	public int Severity { get; set; }

	/// <summary>Observation UTC time (event time or alert time).</summary>
	public DateTime TimeUtc { get; set; }

	/// <summary>Canonical source IP, already normalized by the mapper.</summary>
	public string SourceIp { get; set; } = string.Empty;

	public int? SourcePort { get; set; }

	/// <summary>User name observed in the event or attached to the alert.</summary>
	public string? SourceUser { get; set; }

	/// <summary>Target / destination user name.</summary>
	public string? DestinationUser { get; set; }

	public string? Channel { get; set; }

	public int? LogonType { get; set; }

	public string? AuthPackage { get; set; }

	public string? ProcessName { get; set; }

	/// <summary>NTSTATUS or sub-status text of the event.</summary>
	public string? Status { get; set; }

	/// <summary>Attack classification label projected from AttackStats.</summary>
	public string? AttackType { get; set; }

	public int? EventId { get; set; }

	public long? FailedCount { get; set; }

	public long? TotalEvents { get; set; }

	/// <summary>Free-text message (alert message or event fallback).</summary>
	public string? Msg { get; set; }

	/// <summary>Stable external identifier (event row id or alert id).</summary>
	public string? ExternalId { get; set; }

	public bool Acknowledged { get; set; }

	public long? TriggerEventId { get; set; }

	/// <summary>Device vendor (CEF header field 2 / LEEF header field 2).</summary>
	public string DeviceVendor { get; set; } = string.Empty;

	/// <summary>Device product (CEF header field 3 / LEEF header field 3).</summary>
	public string DeviceProduct { get; set; } = string.Empty;

	/// <summary>Device version (CEF header field 4 / LEEF header field 4). Supplied by the
	/// caller from IPC ServiceStatus.Version; never hardcoded.</summary>
	public string DeviceVersion { get; set; } = string.Empty;
}
