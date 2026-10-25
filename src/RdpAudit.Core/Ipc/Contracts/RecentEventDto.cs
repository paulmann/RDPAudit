// File:    src/RdpAudit.Core/Ipc/Contracts/RecentEventDto.cs
// Module:  RdpAudit.Core.Ipc.Contracts
// Purpose: Typed projection returned by GetRecentEvents (ordinal 2). Replaces the anonymous
//          projection so the Stage 15 threat-intel pass can stamp IsHighRisk /
//          ThreatIntelConfidenceScore per row without changing the JSON field names the
//          Configurator's LiveEventRow already binds. Stage PM stamps IsProcessNew (key 15)
//          from the persisted PROCESS_NEW alert for the row's RawEvent id. JSON serialisation
//          uses the shared JsonOptions camel-case policy; MessagePack keys are append-only.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using MessagePack;

namespace RdpAudit.Core.Ipc.Contracts;

/// <summary>Single recent-event row returned by <c>GetRecentEvents</c>.</summary>
[MessagePackObject(keyAsPropertyName: false)]
public sealed class RecentEventDto
{
	[Key(0)]
	public long Id { get; set; }

	[Key(1)]
	public int EventId { get; set; }

	[Key(2)]
	public string? Channel { get; set; }

	[Key(3)]
	public DateTime TimeUtc { get; set; }

	[Key(4)]
	public string? SourceIp { get; set; }

	[Key(5)]
	public bool SourceIpDerived { get; set; }

	[Key(6)]
	public bool SourceIpUnresolved { get; set; }

	[Key(7)]
	public string? UserName { get; set; }

	[Key(8)]
	public string? Domain { get; set; }

	[Key(9)]
	public string? LogonId { get; set; }

	[Key(10)]
	public int? LogonType { get; set; }

	[Key(11)]
	public string? AuthPackage { get; set; }

	[Key(12)]
	public string? ProcessName { get; set; }

	// --- Stage 15 threat-intel additions (append-only keys). Fail-closed: default false / 0 when
	// the IP has no fresh Success cache row or the feature is disabled. ---

	/// <summary>True when a fresh cached threat-intel snapshot classifies this source IP as High-risk.</summary>
	[Key(13)]
	public bool IsHighRisk { get; set; }

	/// <summary>Clamped provider abuse-confidence score backing the flag; 0 when unavailable.</summary>
	[Key(14)]
	public int ThreatIntelConfidenceScore { get; set; }

	// --- Stage PM process-monitoring addition (append-only key). Fail-closed: default false when
	// the feature has never flagged this event. ---

	/// <summary>True when a persisted PROCESS_NEW alert was raised for this exact RawEvent row.</summary>
	[Key(15)]
	public bool IsProcessNew { get; set; }
}
