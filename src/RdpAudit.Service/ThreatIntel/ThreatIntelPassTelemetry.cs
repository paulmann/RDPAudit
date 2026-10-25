// File:    src/RdpAudit.Service/ThreatIntel/ThreatIntelPassTelemetry.cs
// Module:  RdpAudit.Service.ThreatIntel
// Purpose: Immutable snapshot of the most recent ThreatIntelEnrichmentWorker pass, surfaced
//          through IPC GetThreatIntelStatus (ordinal 71). Carries only sanitised timing / counters -
//          never secrets or provider payloads.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

namespace RdpAudit.Service.ThreatIntel;

/// <summary>Immutable snapshot of the most recent background enrichment pass.</summary>
public readonly record struct ThreatIntelPassTelemetry(
	DateTime? StartedUtc,
	DateTime? FinishedUtc,
	int Lookups,
	string? Error);
