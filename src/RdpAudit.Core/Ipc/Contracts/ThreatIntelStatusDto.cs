// File:    src/RdpAudit.Core/Ipc/Contracts/ThreatIntelStatusDto.cs
// Module:  RdpAudit.Core.Ipc.Contracts
// Purpose: DTO returned by GetThreatIntelStatus (IPC ordinal 71). Reports the threat-intel
//          enrichment subsystem status: configuration flags, cache row counts by outcome, today's
//          usage against the daily budget and the last background pass telemetry. Informational
//          only - never contains the AbuseIPDB API key, never performs a network call and never
//          exposes provider payloads.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using MessagePack;

namespace RdpAudit.Core.Ipc.Contracts;

/// <summary>Outcome bucket in the threat-intel cache status report.</summary>
[MessagePackObject(keyAsPropertyName: false)]
public sealed class ThreatIntelOutcomeCountDto
{
	/// <summary>Persisted <see cref="RdpAudit.Core.ThreatIntel.ThreatIntelLookupOutcome"/> ordinal.</summary>
	[Key(0)]
	public int Outcome { get; set; }

	/// <summary>Number of cache rows recorded with this outcome.</summary>
	[Key(1)]
	public int Count { get; set; }
}

/// <summary>DTO returned by <c>GetThreatIntelStatus</c>. Informational telemetry only.</summary>
[MessagePackObject(keyAsPropertyName: false)]
public sealed class ThreatIntelStatusDto
{
	[Key(0)]
	public IpcResultStatus Status { get; set; } = IpcResultStatus.Success;

	/// <summary>True when the /api/v2/check enrichment feature is enabled in configuration.</summary>
	[Key(1)]
	public bool CheckEnabled { get; set; }

	/// <summary>Total rows in the ThreatIntelLookups cache table.</summary>
	[Key(2)]
	public int TotalCacheRows { get; set; }

	/// <summary>Cache rows whose persisted outcome is Success (may include stale snapshots).</summary>
	[Key(3)]
	public int SuccessCacheRows { get; set; }

	/// <summary>Success rows younger than the configured freshness window - the rows currently able
	/// to stamp High-risk flags on IPC responses.</summary>
	[Key(4)]
	public int FreshSuccessRows { get; set; }

	/// <summary>Persisted lookups performed today (UTC) against the daily budget.</summary>
	[Key(5)]
	public int DailyUsage { get; set; }

	/// <summary>Configured daily lookup budget (clamped to the canonical band).</summary>
	[Key(6)]
	public int DailyBudget { get; set; }

	/// <summary>Clamped abuse-confidence score threshold used by the High-risk classifier.</summary>
	[Key(7)]
	public int HighRiskThreshold { get; set; }

	/// <summary>UTC time the most recent enrichment pass started; null when no pass has run.</summary>
	[Key(8)]
	public DateTime? LastPassStartedUtc { get; set; }

	/// <summary>UTC time the most recent enrichment pass finished; null when no pass has run.</summary>
	[Key(9)]
	public DateTime? LastPassFinishedUtc { get; set; }

	/// <summary>Number of lookups performed by the most recent pass (0 when none or failed).</summary>
	[Key(10)]
	public int LastPassLookups { get; set; }

	/// <summary>Sanitised error of the most recent failed pass; null when the pass succeeded or
	/// has never run.</summary>
	[Key(11)]
	public string? LastPassError { get; set; }

	/// <summary>Cache row counts grouped by persisted outcome ordinal, ascending.</summary>
	[Key(12)]
	public List<ThreatIntelOutcomeCountDto> OutcomeCounts { get; set; } = new();

	/// <summary>Optional human-readable summary of the subsystem state.</summary>
	[Key(13)]
	public string? Message { get; set; }
}
