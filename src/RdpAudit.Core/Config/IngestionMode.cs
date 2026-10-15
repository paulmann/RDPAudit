/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 2.0.0
// File   : IngestionMode.cs
// Project: RdpAudit.Core (RdpAudit.Core.Config)
// Purpose: Selects which transport RdpAudit uses to ingest Windows security events from the OS
//          into the RawEventDto pipeline. v1.x has only EventLogWatcher; v2.x adds a real-time
//          ETW consumer for lower latency and zero-XML hot path. Auto probes ETW first and
//          falls back to EventLog when the probe fails (non-Windows host, missing manifest,
//          insufficient privilege).
// Depends: System.Enum
// Extends: Append-only enum — values MUST NEVER be reused or reordered because appsettings.json
//          references them by name and structured logs by ordinal. New transports (EVTX file
//          replay, kernel-mode driver ingestion, IPC shim) receive new ordinals.

namespace RdpAudit.Core.Config;

/// <summary>
/// Selects the event-ingestion transport. See file header for backward-compatibility rules.
/// </summary>
/// <remarks>
/// <para>The 1.4.x default is <see cref="EventLog"/>. <see cref="Auto"/> is promoted to the
/// default after ETW benchmarks confirm a measurable win and one release cycle proves the
/// probe is stable in the field.</para>
/// <para><see cref="Etw"/> without the fallback is intended for lab / benchmark runs and for
/// operators who explicitly want the service to fail-fast if ETW is unavailable, rather than
/// silently falling back to the legacy transport.</para>
/// </remarks>
public enum IngestionMode
{
	/// <summary>Legacy EventLogWatcher subscription. Safe default — every RDPAudit 1.x
	/// installation used exactly this transport.</summary>
	EventLog = 0,

	/// <summary>Real-time ETW consumer via <c>Microsoft.Diagnostics.Tracing.TraceEvent</c>.
	/// Zero-XML hot path when the caller opts into span-based normalization. If ETW cannot
	/// start on this host, the service refuses to start — no silent fallback.</summary>
	Etw = 1,

	/// <summary>Probe ETW at startup. If the probe succeeds, use ETW; otherwise transparently
	/// fall back to <see cref="EventLog"/> and log the reason at Warning level. Recommended
	/// once ETW has proven stable in the field.</summary>
	Auto = 2,
}
