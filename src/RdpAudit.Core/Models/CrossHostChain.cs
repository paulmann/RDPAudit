// File:    src/RdpAudit.Core/Models/CrossHostChain.cs
// Module:  RdpAudit.Core.Models
// Purpose: Persisted cross-host attack chain produced by the correlation engine. One row per
//          stable ChainKey; when the engine emits the same key again the existing row is
//          refreshed (times, score, failed count) instead of duplicated. Chains link to the
//          single CROSS_HOST_CHAIN alert raised for them (AlertId) and keep the operator's
//          acknowledgment state so the Configurator tab and the alert layer stay in sync.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

namespace RdpAudit.Core.Models;

/// <summary>Persisted cross-host attack chain.</summary>
public sealed class CrossHostChain
{
	/// <summary>Surrogate primary key.</summary>
	public long Id { get; set; }

	/// <summary>Stable chain key (SHA-256 hex computed by the engine); unique per rule.</summary>
	public string ChainKey { get; set; } = string.Empty;

	/// <summary>Rule that produced this chain (e.g. 'RDP_LATERAL_MOVEMENT').</summary>
	public string RuleId { get; set; } = string.Empty;

	/// <summary>Canonical user key the chain pivots on.</summary>
	public string NormalizedUserName { get; set; } = string.Empty;

	/// <summary>UTC time of the first link in the chain.</summary>
	public DateTime FirstSeenUtc { get; set; }

	/// <summary>UTC time of the last link in the chain.</summary>
	public DateTime LastSeenUtc { get; set; }

	/// <summary>Risk score computed by the rule (0..100).</summary>
	public int Score { get; set; }

	/// <summary>Number of failed-login facts that fed the first link.</summary>
	public int FailedAttemptCount { get; set; }

	/// <summary>UTC timestamp when the chain row was created or last refreshed.</summary>
	public DateTime DetectedUtc { get; set; }

	/// <summary>Id of the CROSS_HOST_CHAIN alert raised for this chain; null until AlertWorker
	/// links the alert. This column is the durable alert dedup gate: exactly one alert per chain.</summary>
	public long? AlertId { get; set; }

	/// <summary>Navigation: linked CROSS_HOST_CHAIN alert (null until AlertWorker links it).</summary>
	public Alert? Alert { get; set; }

	/// <summary>True when an operator acknowledged the chain in the Configurator Cross-Host tab.
	/// Acknowledging also clears the linked CROSS_HOST_CHAIN alert.</summary>
	public bool IsAcknowledged { get; set; }

	/// <summary>Links (hops) of this chain in deterministic path order.</summary>
	public List<CrossHostLink> Links { get; set; } = new();
}
