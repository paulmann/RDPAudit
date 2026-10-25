// File:    src/RdpAudit.Core/Models/CrossHostFact.cs
// Module:  RdpAudit.Core.Models
// Purpose: Persisted projection of one authentication fact pulled from a remote agent host for
//          cross-host correlation. Mirrors CrossHostFactProjection (the in-memory shape the
//          correlation engine consumes); every row is exported by an agent and pulled by the
//          central service over the named-pipe transport - never derived from local events.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using RdpAudit.Core.CrossHost;

namespace RdpAudit.Core.Models;

/// <summary>Persisted cross-host fact projection. The central service stores one row per unique
/// observation (see DedupKey) contributed by the configured agent hosts.</summary>
public sealed class CrossHostFact
{
	/// <summary>Surrogate primary key.</summary>
	public long Id { get; set; }

	/// <summary>Agent host this fact was observed on.</summary>
	public string HostName { get; set; } = string.Empty;

	/// <summary>UTC observation time from the originating Windows event.</summary>
	public DateTime TimeUtc { get; set; }

	/// <summary>Attempted / authenticated user name.</summary>
	public string? UserName { get; set; }

	/// <summary>Canonical user key (lower-case, domain-stripped) used for cross-host joining.</summary>
	public string? NormalizedUserName { get; set; }

	/// <summary>Source IP, when known.</summary>
	public string? SourceIp { get; set; }

	/// <summary>Windows logon type, when known.</summary>
	public int? LogonType { get; set; }

	/// <summary>Classification of this fact as a chain-link candidate.</summary>
	public CrossHostFactKind Kind { get; set; }

	/// <summary>Originating Windows event id (4624 / 4625 / 4672).</summary>
	public int EventId { get; set; }

	/// <summary>Stable deduplication key computed by the exporter (SHA-256 hex). Uniquely indexed so a
	/// re-pull of the same observation never creates a second row.</summary>
	public string? DedupKey { get; set; }

	/// <summary>UTC processing timestamp - when this fact landed in the central database.</summary>
	public DateTime IngestedUtc { get; set; }
}
