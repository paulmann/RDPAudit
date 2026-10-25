// File:    src/RdpAudit.Core/Models/CrossHostLink.cs
// Module:  RdpAudit.Core.Models
// Purpose: Persisted hop of a cross-host attack chain - one host contribution inside a
//          CrossHostChain row. Mirrors CrossHostChainLinkCandidate and stays a plain child row
//          so the UI can render host-to-host transitions without re-running the engine.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using RdpAudit.Core.CrossHost;

namespace RdpAudit.Core.Models;

/// <summary>Persisted link (hop) of one cross-host chain.</summary>
public sealed class CrossHostLink
{
	/// <summary>Surrogate primary key.</summary>
	public long Id { get; set; }

	/// <summary>Owning chain row this link belongs to.</summary>
	public long CrossHostChainId { get; set; }

	/// <summary>Navigation: owning chain.</summary>
	public CrossHostChain? Chain { get; set; }

	/// <summary>Zero-based ordinal inside the chain path (deterministic engine output).</summary>
	public int Ordinal { get; set; }

	/// <summary>Agent host this hop was observed on.</summary>
	public string HostName { get; set; } = string.Empty;

	/// <summary>Classification of this hop.</summary>
	public CrossHostFactKind Kind { get; set; }

	/// <summary>Originating Windows event id.</summary>
	public int EventId { get; set; }

	/// <summary>UTC observation time of the hop.</summary>
	public DateTime TimeUtc { get; set; }

	/// <summary>Source IP, when known.</summary>
	public string? SourceIp { get; set; }

	/// <summary>Attempted / authenticated user name at this hop.</summary>
	public string? UserName { get; set; }
}
