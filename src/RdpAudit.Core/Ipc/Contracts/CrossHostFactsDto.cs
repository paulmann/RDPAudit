// File:    src/RdpAudit.Core/Ipc/Contracts/CrossHostFactsDto.cs
// Module:  RdpAudit.Core.Ipc.Contracts
// Purpose: Response shapes for GetCrossHostFacts (pull of cross-host fact projections from an
//          agent host). The request is bounded (optional sinceUtc watermark + server-clamped
//          limit); each fact carries its stable DedupKey so the central receiver can dedupe
//          re-pulled observations. MessagePack keys are append-only.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using MessagePack;
using RdpAudit.Core.CrossHost;

namespace RdpAudit.Core.Ipc.Contracts;

/// <summary>Request payload for <c>GetCrossHostFacts</c>: asks an agent host for fact projections
/// newer than an optional watermark, bounded by a server-clamped fact count.</summary>
[MessagePackObject(keyAsPropertyName: false)]
public sealed class CrossHostFactsRequest
{
	/// <summary>Optional exclusive lower bound on <c>TimeUtc</c>. Null asks for the most recent
	/// facts only; a past value asks for everything newer than the watermark.</summary>
	[Key(0)]
	public DateTime? SinceUtc { get; set; }

	/// <summary>Maximum facts the caller wants; the agent clamps this to its configured cap.</summary>
	[Key(1)]
	public int MaxFacts { get; set; }

	/// <summary>Echoed back for operator correlation of a poll round-trip.</summary>
	[Key(2)]
	public string? RequestId { get; set; }
}

/// <summary>One cross-host fact projection exported by an agent host (summary only - never raw
/// event XML).</summary>
[MessagePackObject(keyAsPropertyName: false)]
public sealed class CrossHostFactDto
{
	/// <summary>Agent host this fact was observed on.</summary>
	[Key(0)]
	public string HostName { get; set; } = string.Empty;

	/// <summary>UTC observation time from the originating Windows event.</summary>
	[Key(1)]
	public DateTime TimeUtc { get; set; }

	/// <summary>Attempted / authenticated user name.</summary>
	[Key(2)]
	public string? UserName { get; set; }

	/// <summary>Canonical user key (lower-case, domain-stripped).</summary>
	[Key(3)]
	public string? NormalizedUserName { get; set; }

	/// <summary>Source IP, when known.</summary>
	[Key(4)]
	public string? SourceIp { get; set; }

	/// <summary>Windows logon type, when known.</summary>
	[Key(5)]
	public int? LogonType { get; set; }

	/// <summary>Classification of this fact as a chain-link candidate.</summary>
	[Key(6)]
	public CrossHostFactKind Kind { get; set; }

	/// <summary>Originating Windows event id (4624 / 4625 / 4672).</summary>
	[Key(7)]
	public int EventId { get; set; }

	/// <summary>Stable deduplication key (SHA-256 hex) so re-pulled observations dedupe.</summary>
	[Key(8)]
	public string? DedupKey { get; set; }
}

/// <summary>Response payload for <c>GetCrossHostFacts</c>.</summary>
[MessagePackObject(keyAsPropertyName: false)]
public sealed class CrossHostFactsDto
{
	/// <summary>Outcome of the pull. Success carries facts; Refused/Unavailable/InvalidRequest
	/// carry no facts and an operator-facing message.</summary>
	[Key(0)]
	public IpcResultStatus Status { get; set; } = IpcResultStatus.Success;

	/// <summary>UTC timestamp at which the agent produced the snapshot.</summary>
	[Key(1)]
	public DateTime QueriedUtc { get; set; }

	/// <summary>Echo of the caller-supplied request id, when provided.</summary>
	[Key(2)]
	public string? RequestId { get; set; }

	/// <summary>Most recent fact <c>TimeUtc</c> included; null when no facts were returned.
	/// The central worker uses this value as the next poll's watermark.</summary>
	[Key(3)]
	public DateTime? LatestFactUtc { get; set; }

	/// <summary>Bounded fact projections ordered <c>TimeUtc</c> ascending.</summary>
	[Key(4)]
	public List<CrossHostFactDto> Facts { get; set; } = new();

	/// <summary>Operator-facing message; never carries secret material.</summary>
	[Key(5)]
	public string? Message { get; set; }
}
