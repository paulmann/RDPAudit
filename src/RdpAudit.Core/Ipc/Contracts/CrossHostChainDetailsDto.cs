// File:    src/RdpAudit.Core/Ipc/Contracts/CrossHostChainDetailsDto.cs
// Module:  RdpAudit.Core.Ipc.Contracts
// Purpose: Response shapes for GetCrossHostChainDetails (one persisted chain plus its ordered
//          link list, rendered by the Configurator's Cross-Host tab details panel) and
//          AcknowledgeCrossHostChain (ack state change). MessagePack keys are append-only.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using MessagePack;
using RdpAudit.Core.CrossHost;

namespace RdpAudit.Core.Ipc.Contracts;

/// <summary>One link (hop) of a chain's details view.</summary>
[MessagePackObject(keyAsPropertyName: false)]
public sealed class CrossHostChainLinkDto
{
	/// <summary>Zero-based ordinal inside the chain path.</summary>
	[Key(0)]
	public int Ordinal { get; set; }

	/// <summary>Agent host this hop was observed on.</summary>
	[Key(1)]
	public string HostName { get; set; } = string.Empty;

	/// <summary>Classification of this hop.</summary>
	[Key(2)]
	public CrossHostFactKind Kind { get; set; }

	/// <summary>Originating Windows event id.</summary>
	[Key(3)]
	public int EventId { get; set; }

	/// <summary>UTC observation time of the hop.</summary>
	[Key(4)]
	public DateTime TimeUtc { get; set; }

	/// <summary>Source IP, when known.</summary>
	[Key(5)]
	public string? SourceIp { get; set; }

	/// <summary>Attempted / authenticated user name at this hop.</summary>
	[Key(6)]
	public string? UserName { get; set; }
}

/// <summary>Request payload for <c>GetCrossHostChainDetails</c>.</summary>
[MessagePackObject(keyAsPropertyName: false)]
public sealed class CrossHostChainDetailsRequest
{
	/// <summary>Surrogate row id of the chain to load.</summary>
	[Key(0)]
	public long ChainId { get; set; }
}

/// <summary>Response payload for <c>GetCrossHostChainDetails</c>.</summary>
[MessagePackObject(keyAsPropertyName: false)]
public sealed class CrossHostChainDetailsDto
{
	/// <summary>Outcome of the query. InvalidRequest when the id is unknown.</summary>
	[Key(0)]
	public IpcResultStatus Status { get; set; } = IpcResultStatus.Success;

	/// <summary>UTC timestamp at which the snapshot was produced.</summary>
	[Key(1)]
	public DateTime QueriedUtc { get; set; }

	/// <summary>Surrogate row id of the chain.</summary>
	[Key(2)]
	public long Id { get; set; }

	/// <summary>Stable chain key computed by the correlation engine.</summary>
	[Key(3)]
	public string ChainKey { get; set; } = string.Empty;

	/// <summary>Rule that produced this chain.</summary>
	[Key(4)]
	public string RuleId { get; set; } = string.Empty;

	/// <summary>Canonical user key the chain pivots on.</summary>
	[Key(5)]
	public string NormalizedUserName { get; set; } = string.Empty;

	/// <summary>UTC time of the first link in the chain.</summary>
	[Key(6)]
	public DateTime FirstSeenUtc { get; set; }

	/// <summary>UTC time of the last link in the chain.</summary>
	[Key(7)]
	public DateTime LastSeenUtc { get; set; }

	/// <summary>Risk score computed by the rule (0..100).</summary>
	[Key(8)]
	public int Score { get; set; }

	/// <summary>Number of failed-login facts that fed the first link.</summary>
	[Key(9)]
	public int FailedAttemptCount { get; set; }

	/// <summary>True when an operator already acknowledged the chain.</summary>
	[Key(10)]
	public bool IsAcknowledged { get; set; }

	/// <summary>Ordered links of the chain path (deterministic engine output).</summary>
	[Key(11)]
	public List<CrossHostChainLinkDto> Links { get; set; } = new();

	/// <summary>Operator-facing message; never carries secret material.</summary>
	[Key(12)]
	public string? Message { get; set; }
}

/// <summary>Request payload for <c>AcknowledgeCrossHostChain</c>.</summary>
[MessagePackObject(keyAsPropertyName: false)]
public sealed class CrossHostChainAckRequest
{
	/// <summary>Surrogate row id of the chain to acknowledge.</summary>
	[Key(0)]
	public long ChainId { get; set; }
}

/// <summary>Response payload for <c>AcknowledgeCrossHostChain</c>.</summary>
[MessagePackObject(keyAsPropertyName: false)]
public sealed class CrossHostChainAckResultDto
{
	/// <summary>Outcome of the state change. InvalidRequest when the id is unknown.</summary>
	[Key(0)]
	public IpcResultStatus Status { get; set; } = IpcResultStatus.Success;

	/// <summary>Surrogate row id of the acknowledged chain.</summary>
	[Key(1)]
	public long ChainId { get; set; }

	/// <summary>Operator-facing message; never carries secret material.</summary>
	[Key(2)]
	public string? Message { get; set; }
}
