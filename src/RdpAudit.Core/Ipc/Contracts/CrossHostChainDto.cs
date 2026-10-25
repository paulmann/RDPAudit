// File:    src/RdpAudit.Core/Ipc/Contracts/CrossHostChainDto.cs
// Module:  RdpAudit.Core.Ipc.Contracts
// Purpose: Response shapes for ListCrossHostChains (bounded, newest-first cross-host chain list
//          shown by the Configurator's Cross-Host tab). Each chain item carries the ordered host
//          path and acknowledgment state so the list grid renders host-to-host transitions
//          without a per-row details call. MessagePack keys are append-only.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using MessagePack;

namespace RdpAudit.Core.Ipc.Contracts;

/// <summary>Request payload for <c>ListCrossHostChains</c>: newest-first window over persisted
/// chains, clamped server-side.</summary>
[MessagePackObject(keyAsPropertyName: false)]
public sealed class CrossHostChainsRequest
{
	/// <summary>Maximum chain rows the caller wants; the service clamps this to a safe cap.</summary>
	[Key(0)]
	public int MaxRows { get; set; }

	/// <summary>Optional rule filter (e.g. 'RDP_LATERAL_MOVEMENT'); null returns every rule.</summary>
	[Key(1)]
	public string? RuleId { get; set; }

	/// <summary>When true, acknowledged chains are included; when false they are hidden.</summary>
	[Key(2)]
	public bool IncludeAcknowledged { get; set; } = true;
}

/// <summary>One cross-host chain row for the list grid.</summary>
[MessagePackObject(keyAsPropertyName: false)]
public sealed class CrossHostChainDto
{
	/// <summary>Surrogate row id used by GetCrossHostChainDetails / AcknowledgeCrossHostChain.</summary>
	[Key(0)]
	public long Id { get; set; }

	/// <summary>Stable chain key computed by the correlation engine.</summary>
	[Key(1)]
	public string ChainKey { get; set; } = string.Empty;

	/// <summary>Rule that produced this chain (e.g. 'RDP_LATERAL_MOVEMENT').</summary>
	[Key(2)]
	public string RuleId { get; set; } = string.Empty;

	/// <summary>Canonical user key the chain pivots on.</summary>
	[Key(3)]
	public string NormalizedUserName { get; set; } = string.Empty;

	/// <summary>UTC time of the first link in the chain.</summary>
	[Key(4)]
	public DateTime FirstSeenUtc { get; set; }

	/// <summary>UTC time of the last link in the chain.</summary>
	[Key(5)]
	public DateTime LastSeenUtc { get; set; }

	/// <summary>Risk score computed by the rule (0..100).</summary>
	[Key(6)]
	public int Score { get; set; }

	/// <summary>Number of failed-login facts that fed the first link.</summary>
	[Key(7)]
	public int FailedAttemptCount { get; set; }

	/// <summary>Ordered host names of the chain path (e.g. SRV-A, SRV-B, SRV-C) for direct
	/// host-to-host rendering in the grid.</summary>
	[Key(8)]
	public List<string> HostPath { get; set; } = new();

	/// <summary>Source IP of the last chain link, when known.</summary>
	[Key(9)]
	public string? LastSourceIp { get; set; }

	/// <summary>True when an operator already acknowledged the chain (via the alert layer).</summary>
	[Key(10)]
	public bool IsAcknowledged { get; set; }
}

/// <summary>Response payload for <c>ListCrossHostChains</c>.</summary>
[MessagePackObject(keyAsPropertyName: false)]
public sealed class CrossHostChainListDto
{
	/// <summary>Outcome of the query.</summary>
	[Key(0)]
	public IpcResultStatus Status { get; set; } = IpcResultStatus.Success;

	/// <summary>UTC timestamp at which the snapshot was produced.</summary>
	[Key(1)]
	public DateTime QueriedUtc { get; set; }

	/// <summary>Total number of chains matching the filter, before the limit was applied.</summary>
	[Key(2)]
	public int TotalMatching { get; set; }

	/// <summary>Limit the server clamped the response to (also equals <c>Chains.Count</c>).</summary>
	[Key(3)]
	public int AppliedLimit { get; set; }

	/// <summary>Bounded chain rows ordered <c>DetectedUtc</c> descending.</summary>
	[Key(4)]
	public List<CrossHostChainDto> Chains { get; set; } = new();

	/// <summary>Operator-facing message; never carries secret material.</summary>
	[Key(5)]
	public string? Message { get; set; }
}
