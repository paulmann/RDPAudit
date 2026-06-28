// File:    src/RdpAudit.Core/Ipc/Contracts/AttackStatsRequest.cs
// Module:  RdpAudit.Core.Ipc.Contracts
// Purpose: Request filter for the GetAttackStats IPC command. Append-only — new fields land at the
//          end so deployed Configurator / Service builds across version skew can ignore unknown
//          keys without crashing.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using MessagePack;

namespace RdpAudit.Core.Ipc.Contracts;

/// <summary>Request filter for <c>GetAttackStats</c>.</summary>
[MessagePackObject(keyAsPropertyName: false)]
public sealed class AttackStatsRequest
{
	/// <summary>Optional case-insensitive substring matched against the row IP.</summary>
	[Key(0)]
	public string? IpQuery { get; set; }

	/// <summary>Optional inclusive minimum <c>ThreatScore</c>; rows below this score are excluded.</summary>
	[Key(1)]
	public double? MinThreatScore { get; set; }

	/// <summary>When <c>true</c>, only rows with <c>IsBlocked</c> set are returned.</summary>
	[Key(2)]
	public bool OnlyBlocked { get; set; }

	/// <summary>Optional inclusive UTC lower bound on <c>LastSeenUtc</c>.</summary>
	[Key(3)]
	public DateTime? SinceUtc { get; set; }

	/// <summary>Optional inclusive UTC upper bound on <c>LastSeenUtc</c>.</summary>
	[Key(4)]
	public DateTime? UntilUtc { get; set; }

	/// <summary>Maximum number of rows returned. Server clamps to <c>1..2000</c>. Zero falls back to the default.</summary>
	[Key(5)]
	public int Limit { get; set; }
}
