// File:    src/RdpAudit.Core/Ipc/Contracts/ConnectionFactsRequest.cs
// Module:  RdpAudit.Core.Ipc.Contracts
// Purpose: Bounded request shape for ListConnectionFacts (recent + filtered) and GetConnectionFactsForIp
//          (per-IP detail). Carries optional IP/User filters, an optional time window, and a
//          requested row limit that the server clamps. MessagePack keys are append-only.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using MessagePack;

namespace RdpAudit.Core.Ipc.Contracts;

/// <summary>Bounded request for <c>ListConnectionFacts</c>.</summary>
[MessagePackObject(keyAsPropertyName: false)]
public sealed class ConnectionFactsRequest
{
	/// <summary>Optional case-insensitive IP substring filter. Empty means no filter.</summary>
	[Key(0)]
	public string? IpQuery { get; set; }

	/// <summary>Optional case-insensitive UserName substring filter. Empty means no filter.</summary>
	[Key(1)]
	public string? UserQuery { get; set; }

	/// <summary>Optional inclusive lower bound on <c>LastSeenUtc</c>. Null means "any".</summary>
	[Key(2)]
	public DateTime? SinceUtc { get; set; }

	/// <summary>Optional inclusive upper bound on <c>LastSeenUtc</c>. Null means "any".</summary>
	[Key(3)]
	public DateTime? UntilUtc { get; set; }

	/// <summary>Restrict to currently-active facts only.</summary>
	[Key(4)]
	public bool OnlyActive { get; set; }

	/// <summary>Requested row cap. Zero means "use server default"; the server hard-caps at 1000.</summary>
	[Key(5)]
	public int Limit { get; set; }
}

/// <summary>Bounded request for <c>GetConnectionFactsForIp</c>.</summary>
[MessagePackObject(keyAsPropertyName: false)]
public sealed class ConnectionFactsForIpRequest
{
	/// <summary>Canonical IPv4 / IPv6 literal. Required.</summary>
	[Key(0)]
	public string Ip { get; set; } = string.Empty;

	/// <summary>Requested row cap. Zero means "use server default"; the server hard-caps at 1000.</summary>
	[Key(1)]
	public int Limit { get; set; }
}
