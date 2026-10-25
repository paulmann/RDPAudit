// File:    src/RdpAudit.Core/Ipc/Contracts/AuthSuccessSummaryRequest.cs
// Module:  RdpAudit.Core.Ipc.Contracts
// Purpose: Bounded request shape for GetAuthSuccessSummaryForIp. Carries the target IP, a login-row
//          cap the server clamps, and a flag choosing between "successful logins only" (the default,
//          keeps the report compact) and "every observed login".
// Extends: Add a new [Key] here to introduce another server-side filter (e.g. a time window). Keys
//          are append-only.
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using MessagePack;

namespace RdpAudit.Core.Ipc.Contracts;

/// <summary>Bounded request for <c>GetAuthSuccessSummaryForIp</c>.</summary>
[MessagePackObject(keyAsPropertyName: false)]
public sealed class AuthSuccessSummaryRequest
{
	/// <summary>Canonical IPv4 / IPv6 literal. Required.</summary>
	[Key(0)]
	public string Ip { get; set; } = string.Empty;

	/// <summary>Requested per-login row cap. Zero means "use server default"; the server hard-caps.</summary>
	[Key(1)]
	public int Limit { get; set; }

	/// <summary>When true (default), only logins that had at least one success are returned. When
	/// false, every observed login for the IP is returned regardless of outcome.</summary>
	[Key(2)]
	public bool SucceededLoginsOnly { get; set; } = true;
}
