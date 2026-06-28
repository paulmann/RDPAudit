// File:    src/RdpAudit.Core/Ipc/Contracts/LoginRuleMutationRequest.cs
// Module:  RdpAudit.Core.Ipc.Contracts
// Purpose: Request payload for AddLoginRule / RemoveLoginRule / SetLoginRuleEnabled.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using MessagePack;

namespace RdpAudit.Core.Ipc.Contracts;

/// <summary>Request payload for login-rule mutation commands.</summary>
/// <remarks>
/// For Add the server normalises <see cref="Login"/> (trim, lower-case) and ignores <see cref="Id"/>.
/// For Remove the server prefers <see cref="Id"/>, falling back to <see cref="Login"/> match when
/// <see cref="Id"/> is zero. For SetEnabled both <see cref="Id"/> and <see cref="Enabled"/> are required.
/// </remarks>
[MessagePackObject(keyAsPropertyName: false)]
public sealed class LoginRuleMutationRequest
{
	[Key(0)]
	public long Id { get; set; }

	[Key(1)]
	public string Login { get; set; } = string.Empty;

	[Key(2)]
	public string? Note { get; set; }

	[Key(3)]
	public bool Enabled { get; set; } = true;
}
