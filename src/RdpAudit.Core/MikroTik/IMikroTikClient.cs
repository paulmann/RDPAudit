// File:    src/RdpAudit.Core/MikroTik/IMikroTikClient.cs
// Module:  RdpAudit.Core.MikroTik
// Purpose: Abstraction over the MikroTik RouterOS v7 REST API used by the Stage 9 firewall
//          provider. Living in Core lets unit tests swap in a fake without depending on HttpClient
//          internals or the Service host. Implementations MUST never log plaintext credentials,
//          never delete rules they did not author (comment-prefix check) and surface controlled
//          MikroTikOperationResult values for every code path.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

namespace RdpAudit.Core.MikroTik;

/// <summary>Abstraction over the MikroTik RouterOS v7 REST API.</summary>
public interface IMikroTikClient
{
	/// <summary>Performs a safe read-only probe (typically /rest/system/resource) to validate connectivity / credentials.</summary>
	Task<MikroTikOperationResult> PingAsync(CancellationToken ct);

	/// <summary>Lists firewall filter rules whose comment matches the configured RdpAudit prefix.</summary>
	Task<(MikroTikOperationResult Result, IReadOnlyList<MikroTikRule> Rules)> ListOwnedRulesAsync(CancellationToken ct);

	/// <summary>Creates (or reuses) a firewall filter rule for the supplied attacker IP. Idempotent.</summary>
	Task<MikroTikOperationResult> AddBlockAsync(MikroTikBlockRequest request, CancellationToken ct);

	/// <summary>Removes a firewall filter rule previously created by this provider.</summary>
	/// <param name="ruleId">Server-assigned rule id (returned by <see cref="AddBlockAsync"/>).</param>
	/// <param name="ip">Source IP literal whose rule should be removed (used for matching when no id is known).</param>
	/// <param name="ct">Cancellation token.</param>
	Task<MikroTikOperationResult> RemoveBlockAsync(string? ruleId, string ip, CancellationToken ct);
}
