// File:    src/RdpAudit.Core/Firewall/IFirewallProvider.cs
// Module:  RdpAudit.Core.Firewall
// Purpose: Abstraction for any firewall provider RdpAudit can drive (Windows Advanced Firewall,
//          MikroTik RouterOS, future cloud providers). All methods are async and honour the
//          supplied CancellationToken; never block on .Result / .Wait.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

namespace RdpAudit.Core.Firewall;

/// <summary>Abstraction for any firewall provider RdpAudit can drive.</summary>
/// <remarks>
/// Provider implementations MUST be safe to call from background workers and must never log
/// plaintext credentials. Implementations are wired into DI; Stage 1 ships stub implementations
/// that compile, expose a stable contract, and return <see cref="FirewallActionStatus.NotImplemented"/>.
/// </remarks>
public interface IFirewallProvider
{
	/// <summary>Stable, machine-readable identifier ("Windows", "MikroTik", ...).</summary>
	string ProviderId { get; }

	/// <summary>Returns a snapshot of the provider's current readiness.</summary>
	Task<FirewallStatusReport> GetStatusAsync(CancellationToken ct);

	/// <summary>Installs (or refreshes) a block for the supplied IP. Implementations are idempotent.</summary>
	Task<FirewallActionResult> BlockAsync(FirewallBlockRequest request, CancellationToken ct);

	/// <summary>Removes a previously installed block for the supplied IP. Missing rules are non-fatal.</summary>
	Task<FirewallActionResult> UnblockAsync(string ip, string ruleName, CancellationToken ct);

	/// <summary>Lists active blocks attributable to the supplied base rule name.</summary>
	Task<IReadOnlyList<FirewallBlockEntry>> ListBlocksAsync(string ruleName, CancellationToken ct);
}
