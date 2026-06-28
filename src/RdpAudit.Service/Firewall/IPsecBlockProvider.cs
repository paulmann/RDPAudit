// File:    src/RdpAudit.Service/Firewall/IPsecBlockProvider.cs
// Module:  RdpAudit.Service.Firewall
// Purpose: Advanced IPsec block-policy backend, delivered as a clean IFirewallProvider with an
//          explicit NotImplemented status. A full IPsec implementation must enumerate and compose
//          with existing local/domain IPsec policies WITHOUT overwriting unrelated rules; doing
//          that safely is larger than this stabilisation patch, so rather than risk a partial,
//          policy-clobbering write the backend reports NotImplemented with professional
//          diagnostics. The interface and DI wiring are in place so the gated implementation can
//          land later without touching the auto-block / expiration workers.
// Extends: RdpAudit.Core.Firewall.IFirewallProvider
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using Microsoft.Extensions.Logging;
using RdpAudit.Core.Firewall;

namespace RdpAudit.Service.Firewall;

/// <summary>IPsec block-policy <see cref="IFirewallProvider"/>; reports NotImplemented until the
/// policy-safe implementation lands. Never writes IPsec policy in this build.</summary>
public sealed class IPsecBlockProvider : IFirewallProvider
{
	private readonly ILogger<IPsecBlockProvider> _logger;

	public IPsecBlockProvider(ILogger<IPsecBlockProvider> logger)
	{
		ArgumentNullException.ThrowIfNull(logger);
		_logger = logger;
	}

	public string ProviderId => "IPsec";

	public Task<FirewallStatusReport> GetStatusAsync(CancellationToken ct)
	{
		ct.ThrowIfCancellationRequested();
		return Task.FromResult(new FirewallStatusReport
		{
			Status = FirewallProviderStatus.NotImplemented,
			ProviderId = ProviderId,
			Message = "IPsec block backend is present as a clean interface but not implemented in this build; "
				+ "a full implementation must compose with existing local/domain IPsec policy without overwriting it.",
		});
	}

	public Task<FirewallActionResult> BlockAsync(FirewallBlockRequest request, CancellationToken ct)
	{
		ArgumentNullException.ThrowIfNull(request);
		ct.ThrowIfCancellationRequested();
		_logger.LogInformation(
			"IPsec backend block requested for {Ip} but the backend is not implemented in this build",
			request.Ip);
		return Task.FromResult(FirewallActionResult.NotImplementedFor(ProviderId, "Block"));
	}

	public Task<FirewallActionResult> UnblockAsync(string ip, string ruleName, CancellationToken ct)
	{
		ArgumentException.ThrowIfNullOrWhiteSpace(ip);
		ct.ThrowIfCancellationRequested();
		return Task.FromResult(FirewallActionResult.NotImplementedFor(ProviderId, "Unblock"));
	}

	public Task<IReadOnlyList<FirewallBlockEntry>> ListBlocksAsync(string ruleName, CancellationToken ct)
	{
		ct.ThrowIfCancellationRequested();
		return Task.FromResult<IReadOnlyList<FirewallBlockEntry>>(Array.Empty<FirewallBlockEntry>());
	}
}
