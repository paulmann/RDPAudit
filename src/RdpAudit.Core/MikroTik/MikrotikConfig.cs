/*
 * File   : MikrotikConfig.cs
 * Project: RdpAudit.Core (RdpAudit.Core.MikroTik)
 * Purpose: Persisted result of a completed MikroTik api-ssl/mTLS bootstrap — the production
 *          mutual-TLS channel description shared between the RdpAudit.Mikrotik wizard and the
 *          running Service. Distinct from RdpAudit.Core.Config.MikroTikOptions (the legacy REST
 *          provider): this type describes the certificate-pinned api-ssl path, not Basic-auth REST.
 * Depends: System.Object
 * Extends: When the bootstrap learns a new durable fact about the router (e.g. an additional RAW
 *          chain rule id, a second address-list, an IPv6 contour), add a property here, surface it
 *          in MikrotikConfigPushMessage, and have BootstrapOrchestrator populate it.
 *
 * Author : Mikhail Deynekin — https://Deynekin.com
 * Version: 1.0.1
 */

using System.Globalization;

namespace RdpAudit.Core.MikroTik;

/// <summary>
/// Persisted, credential-light description of a completed MikroTik api-ssl/mutual-TLS bootstrap.
/// </summary>
/// <remarks>
/// <see cref="ServicePasswordDpapi"/> is a DPAPI (CurrentUser) protected envelope, never a plaintext
/// secret; it must never be logged or echoed in an IPC response. Certificates are referenced by
/// SHA-1 thumbprint only — the private keys live in the Windows certificate store, not in this type.
/// </remarks>
public sealed class MikrotikConfig
{
	// ── Public API ───────────────────────────────────────────────────────────────

	/// <summary>RouterOS management IP literal the production channel connects to (e.g. "192.168.88.1").</summary>
	public string RouterIp { get; set; } = string.Empty;

	/// <summary>TCP port of the RouterOS api-ssl service. RouterOS default is 8729.</summary>
	public int ApiSslPort { get; set; } = 8729;

	/// <summary>Randomly generated, least-privilege RouterOS service account ("rdpaudit_xxxxxxxx").</summary>
	public string ServiceUsername { get; set; } = string.Empty;

	/// <summary>DPAPI-protected (CurrentUser) envelope wrapping the service account password.</summary>
	public string ServicePasswordDpapi { get; set; } = string.Empty;

	/// <summary>SHA-1 thumbprint of the MikroTik Local CA certificate imported into Windows Trusted Root.</summary>
	public string CaCertThumbprint { get; set; } = string.Empty;

	/// <summary>SHA-1 thumbprint of the Windows client certificate presented for mutual-TLS.</summary>
	public string ClientCertThumbprint { get; set; } = string.Empty;

	/// <summary>True once the firewall blocking contour (address-list drop rules) has been installed.</summary>
	public bool FirewallRulesInstalled { get; set; }

	/// <summary>RouterOS address-list that holds blocked RDP attacker IPs.</summary>
	public string AddressListName { get; set; } = "rdpaudit_rdp_blocklist";

	/// <summary>Default RouterOS timeout string applied to address-list entries (e.g. "24h").</summary>
	public string DefaultBanTimeout { get; set; } = "24h";

	/// <summary>UTC instant the bootstrap completed; null until a successful bootstrap is recorded.</summary>
	public DateTime? BootstrappedUtc { get; set; }

	/// <summary>Returns a sanitised, credential-free endpoint description for logs and UI.</summary>
	public string DescribeEndpoint()
	{
		if (string.IsNullOrWhiteSpace(RouterIp))
		{
			return string.Empty;
		}
		return string.Format(CultureInfo.InvariantCulture, "api-ssl://{0}:{1}", RouterIp, ApiSslPort);
	}

	/// <summary>True when enough fields are present to attempt a production mutual-TLS connection.</summary>
	public bool IsUsable()
		=> !string.IsNullOrWhiteSpace(RouterIp)
			&& ApiSslPort > 0
			&& !string.IsNullOrWhiteSpace(ServiceUsername)
			&& !string.IsNullOrWhiteSpace(ServicePasswordDpapi)
			&& !string.IsNullOrWhiteSpace(ClientCertThumbprint);
}
