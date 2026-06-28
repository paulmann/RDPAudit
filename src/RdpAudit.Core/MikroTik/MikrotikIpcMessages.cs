/*
 * File   : MikrotikIpcMessages.cs
 * Project: RdpAudit.Core (RdpAudit.Core.MikroTik)
 * Purpose: JSON-serialized IPC payload contracts exchanged between the RdpAudit.Mikrotik wizard and
 *          the Service for the api-ssl/mTLS channel: the bootstrap push (PushMikroTikConfig = 61) and
 *          the mTLS status query reply (GetMikroTikMtlsStatus = 62). These payloads are serialized to
 *          a JSON string with RdpAudit.Core.Util.JsonOptions.Default and carried inside the
 *          MessagePack IpcRequest/IpcResponse envelope.
 * Depends: MikrotikConfig, RdpAudit.Core.Util.JsonOptions
 * Extends: When the wizard needs to send the Service a new fact, add a property to
 *          MikrotikConfigPushMessage; when the Service must report new health, add a property to
 *          MikrotikMtlsStatusReply. Keep both names distinct from the legacy REST DTOs
 *          (MikroTikStatusDto / MikroTikTestResult) to avoid collisions.
 *
 * Author : Mikhail Deynekin — https://Deynekin.com
 * Version: 1.0.1
 */

namespace RdpAudit.Core.MikroTik;

/// <summary>
/// Payload for <c>IpcCommand.PushMikroTikConfig</c>: the completed api-ssl/mTLS bootstrap result the
/// wizard hands to the Service so it can adopt the production mutual-TLS firewall channel.
/// </summary>
/// <remarks>
/// Carries no plaintext secret. <see cref="MikrotikConfig.ServicePasswordDpapi"/> is a DPAPI envelope
/// and the certificates are referenced by thumbprint; the Service resolves both at runtime.
/// </remarks>
public sealed class MikrotikConfigPushMessage
{
	/// <summary>The bootstrap result to adopt. Required.</summary>
	public MikrotikConfig Config { get; set; } = new();

	/// <summary>Schema/format version of this push, allowing forward-compatible Service handling.</summary>
	public int SchemaVersion { get; set; } = 1;

	/// <summary>Optional free-text note recorded in the Service operation log for traceability.</summary>
	public string? Note { get; set; }
}

/// <summary>
/// Reply payload for <c>IpcCommand.GetMikroTikMtlsStatus</c>: the Service's current view of the
/// MikroTik mutual-TLS channel. Never carries plaintext credentials.
/// </summary>
public sealed class MikrotikMtlsStatusReply
{
	/// <summary>True when the Service holds a usable api-ssl/mTLS configuration.</summary>
	public bool Configured { get; set; }

	/// <summary>Sanitised endpoint description (e.g. "api-ssl://192.168.88.1:8729"), or empty.</summary>
	public string Endpoint { get; set; } = string.Empty;

	/// <summary>RouterOS address-list the Service writes blocks into.</summary>
	public string AddressListName { get; set; } = string.Empty;

	/// <summary>True when the Service has verified the firewall blocking contour is installed.</summary>
	public bool FirewallRulesInstalled { get; set; }

	/// <summary>SHA-1 thumbprint of the trusted CA certificate, or empty when not configured.</summary>
	public string CaCertThumbprint { get; set; } = string.Empty;

	/// <summary>SHA-1 thumbprint of the client certificate presented for mutual-TLS, or empty.</summary>
	public string ClientCertThumbprint { get; set; } = string.Empty;

	/// <summary>True when the most recent api-ssl probe succeeded.</summary>
	public bool LastProbeSucceeded { get; set; }

	/// <summary>UTC of the most recent probe, or null when never probed.</summary>
	public DateTime? LastProbeUtc { get; set; }

	/// <summary>Curated, credential-free description of the last probe outcome for the UI.</summary>
	public string LastProbeMessage { get; set; } = string.Empty;
}
