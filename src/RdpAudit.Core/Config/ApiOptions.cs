/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 2.1.0
// File   : ApiOptions.cs
// Project: RdpAudit.Core (RdpAudit.Core.Config)
// Purpose: Configures the optional read-only HTTPS REST API (roadmap backlog #3). Disabled by
//          default so existing installations expose no new listening surface until an operator
//          opts in. The bearer token is stored as a protected envelope exactly like the other
//          credentials and must never be logged or echoed in IPC payloads.
// Depends: System
// Extends: Add per-endpoint rate-limit overrides when the API outgrows a single global window.

namespace RdpAudit.Core.Config;

/// <summary>
/// Settings for the optional read-only HTTPS REST API. Disabled by default: the Kestrel
/// listener is only started when <see cref="Enabled"/> is true and a usable token plus TLS
/// certificate are resolvable (fail-closed). Default listen address is the IPv4 loopback;
/// exposing a non-loopback address or opting into <see cref="AllowInsecureLoopback"/> is
/// logged with an explicit risk warning by the hosting layer.
/// </summary>
public sealed class ApiOptions
{
	/// <summary>Smallest effective listen port.</summary>
	public const int MinPort = 1;

	/// <summary>Largest effective listen port.</summary>
	public const int MaxPort = 65535;

	/// <summary>Smallest effective per-IP request budget (requests per minute).</summary>
	public const int MinRateLimitPerMinute = 1;

	/// <summary>Largest effective per-IP request budget. Bounds the memory of the fixed-window limiter.</summary>
	public const int MaxRateLimitPerMinute = 60_000;

	/// <summary>Smallest effective concurrent-connection cap.</summary>
	public const int MinMaxConnections = 1;

	/// <summary>Largest effective concurrent-connection cap.</summary>
	public const int MaxMaxConnections = 10_000;

	/// <summary>Default listen address (IPv4 loopback), used when <see cref="ListenAddress"/> is blank.</summary>
	public const string DefaultListenAddress = "127.0.0.1";

	/// <summary>Default listen port.</summary>
	public const int DefaultPort = 8443;

	/// <summary>Master switch for the REST API listener. Defaults to false.</summary>
	public bool Enabled { get; set; }

	/// <summary>
	/// Static bearer token required by every endpoint except <c>/healthz</c>. Stored in
	/// protected-envelope form (e.g. a DPAPI payload tagged with "$protected") like the
	/// AbuseIPDB / MikroTik credentials; plaintext is accepted on first enable and wrapped
	/// by <c>SettingsManager</c> before persistence.
	/// </summary>
	public string Token { get; set; } = string.Empty;

	/// <summary>Listen address for the HTTPS listener. Blank resolves to <see cref="DefaultListenAddress"/>.</summary>
	public string ListenAddress { get; set; } = DefaultListenAddress;

	/// <summary>Listen port. Clamped to [<see cref="MinPort"/>, <see cref="MaxPort"/>]; defaults to <see cref="DefaultPort"/>.</summary>
	public int Port { get; set; } = DefaultPort;

	/// <summary>Thumbprint of the server TLS certificate in <c>LocalMachine\My</c>. Takes precedence over <see cref="CertificateSubject"/>.</summary>
	public string CertificateThumbprint { get; set; } = string.Empty;

	/// <summary>Subject name of the server TLS certificate, used only when <see cref="CertificateThumbprint"/> is blank.</summary>
	public string CertificateSubject { get; set; } = string.Empty;

	/// <summary>
	/// When true, the listener may accept a self-signed / non-validated certificate (or a
	/// plain HTTP loopback when the hosting layer supports it) - for loopback deployments
	/// only. The hosting layer logs an explicit risk warning. Defaults to false.
	/// </summary>
	public bool AllowInsecureLoopback { get; set; }

	/// <summary>Maximum concurrent Kestrel connections. Clamped to [<see cref="MinMaxConnections"/>, <see cref="MaxMaxConnections"/>].</summary>
	public int MaxConnections { get; set; } = 100;

	/// <summary>Per-IP fixed-window request budget per minute. Clamped to [<see cref="MinRateLimitPerMinute"/>, <see cref="MaxRateLimitPerMinute"/>].</summary>
	public int RateLimitPerMinute { get; set; } = 60;

	/// <summary>Returns <see cref="Port"/> clamped to the supported range.</summary>
	public int ResolvePort() => Math.Clamp(Port, MinPort, MaxPort);

	/// <summary>Returns <see cref="MaxConnections"/> clamped to the supported range.</summary>
	public int ResolveMaxConnections() => Math.Clamp(MaxConnections, MinMaxConnections, MaxMaxConnections);

	/// <summary>Returns <see cref="RateLimitPerMinute"/> clamped to the supported range.</summary>
	public int ResolveRateLimitPerMinute() => Math.Clamp(RateLimitPerMinute, MinRateLimitPerMinute, MaxRateLimitPerMinute);

	/// <summary>Returns the trimmed listen address or the loopback default when blank.</summary>
	public string ResolveListenAddress()
	{
		if (!string.IsNullOrWhiteSpace(ListenAddress))
		{
			return ListenAddress.Trim();
		}

		return DefaultListenAddress;
	}

	/// <summary>True when the resolved listen address is a loopback literal (IPv4, IPv6, or host name).</summary>
	public bool IsLoopback()
	{
		string address = ResolveListenAddress();
		return string.Equals(address, "localhost", StringComparison.OrdinalIgnoreCase)
			|| string.Equals(address, DefaultListenAddress, StringComparison.Ordinal)
			|| string.Equals(address, "::1", StringComparison.Ordinal);
	}
}
