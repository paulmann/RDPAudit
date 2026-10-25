// File:    src/RdpAudit.Web/Config/WebUiProxyOptions.cs
// Module:  RdpAudit.Web
// Purpose: Configuration surface of the IIS-hosted web-UI proxy: the backend REST base URL,
//          the shared token-vault file, the backend TLS certificate thumbprint pin and the
//          explicit developer switch that relaxes the Content-Security-Policy for the reference
//          dashboard. Every value is optional with a safe default; <see cref="Resolve"/> finalizes
//          them at boot and enforces the loopback-only security model of the plan.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System.Net;
using RdpAudit.Core.Util;

namespace RdpAudit.Web.Config;

/// <summary>Resolved web-UI proxy options.</summary>
public sealed class WebUiProxyOptions
{
	/// <summary>Path to the shared bearer-token vault file; blank = canonical ProgramData path.</summary>
	public string TokenVaultPath { get; set; } = string.Empty;

	/// <summary>Base URL of the service REST endpoint this proxy forwards /api/* to.</summary>
	public string BackendBaseUrl { get; set; } = "https://127.0.0.1:8443";

	/// <summary>Thumbprint of the backend TLS certificate for pinning; blank = system validation.</summary>
	public string BackendCertificateThumbprint { get; set; } = string.Empty;

	/// <summary>When true, a non-loopback backend URL is accepted. OFF by default (fail-safe).</summary>
	public bool AllowNonLoopbackBackend { get; set; }

	/// <summary>When true, CSP allows inline scripts/styles. OFF by default (fail-safe).</summary>
	public bool AllowInlineScripts { get; set; }

	/// <summary>Absolute path of the token vault actually in use.</summary>
	public string ResolvedTokenVaultPath { get; private set; } = string.Empty;

	/// <summary>Base URL of the backend actually in use.</summary>
	public string ResolvedBackendBaseUrl { get; private set; } = string.Empty;

	/// <summary>Normalized thumbprint of the pinned backend certificate (blank = not pinned).</summary>
	public string ResolvedBackendCertificateThumbprint { get; private set; } = string.Empty;

	/// <summary>Finalises the options: validates them, resolves defaults and enforces the security model.</summary>
	/// <exception cref="InvalidOperationException">On unusable backend URL/token path, non-loopback backend
	/// without the explicit opt-in, or a malformed certificate thumbprint.</exception>
	public void Resolve()
	{
		ArgumentNullException.ThrowIfNull(BackendBaseUrl);

		string backend = BackendBaseUrl.Trim();
		if (backend.Length == 0 || !(Uri.TryCreate(backend, UriKind.Absolute, out Uri? backendUri)
			&& (backendUri.Scheme == Uri.UriSchemeHttps || backendUri.Scheme == Uri.UriSchemeHttp)))
		{
			throw new InvalidOperationException(
				"WebUI: the backend base URL must be an absolute http/https URL (example: https://127.0.0.1:8443).");
		}

		if (!IsLoopbackHost(backendUri) && !AllowNonLoopbackBackend)
		{
			throw new InvalidOperationException(
				"WebUI: the backend base URL must target a loopback address; set AllowNonLoopbackBackend=true "
				+ "to deliberately accept a non-loopback backend (not recommended).");
		}

		ResolvedBackendBaseUrl = backend.TrimEnd('/');
		ResolvedTokenVaultPath = string.IsNullOrWhiteSpace(TokenVaultPath)
			? RdpAuditPaths.Default.WebUiTokenPath
			: Path.GetFullPath(TokenVaultPath.Trim());

		if (!string.IsNullOrWhiteSpace(BackendCertificateThumbprint))
		{
			string thumbprint = BackendCertificateThumbprint
				.Replace(" ", string.Empty, StringComparison.Ordinal)
				.Trim()
				.ToUpperInvariant();
			if (thumbprint.Length != 40 || thumbprint.Any(static c => !Uri.IsHexDigit(c)))
			{
				throw new InvalidOperationException(
					"WebUI: BackendCertificateThumbprint must be a 40-character hex certificate thumbprint.");
			}

			ResolvedBackendCertificateThumbprint = thumbprint;
		}
	}

	/// <summary>Returns true when the host is a loopback literal (IPv4 127.0.0.0/8, ::1 or 'localhost').</summary>
	private static bool IsLoopbackHost(Uri uri)
	{
		string host = uri.Host;
		if (string.Equals(host, "localhost", StringComparison.OrdinalIgnoreCase)
			|| string.Equals(host, "::1", StringComparison.Ordinal))
		{
			return true;
		}

		return IPAddress.TryParse(host, out IPAddress? address) && IPAddress.IsLoopback(address);
	}
}
