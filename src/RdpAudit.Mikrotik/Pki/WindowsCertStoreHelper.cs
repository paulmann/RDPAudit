/*
 * File   : WindowsCertStoreHelper.cs
 * Project: RdpAudit.Mikrotik (RdpAudit.Mikrotik.Pki)
 * Purpose: Installs, finds and removes RdpAudit certificates in the Windows certificate store using
 *          the managed X509Store API. The MikroTik Local CA certificate is imported into the machine
 *          Trusted Root so the api-ssl server certificate validates; the client certificate (with its
 *          private key) is placed in the current-user Personal store for mutual TLS.
 * Depends: System.Security.Cryptography.X509Certificates.X509Store
 * Extends: To target a different store (e.g. LocalMachine\My for a service-run client cert), add a
 *          StoreName/StoreLocation overload; to add an uninstall path, mirror RemoveByThumbprint.
 *
 * Author : Mikhail Deynekin — https://Deynekin.com
 * Version: 1.0.0
 */

using System.Security.Cryptography.X509Certificates;

namespace RdpAudit.Mikrotik.Pki;

/// <summary>Installs, finds and removes RdpAudit certificates in the Windows certificate store.</summary>
public sealed class WindowsCertStoreHelper
{
	// ── Public API ───────────────────────────────────────────────────────────────

	/// <summary>
	/// Imports <paramref name="caCertificate"/> (public part only) into LocalMachine\Root so the
	/// RouterOS api-ssl server certificate chains to a trusted root. Returns the installed thumbprint.
	/// Requires administrator rights (the wizard runs elevated).
	/// </summary>
	public string InstallCaIntoTrustedRoot(X509Certificate2 caCertificate)
	{
		ArgumentNullException.ThrowIfNull(caCertificate);

		using X509Certificate2 publicOnly = new(caCertificate.Export(X509ContentType.Cert));
		using X509Store store = new(StoreName.Root, StoreLocation.LocalMachine);
		store.Open(OpenFlags.ReadWrite);
		store.Add(publicOnly);
		return publicOnly.Thumbprint;
	}

	/// <summary>
	/// Installs the client certificate (with its private key, marked exportable+persisted) into
	/// CurrentUser\My for mutual-TLS authentication. Returns the installed thumbprint.
	/// </summary>
	public string InstallClientCertificate(X509Certificate2 clientCertificate)
	{
		ArgumentNullException.ThrowIfNull(clientCertificate);

		using X509Store store = new(StoreName.My, StoreLocation.CurrentUser);
		store.Open(OpenFlags.ReadWrite);
		store.Add(clientCertificate);
		return clientCertificate.Thumbprint;
	}

	/// <summary>Finds a certificate by thumbprint across the supplied store, or null when absent.</summary>
	public X509Certificate2? FindByThumbprint(string thumbprint, StoreName storeName, StoreLocation location)
	{
		if (string.IsNullOrWhiteSpace(thumbprint))
		{
			return null;
		}

		using X509Store store = new(storeName, location);
		store.Open(OpenFlags.ReadOnly);

		X509Certificate2Collection found = store.Certificates.Find(X509FindType.FindByThumbprint, thumbprint, validOnly: false);
		return found.Count > 0 ? found[0] : null;
	}

	/// <summary>Removes a certificate by thumbprint from the supplied store. Idempotent; returns true when removed.</summary>
	public bool RemoveByThumbprint(string thumbprint, StoreName storeName, StoreLocation location)
	{
		if (string.IsNullOrWhiteSpace(thumbprint))
		{
			return false;
		}

		using X509Store store = new(storeName, location);
		store.Open(OpenFlags.ReadWrite);

		X509Certificate2Collection found = store.Certificates.Find(X509FindType.FindByThumbprint, thumbprint, validOnly: false);
		if (found.Count == 0)
		{
			return false;
		}

		store.RemoveRange(found);
		return true;
	}
}
