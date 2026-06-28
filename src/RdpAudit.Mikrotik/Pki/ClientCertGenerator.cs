/*
 * File   : ClientCertGenerator.cs
 * Project: RdpAudit.Mikrotik (RdpAudit.Mikrotik.Pki)
 * Purpose: Generates the RdpAudit client certificate used for mutual TLS against RouterOS api-ssl.
 *          The certificate is issued by the MikroTik Local CA (so RouterOS, which trusts its own CA,
 *          accepts the client) and carries the clientAuth EKU. Implemented with the managed
 *          CertificateRequest API — no PowerShell process and no third-party crypto library.
 * Depends: System.Security.Cryptography.X509Certificates.CertificateRequest, RSA, MikrotikCaManager
 * Extends: To change key size / algorithm, edit the RSA.Create call; to add a SAN or a different EKU,
 *          extend the SubjectAlternativeNameBuilder / X509EnhancedKeyUsageExtension setup.
 *
 * Author : Mikhail Deynekin — https://Deynekin.com
 * Version: 1.0.0
 */

using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace RdpAudit.Mikrotik.Pki;

/// <summary>Generates the mutual-TLS client certificate signed by the MikroTik Local CA.</summary>
public sealed class ClientCertGenerator
{
	// ── Fields & DI ──────────────────────────────────────────────────────────────

	/// <summary>clientAuth EKU OID (1.3.6.1.5.5.7.3.2).</summary>
	private const string ClientAuthEku = "1.3.6.1.5.5.7.3.2";

	// ── Public API ───────────────────────────────────────────────────────────────

	/// <summary>
	/// Issues a client certificate for <paramref name="subjectCommonName"/> signed by
	/// <paramref name="issuingCa"/> (which must hold a private key), valid for
	/// <paramref name="validityDays"/>. The returned certificate carries its own private key and is
	/// marked exportable so it can be installed into the Windows store.
	/// </summary>
	public X509Certificate2 Generate(X509Certificate2 issuingCa, string subjectCommonName, int validityDays = 825)
	{
		ArgumentNullException.ThrowIfNull(issuingCa);
		ArgumentException.ThrowIfNullOrWhiteSpace(subjectCommonName);
		if (!issuingCa.HasPrivateKey)
		{
			throw new InvalidOperationException("The issuing CA certificate must hold a private key to sign client certificates.");
		}

		using RSA key = RSA.Create(2048);
		CertificateRequest request = new(
			"CN=" + subjectCommonName,
			key,
			HashAlgorithmName.SHA256,
			RSASignaturePadding.Pkcs1);

		request.CertificateExtensions.Add(new X509BasicConstraintsExtension(certificateAuthority: false, hasPathLengthConstraint: false, pathLengthConstraint: 0, critical: true));
		request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment, critical: true));
		request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(new OidCollection { new Oid(ClientAuthEku) }, critical: false));
		request.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(request.PublicKey, critical: false));

		DateTimeOffset notBefore = DateTimeOffset.UtcNow.AddMinutes(-5);
		DateTimeOffset notAfter = notBefore.AddDays(validityDays);
		byte[] serial = RandomNumberGenerator.GetBytes(16);

		using X509Certificate2 issued = request.Create(issuingCa, notBefore, notAfter, serial);
		// Attach the freshly generated private key so the returned certificate is usable for TLS.
		X509Certificate2 withKey = issued.CopyWithPrivateKey(key);

		// Round-trip through a PFX export/import so the key is persisted and the cert is exportable.
		byte[] pfx = withKey.Export(X509ContentType.Pfx);
		withKey.Dispose();
		return new X509Certificate2(pfx, (string?)null, X509KeyStorageFlags.Exportable | X509KeyStorageFlags.PersistKeySet);
	}
}
