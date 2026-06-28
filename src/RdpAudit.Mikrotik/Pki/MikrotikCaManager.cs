/*
 * File   : MikrotikCaManager.cs
 * Project: RdpAudit.Mikrotik (RdpAudit.Mikrotik.Pki)
 * Purpose: Manages the MikroTik Local CA hierarchy used for the mutual-TLS api-ssl channel. It can
 *          create a self-signed Local CA (for the bootstrap-on-Windows model) and produce the server
 *          certificate the router presents, all with the managed CertificateRequest API. The CA's
 *          public certificate is what WindowsCertStoreHelper imports into Trusted Root.
 * Depends: System.Security.Cryptography.X509Certificates.CertificateRequest, RSA, ClientCertGenerator
 * Extends: To change CA key strength / lifetime, edit CreateLocalCa; to issue another leaf type, add
 *          a method that mirrors CreateServerCertificate with a different EKU set.
 *
 * Author : Mikhail Deynekin — https://Deynekin.com
 * Version: 1.0.0
 */

using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace RdpAudit.Mikrotik.Pki;

/// <summary>The certificate trio that defines an RdpAudit mutual-TLS deployment.</summary>
/// <param name="Ca">Self-signed Local CA (holds private key, used to sign leaves).</param>
/// <param name="ServerCertificate">Server certificate the router presents on api-ssl.</param>
/// <param name="ClientCertificate">Client certificate Windows presents for mutual TLS.</param>
public sealed record MikrotikCertificateSet(
	X509Certificate2 Ca,
	X509Certificate2 ServerCertificate,
	X509Certificate2 ClientCertificate);

/// <summary>Manages the MikroTik Local CA hierarchy for the mutual-TLS api-ssl channel.</summary>
public sealed class MikrotikCaManager
{
	// ── Fields & DI ──────────────────────────────────────────────────────────────

	private const string ServerAuthEku = "1.3.6.1.5.5.7.3.1";
	private readonly ClientCertGenerator _clientGenerator = new();

	// ── Public API ───────────────────────────────────────────────────────────────

	/// <summary>Creates a self-signed Local CA certificate (with private key) valid for the given days.</summary>
	public X509Certificate2 CreateLocalCa(string commonName = "RdpAudit MikroTik Local CA", int validityDays = 3650)
	{
		ArgumentException.ThrowIfNullOrWhiteSpace(commonName);

		using RSA key = RSA.Create(4096);
		CertificateRequest request = new("CN=" + commonName, key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

		request.CertificateExtensions.Add(new X509BasicConstraintsExtension(certificateAuthority: true, hasPathLengthConstraint: true, pathLengthConstraint: 1, critical: true));
		request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign | X509KeyUsageFlags.DigitalSignature, critical: true));
		request.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(request.PublicKey, critical: false));

		DateTimeOffset notBefore = DateTimeOffset.UtcNow.AddMinutes(-5);
		DateTimeOffset notAfter = notBefore.AddDays(validityDays);

		using X509Certificate2 ca = request.CreateSelfSigned(notBefore, notAfter);
		byte[] pfx = ca.Export(X509ContentType.Pfx);
		return new X509Certificate2(pfx, (string?)null, X509KeyStorageFlags.Exportable | X509KeyStorageFlags.PersistKeySet);
	}

	/// <summary>
	/// Issues the api-ssl server certificate for <paramref name="serverIdentity"/> (router IP or host)
	/// signed by <paramref name="issuingCa"/>, with the serverAuth EKU and a matching SAN.
	/// </summary>
	public X509Certificate2 CreateServerCertificate(X509Certificate2 issuingCa, string serverIdentity, int validityDays = 825)
	{
		ArgumentNullException.ThrowIfNull(issuingCa);
		ArgumentException.ThrowIfNullOrWhiteSpace(serverIdentity);
		if (!issuingCa.HasPrivateKey)
		{
			throw new InvalidOperationException("The issuing CA certificate must hold a private key to sign the server certificate.");
		}

		using RSA key = RSA.Create(2048);
		CertificateRequest request = new("CN=" + serverIdentity, key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

		request.CertificateExtensions.Add(new X509BasicConstraintsExtension(certificateAuthority: false, hasPathLengthConstraint: false, pathLengthConstraint: 0, critical: true));
		request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment, critical: true));
		request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(new OidCollection { new Oid(ServerAuthEku) }, critical: false));

		SubjectAlternativeNameBuilder san = new();
		if (System.Net.IPAddress.TryParse(serverIdentity, out System.Net.IPAddress? ip))
		{
			san.AddIpAddress(ip);
		}
		else
		{
			san.AddDnsName(serverIdentity);
		}
		request.CertificateExtensions.Add(san.Build());

		DateTimeOffset notBefore = DateTimeOffset.UtcNow.AddMinutes(-5);
		DateTimeOffset notAfter = notBefore.AddDays(validityDays);
		byte[] serial = RandomNumberGenerator.GetBytes(16);

		using X509Certificate2 issued = request.Create(issuingCa, notBefore, notAfter, serial);
		X509Certificate2 withKey = issued.CopyWithPrivateKey(key);
		byte[] pfx = withKey.Export(X509ContentType.Pfx);
		withKey.Dispose();
		return new X509Certificate2(pfx, (string?)null, X509KeyStorageFlags.Exportable | X509KeyStorageFlags.PersistKeySet);
	}

	/// <summary>Creates a full CA + server + client certificate set in one call for the wizard.</summary>
	public MikrotikCertificateSet CreateCertificateSet(string serverIdentity, string clientCommonName = "RdpAudit Windows Client")
	{
		X509Certificate2 ca = CreateLocalCa();
		X509Certificate2 server = CreateServerCertificate(ca, serverIdentity);
		X509Certificate2 client = _clientGenerator.Generate(ca, clientCommonName);
		return new MikrotikCertificateSet(ca, server, client);
	}
}
