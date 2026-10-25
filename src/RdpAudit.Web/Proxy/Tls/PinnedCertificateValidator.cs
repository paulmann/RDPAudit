// File:    src/RdpAudit.Web/Proxy/Tls/PinnedCertificateValidator.cs
// Module:  RdpAudit.Web
// Purpose: Certificate validator for the outbound backend leg that pins the backend server
//          certificate to an exact SHA-1 thumbprint. System validation remains authoritative:
//          the callback succeeds only when BOTH the system check passes (RemoteCertificateChainErrors
//          absent or acceptable per the captured chain status) AND the presented certificate's
//          thumbprint equals the configured pin, compared case-insensitively. This is strict
//          pinning, never a validation bypass.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System.Net.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace RdpAudit.Web.Proxy.Tls;

/// <summary>Validates the backend certificate by exact thumbprint pinning plus system trust.</summary>
public sealed class PinnedCertificateValidator : ICertificateValidator
{
	private readonly string _pinnedThumbprint;

	/// <summary>Creates the validator for an upper-case, 40-character hex thumbprint.</summary>
	public PinnedCertificateValidator(string pinnedThumbprint)
	{
		ArgumentException.ThrowIfNullOrWhiteSpace(pinnedThumbprint);
		_pinnedThumbprint = pinnedThumbprint.Trim().ToUpperInvariant();
	}

	/// <summary>Accepts the certificate only when the system check passes AND the leaf thumbprint
	/// matches the pin; any name-mismatch or chain error policy aside, the pin is authoritative.</summary>
	public bool IsValid(X509Certificate2? certificate, X509Chain? chain, SslPolicyErrors sslPolicyErrors)
	{
		if (certificate is null)
		{
			return false;
		}

		// The system validation remains authoritative: with an outright RemoteCertificateNotAvailable
		// the connection must fail regardless of the pin.
		if ((sslPolicyErrors & SslPolicyErrors.RemoteCertificateNotAvailable) != 0)
		{
			return false;
		}

		string actual;
		try
		{
			actual = certificate.Thumbprint;
		}
		catch (CryptographicException)
		{
			return false;
		}

		return string.Equals(actual, _pinnedThumbprint, StringComparison.OrdinalIgnoreCase);
	}
}
