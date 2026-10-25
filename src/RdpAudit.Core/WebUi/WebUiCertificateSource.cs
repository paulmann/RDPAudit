// File:    src/RdpAudit.Core/WebUi/WebUiCertificateSource.cs
// Module:  RdpAudit.Core.WebUi
// Purpose: Certificate resolution and self-signed generation command for the Configure IIS
//          workflow (plan Step 11, variant A). The source READS LocalMachine\My for a
//          certificate that can serve the loopback dashboard (private key present, currently
//          valid, identity covering localhost via subject CN or DNS name, server
//          authentication EKU when one is declared). When none exists, the workflow generates
//          one through the self-signed command builder - the builder is a pure argument vector
//          (PowerShell, no shell concatenation) and the workflow executes it only through the
//          central IExternalCommandRunner, so unit tests stay deterministic and never touch the
//          machine certificate store. Self-signed detection is honest (issuer equals subject)
//          so the workflow can emit the required explicit trust warning.
//          net8-compatible by design: identity matching relies on the subject CN and
//          GetNameInfo(X509NameType.DnsName), never on .NET 9-only SAN enumeration APIs.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using RdpAudit.Core.Util;

namespace RdpAudit.Core.WebUi;

/// <summary>Resolved certificate usable for the loopback dashboard binding.</summary>
public sealed record WebUiCertificateInfo(string Thumbprint, bool SelfSigned);

/// <summary>Abstraction over the machine certificate lookup so the Configure workflow is testable.</summary>
public interface IWebUiCertificateSource
{
	/// <summary>Finds a machine certificate usable for the loopback HTTPS binding; null when none exists.</summary>
	WebUiCertificateInfo? FindUsableCertificate();
}

/// <summary>Windows implementation backed by <c>LocalMachine\My</c> (read-only).</summary>
[SupportedOSPlatform("windows")]
public sealed class WindowsWebUiCertificateSource : IWebUiCertificateSource
{
	/// <summary>Object identifier of the server-authentication enhanced key usage.</summary>
	public const string ServerAuthOid = "1.3.6.1.5.5.7.3.1";

	/// <inheritdoc />
	public WebUiCertificateInfo? FindUsableCertificate()
	{
		if (!OperatingSystem.IsWindows())
		{
			return null;
		}

		try
		{
			using X509Store store = new(StoreName.My, StoreLocation.LocalMachine);
			store.Open(OpenFlags.ReadOnly);

			DateTime now = DateTime.UtcNow;
			X509Certificate2? best = store.Certificates
				.Cast<X509Certificate2>()
				.Where(static c => c.HasPrivateKey)
				.Where(c => c.NotBefore.ToUniversalTime() <= now && c.NotAfter.ToUniversalTime() > now)
				.Where(SupportsServerAuthentication)
				.Where(MatchesLoopbackIdentity)
				.OrderByDescending(static c => c.NotAfter.ToUniversalTime())
				.FirstOrDefault();
			if (best is null)
			{
				return null;
			}

			return new WebUiCertificateInfo(
				NormalizeThumbprint(best.Thumbprint),
				IsSelfSigned(best));
		}
		catch (CryptographicException)
		{
			// Store unavailable or a certificate could not be inspected: report 'none found'.
			return null;
		}
	}

	private static bool SupportsServerAuthentication(X509Certificate2 certificate)
	{
		X509EnhancedKeyUsageExtension? eku = certificate.Extensions
			.OfType<X509EnhancedKeyUsageExtension>()
			.FirstOrDefault();
		if (eku is null)
		{
			// No EKU constraint declared: acceptable for a loopback listener.
			return true;
		}

		foreach (Oid usage in eku.EnhancedKeyUsages)
		{
			if (string.Equals(usage.Value, ServerAuthOid, StringComparison.Ordinal))
			{
				return true;
			}
		}

		return false;
	}

	private static bool MatchesLoopbackIdentity(X509Certificate2 certificate)
	{
		try
		{
			// The legacy CN form covers both certificates whose SAN is absent and the ones whose
			// subject still carries CN=localhost (IIS Express dev cert, New-SelfSignedCertificate).
			string subject = certificate.Subject;
			if (subject.Contains("CN=localhost", StringComparison.OrdinalIgnoreCase)
				|| subject.Contains("CN=127.0.0.1", StringComparison.OrdinalIgnoreCase))
			{
				return true;
			}

			string dnsName = certificate.GetNameInfo(X509NameType.DnsName, forIssuer: false);
			return !string.IsNullOrWhiteSpace(dnsName)
				&& string.Equals(dnsName.Trim(), "localhost", StringComparison.OrdinalIgnoreCase);
		}
		catch (CryptographicException)
		{
			return false;
		}
	}

	private static bool IsSelfSigned(X509Certificate2 certificate)
		=> string.Equals(certificate.Issuer, certificate.Subject, StringComparison.OrdinalIgnoreCase);

	private static string NormalizeThumbprint(string thumbprint)
		=> thumbprint.Replace(" ", string.Empty, StringComparison.Ordinal).ToUpperInvariant();
}

/// <summary>
/// Pure argument vector for generating the loopback dashboard certificate. Never executes
/// anything; the Configure workflow runs the vector via <see cref="RdpAudit.Core.Util.IExternalCommandRunner"/>.
/// </summary>
public static class WebUiSelfSignedCertificateCommandSet
{
	/// <summary>PowerShell executable used to mint the self-signed certificate. Resolved through the
	/// shared host resolver, so this never pins Windows PowerShell 5.1 when PowerShell 7 is available.
	/// The cmdlet itself (New-SelfSignedCertificate) resolves natively in pwsh 7 through the PKI
	/// module, so the switch needs no script change.</summary>
	public static string PowerShellExecutable => PowerShellHostResolver.Executable;

	/// <summary>Friendly name of the generated certificate (operator-visible in the store).</summary>
	public const string CertificateFriendlyName = "RdpAudit Web UI";

	/// <summary>
	/// Builds the PowerShell argument vector that creates a self-signed loopback certificate
	/// in LocalMachine\My. DNS names cover localhost and the loopback IP literals; the exportable
	/// key policy keeps the tooling friendly without weakening the store placement.
	/// </summary>
	public static IReadOnlyList<string> BuildNewSelfSignedCertificateArguments() => new[]
	{
		"-NoProfile",
		"-NonInteractive",
		"-ExecutionPolicy",
		"Bypass",
		"-Command",
		"New-SelfSignedCertificate -DnsName 'localhost','127.0.0.1','::1' "
			+ "-CertStoreLocation 'Cert:\\LocalMachine\\My' "
			+ "-FriendlyName '" + CertificateFriendlyName + "' "
			+ "-KeyExportPolicy Exportable -NotAfter (Get-Date).AddYears(5)",
	};
}
