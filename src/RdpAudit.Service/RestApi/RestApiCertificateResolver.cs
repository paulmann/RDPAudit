/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 2.3.6
// File   : RestApiCertificateResolver.cs
// Project: RdpAudit.Service (RdpAudit.Service.RestApi)
// Purpose: Resolves the server TLS certificate for the read-only REST API from the LocalMachine\My
//          certificate store. Thumbprint takes precedence over subject; the store can be replaced
//          in tests via the optional constructor parameter.
// Depends: System.Security.Cryptography.X509Certificates
// Extends: Add a CurrentUser store fallback when needed.

using System.Security.Cryptography.X509Certificates;

namespace RdpAudit.Service.RestApi;

/// <summary>
/// Resolves the REST API server certificate from the supplied certificate store. Failures to
/// resolve never throw - they return a structured reason the plan builder turns into a fail-closed
/// decision.
/// </summary>
public sealed class RestApiCertificateResolver : IRestApiCertificateResolver
{
	private readonly Func<StoreLocation, X509Store> _storeFactory;

	/// <summary>Creates a resolver bound to the LocalMachine\My store.</summary>
	public RestApiCertificateResolver()
		: this(static location => new X509Store(StoreName.My, location))
	{
	}

	/// <summary>Creates a resolver using the supplied store factory (test seam).</summary>
	public RestApiCertificateResolver(Func<StoreLocation, X509Store> storeFactory)
	{
		_storeFactory = storeFactory ?? throw new ArgumentNullException(nameof(storeFactory));
	}

	/// <summary>
	/// Resolves the certificate by thumbprint (first, case-insensitive, PEM-style separators
	/// removed) or by subject name (find-by-subject).
	/// </summary>
	public RestApiCertificateResolution Resolve(string? thumbprint, string? subject)
	{
		string? normalizedThumbprint = NormalizeThumbprint(thumbprint);
		if (!string.IsNullOrEmpty(normalizedThumbprint))
		{
			return ResolveByThumbprint(normalizedThumbprint);
		}

		return ResolveBySubject(subject);
	}

	private RestApiCertificateResolution ResolveByThumbprint(string thumbprint)
	{
		using X509Store store = _storeFactory(StoreLocation.LocalMachine);
		store.Open(OpenFlags.ReadOnly);

		X509Certificate2Collection matches = store.Certificates.Find(
			X509FindType.FindByThumbprint,
			thumbprint,
			validOnly: false);

		if (matches.Count == 0)
		{
			return new RestApiCertificateResolution(null,
				"no certificate matched the configured thumbprint in LocalMachine\\My");
		}

		X509Certificate2 selected = matches[0];
		if (!selected.HasPrivateKey)
		{
			return new RestApiCertificateResolution(null,
				"the configured certificate exists but cannot be used as a server certificate (no private key accessible)");
		}

		if (selected.NotAfter.ToUniversalTime() < DateTime.UtcNow)
		{
			return new RestApiCertificateResolution(null,
				"the configured certificate has expired");
		}

		return new RestApiCertificateResolution(new X509Certificate2(selected), null);
	}

	private RestApiCertificateResolution ResolveBySubject(string? subject)
	{
		if (string.IsNullOrWhiteSpace(subject))
		{
			return new RestApiCertificateResolution(null,
				"no Api.CertificateThumbprint and no Api.CertificateSubject configured");
		}

		string trimmedSubject = subject.Trim();
		using X509Store store = _storeFactory(StoreLocation.LocalMachine);
		store.Open(OpenFlags.ReadOnly);

		X509Certificate2Collection matches = store.Certificates.Find(
			X509FindType.FindBySubjectName,
			trimmedSubject,
			validOnly: false);

		if (matches.Count == 0)
		{
			return new RestApiCertificateResolution(null,
				"no certificate matched the configured subject in LocalMachine\\My");
		}

		// Prefer the first match that is currently valid and has a private key, otherwise the
		// first match at all - the plan builder applies its own self-signed / expiry surface.
		X509Certificate2? selected = null;
		DateTime utcNow = DateTime.UtcNow;
		foreach (X509Certificate2 candidate in matches)
		{
			if (candidate.HasPrivateKey && candidate.NotAfter.ToUniversalTime() >= utcNow)
			{
				selected = candidate;
				break;
			}
		}

		selected ??= matches[0];
		return new RestApiCertificateResolution(new X509Certificate2(selected), null);
	}

	private static string? NormalizeThumbprint(string? thumbprint)
	{
		if (string.IsNullOrWhiteSpace(thumbprint))
		{
			return null;
		}

		return thumbprint.Trim()
			.Replace(" ", string.Empty, StringComparison.Ordinal)
			.Replace(":", string.Empty, StringComparison.Ordinal)
			.ToUpperInvariant();
	}
}
