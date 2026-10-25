// File:    tests/RdpAudit.Service.Tests/RestApiTestFakes.cs
// Module:  RdpAudit.Service.Tests
// Purpose: Shared test doubles for the read-only REST API layer: a secret protector that either
//          returns a fixed token or throws SecretProtectionException, a certificate resolver
//          stub, a service-scope factory for the outer-container bridge, and a fixed
//          IOptionsMonitor used by RestApiHostedService tests.
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using RdpAudit.Core.Security;
using RdpAudit.Service.RestApi;

namespace RdpAudit.Service.Tests;

internal sealed class StubSecretProtector : ISecretProtector
{
	private readonly string? _unprotectedValue;
	private readonly bool _throwOnUnprotect;

	private StubSecretProtector(string? unprotectedValue, bool throwOnUnprotect)
	{
		_unprotectedValue = unprotectedValue;
		_throwOnUnprotect = throwOnUnprotect;
	}

	/// <summary>Protector that resolves every envelope to the supplied plaintext.</summary>
	public static StubSecretProtector Returning(string value) => new(value, false);

	/// <summary>Protector whose <see cref="Unprotect"/> always throws.</summary>
	public static StubSecretProtector Throwing() => new(null, true);

	public bool IsAvailable => !_throwOnUnprotect;

	public string Protect(string plaintext, SecretScope scope = SecretScope.LocalMachine)
		=> plaintext;

	public string Unprotect(string envelopeOrPlaintext)
	{
		if (_throwOnUnprotect)
		{
			throw new SecretProtectionException("Unprotect failed (test stub).");
		}

		return _unprotectedValue!;
	}

	public bool IsProtectedEnvelope(string? value) => false;
}

internal sealed class StubCertificateResolver : IRestApiCertificateResolver
{
	private readonly X509Certificate2? _certificate;
	private readonly string? _failureReason;

	public StubCertificateResolver(X509Certificate2? certificate, string? failureReason = null)
	{
		_certificate = certificate;
		_failureReason = failureReason;
	}

	public static StubCertificateResolver Failed(string reason) => new(null, reason);

	public RestApiCertificateResolution Resolve(string? thumbprint, string? subject)
		=> _certificate is not null
			? new RestApiCertificateResolution(_certificate, null)
			: new RestApiCertificateResolution(null, _failureReason);
}

/// <summary>Scope factory for the outer-container bridge; the stub provider resolves nothing.</summary>
internal sealed class StubScopeFactory : IServiceScopeFactory
{
	public IServiceScope CreateScope() => new StubScope();

	private sealed class StubScope : IServiceScope
	{
		public IServiceProvider ServiceProvider { get; } = new StubProvider();

		public void Dispose()
		{
			// Nothing to release.
		}
	}

	private sealed class StubProvider : IServiceProvider
	{
		public object? GetService(Type serviceType) => null;
	}
}

/// <summary>Fixed IOptionsMonitor for tests that do not need change notifications.</summary>
internal sealed class FixedOptionsMonitor<T> : IOptionsMonitor<T>
	where T : class
{
	private readonly T _value;

	public FixedOptionsMonitor(T value)
	{
		_value = value;
	}

	public T CurrentValue => _value;

	public T Get(string? name) => _value;

	public IDisposable? OnChange(Action<T, string?> listener) => null;
}

internal static class RestApiTestCertificateFactory
{
	/// <summary>Creates a self-signed server certificate (RSA, serverAuth EKU, IP+DNS SANs).</summary>
	public static X509Certificate2 CreateExpired(string commonName = "RdpAudit Expired")
	{
		return Create(DateTimeOffset.UtcNow.AddDays(-2), DateTimeOffset.UtcNow.AddDays(-1), commonName);
	}

	public static X509Certificate2 CreateSelfSigned(string commonName = "RdpAudit Test")
	{
		return Create(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(365), commonName);
	}

	private static X509Certificate2 Create(DateTimeOffset notBefore, DateTimeOffset notAfter, string commonName)
	{
		using RSA rsa = RSA.Create(2048);
		CertificateRequest request = new(
			$"CN={commonName}",
			rsa,
			HashAlgorithmName.SHA256,
			RSASignaturePadding.Pkcs1);
		request.CertificateExtensions.Add(
			new X509BasicConstraintsExtension(false, false, 0, false));
		request.CertificateExtensions.Add(
			new X509KeyUsageExtension(
				X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment,
				false));
		request.CertificateExtensions.Add(
			new X509EnhancedKeyUsageExtension(
				new OidCollection { new Oid("1.3.6.1.5.5.7.3.1") },
				false));

		SubjectAlternativeNameBuilder san = new();
		san.AddIpAddress(IPAddress.Loopback);
		san.AddDnsName("localhost");
		request.CertificateExtensions.Add(san.Build());

		return request.CreateSelfSigned(
			notBefore,
			notAfter);
	}
}