// File:    src/RdpAudit.Web/Proxy/BackendHttpClientFactory.cs
// Module:  RdpAudit.Web
// Purpose: Builds the SocketsHttpHandler of the outbound backend leg. The handler keeps the
//          default system TLS validation unless BackendCertificateThumbprint pinning is
//          configured; in that case it additionally routes the server certificate through
//          <see cref="PinnedCertificateValidator"/> which accepts ONLY the exact pinned
//          thumbprint. Pinning plus validation must always be intentional, never silent.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System.Security.Cryptography.X509Certificates;
using RdpAudit.Web.Config;
using RdpAudit.Web.Proxy.Tls;

namespace RdpAudit.Web.Proxy;

/// <summary>Constructs outbound backend HTTP message invokers with optional certificate pinning.</summary>
internal static class BackendHttpClientFactory
{
	/// <summary>Pooled-connection lifetime for the outbound backend leg.</summary>
	internal static readonly TimeSpan PooledConnectionLifetime = TimeSpan.FromMinutes(5);

	/// <summary>Connect timeout for the outbound backend leg.</summary>
	internal static readonly TimeSpan ConnectTimeout = TimeSpan.FromSeconds(30);

	/// <summary>Creates the backend <see cref="HttpMessageInvoker"/>. When a thumbprint is pinned,
	/// the handler also carries a pinned-certificate validator; the produced invoker keeps a
	/// reference to the handler so disposing the invoker releases the handler.</summary>
	public static HttpMessageInvoker Create(WebUiProxyOptions options)
	{
		SocketsHttpHandler handler = new()
		{
			PooledConnectionLifetime = PooledConnectionLifetime,
			ConnectTimeout = ConnectTimeout,
		};

		if (options.ResolvedBackendCertificateThumbprint.Length > 0)
		{
			PinnedCertificateValidator validator = new(
				options.ResolvedBackendCertificateThumbprint);
			handler.SslOptions.RemoteCertificateValidationCallback =
				(_, certificate, chain, sslPolicyErrors) =>
					validator.IsValid(certificate as X509Certificate2, chain, sslPolicyErrors);
		}

		return new HttpMessageInvoker(handler, disposeHandler: true);
	}
}
