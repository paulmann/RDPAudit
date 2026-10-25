// File:    src/RdpAudit.Web/Proxy/WebUiProxyTransformer.cs
// Module:  RdpAudit.Web
// Purpose: YARP HTTP transformer that impersonates the backend credential for proxied /api/*
//          requests. The token was resolved and staged in HttpContext.Items by
//          BearerHeaderSettingMiddleware (which refuses to forward without one); this transformer
//          consumes it and injects Authorization: Bearer onto the outbound HttpRequestMessage.
//          The browser's own Authorization never travels to the backend: stripping it in the
//          middleware plus overwriting it here makes injection mandatory, never optional.
// Extends: Yarp.ReverseProxy.Forwarder.HttpTransformer
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System.Net.Http.Headers;
using Yarp.ReverseProxy.Forwarder;

namespace RdpAudit.Web.Proxy;

/// <summary>Injects the backend bearer token into outbound proxied requests.</summary>
internal sealed class WebUiProxyTransformer : HttpTransformer
{
	/// <inheritdoc />
	public override async ValueTask TransformRequestAsync(
		HttpContext httpContext,
		HttpRequestMessage proxyRequest,
		string destinationPrefix,
		CancellationToken cancellationToken)
	{
		await base.TransformRequestAsync(httpContext, proxyRequest, destinationPrefix, cancellationToken);

		if (httpContext.Items.TryGetValue(BearerHeaderSettingMiddleware.OutboundBearerTokenItemKey, out object? storedToken)
			&& storedToken is string token && token.Length > 0)
		{
			proxyRequest.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
		}
	}
}
