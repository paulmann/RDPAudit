// File:    src/RdpAudit.Web/Proxy/BearerHeaderSettingMiddleware.cs
// Module:  RdpAudit.Web
// Purpose: Fills the outbound Authorization header for proxied /api/* requests. Operates INSIDE
//          the proxy endpoint (map-level middleware), not as application middleware: it acquires
//          the shared token from the vault-backed provider, stores it in HttpContext.Items
//          (consumed by WebUiProxyTransformer), and strips any Authorization header the browser
//          might have sent. A provider failure short-circuits with a curated JSON problem (503)
//          so a request never reaches the backend without a working credential.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System.Net;
using System.Net.Http.Headers;
using System.Text.Json;
using RdpAudit.Core.Security;

namespace RdpAudit.Web.Proxy;

/// <summary>Resolves and stages the bearer token for a proxied request.</summary>
internal sealed class BearerHeaderSettingMiddleware
{
	/// <summary>HttpContext.Items key holding the plaintext bearer token for the outbound leg.</summary>
	internal const string OutboundBearerTokenItemKey = "RdpAudit.Web.OutboundBearerToken";

	private readonly RequestDelegate _next;
	private readonly IWebUiTokenProvider _tokenProvider;
	private readonly ILogger<BearerHeaderSettingMiddleware> _logger;

	public BearerHeaderSettingMiddleware(
		RequestDelegate next,
		IWebUiTokenProvider tokenProvider,
		ILogger<BearerHeaderSettingMiddleware> logger)
	{
		_next = next;
		_tokenProvider = tokenProvider;
		_logger = logger;
	}

	public async Task InvokeAsync(HttpContext context)
	{
		string token;
		try
		{
			token = await _tokenProvider.GetTokenAsync(context.RequestAborted);
		}
		catch (SecretProtectionException ex)
		{
			_logger.LogError(ex, "The web-UI proxy could not obtain the backend bearer token; refusing to forward the request.");
			await WriteProblemAsync(context, HttpStatusCode.ServiceUnavailable,
				"Web access is not configured yet: the shared bearer token could not be read.");
			return;
		}
		catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
		{
			_logger.LogError(ex, "The web-UI proxy could not read the bearer-token vault file; refusing to forward the request.");
			await WriteProblemAsync(context, HttpStatusCode.ServiceUnavailable,
				"Web access is not available: the bearer-token vault file could not be read.");
			return;
		}

		// The browser never supplies the backend credential. Whatever Authorization header the
		// client sent is dropped here; the outbound one is injected by WebUiProxyTransformer
		// from the item staged above.
		context.Request.Headers.Remove(Microsoft.Net.Http.Headers.HeaderNames.Authorization);
		context.Items[OutboundBearerTokenItemKey] = token;
		await _next(context);
	}

	private static async Task WriteProblemAsync(HttpContext context, HttpStatusCode status, string detail)
	{
		context.Response.StatusCode = (int)status;
		context.Response.ContentType = "application/problem+json";
		var problem = new Dictionary<string, object?>
		{
			["type"] = "about:blank",
			["title"] = "Service Unavailable",
			["status"] = (int)status,
			["detail"] = detail,
			["instance"] = context.Request.Path.Value,
		};
		await JsonSerializer.SerializeAsync(context.Response.Body, problem);
	}
}
