/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 2.3.6
// File   : RestApiSecurityHeadersMiddleware.cs
// Project: RdpAudit.Service (RdpAudit.Service.RestApi)
// Purpose: Adds hardening headers to both REST routes (and redirects bare HTTPS to HTTPS with
//          the headers attached) for the read-only API. Installed before the auth middleware so
//          error responses receive the same headers.
// Depends: Microsoft.AspNetCore.Http, Microsoft.Net.Http.Headers
// Extends: Add an Origin allow-list if a browser-based consumer is ever supported.

using Microsoft.AspNetCore.Http;
using Microsoft.Net.Http.Headers;

namespace RdpAudit.Service.RestApi;

/// <summary>Applies a fixed set of security headers to API responses.</summary>
public sealed class RestApiSecurityHeadersMiddleware
{
	public const string ApiPrefix = "/api";
	public const string OpenApiPrefix = "/openapi";

	private readonly RequestDelegate _next;

	public RestApiSecurityHeadersMiddleware(RequestDelegate next)
	{
		_next = next ?? throw new ArgumentNullException(nameof(next));
	}

	public async Task InvokeAsync(HttpContext context)
	{
		ArgumentNullException.ThrowIfNull(context);

		if (IsApiPath(context.Request.Path))
		{
			IHeaderDictionary headers = context.Response.Headers;
			headers.CacheControl = "no-store";
			headers.Pragma = "no-cache";
			headers[HeaderNames.XContentTypeOptions] = "nosniff";
			// The API is deliberately NOT embeddable and never framed by the Configurator or any
			// browser page, so denying framing does not break navigation.
			headers[HeaderNames.XFrameOptions] = "DENY";
		}

		await _next(context);
	}

	internal static bool IsApiPath(PathString path)
	{
		string value = path.Value ?? string.Empty;
		return value.StartsWith(ApiPrefix, StringComparison.OrdinalIgnoreCase)
			|| value.StartsWith(OpenApiPrefix, StringComparison.OrdinalIgnoreCase);
	}
}
