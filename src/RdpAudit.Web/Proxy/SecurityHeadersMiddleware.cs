// File:    src/RdpAudit.Web/Proxy/SecurityHeadersMiddleware.cs
// Module:  RdpAudit.Web
// Purpose: Adds the defense-in-depth response headers of the web-UI proxy. The IIS layer already
//          applies its own hardening, but the proxy emits the baseline itself so the protections
//          hold regardless of the hosting configuration: X-Content-Type-Options, Referrer-Policy,
//          X-Frame-Options DENY and a Content-Security-Policy that permits only same-origin
//          resources (with a deliberate, explicit opt-in for inline script/style development).
//          HSTS is intentionally NOT set here: the IIS/HNS binding layer owns TLS policy.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using RdpAudit.Web.Config;

namespace RdpAudit.Web.Proxy;

/// <summary>Emits the web-UI security headers on every response.</summary>
internal sealed class SecurityHeadersMiddleware
{
	private const string StrictContentSecurityPolicy =
		"default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
		+ "connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'";

	private const string InlineFriendlyContentSecurityPolicy =
		"default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; "
		+ "img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'";

	private readonly RequestDelegate _next;
	private readonly bool _allowInline;

	public SecurityHeadersMiddleware(RequestDelegate next, bool allowInline)
	{
		_next = next;
		_allowInline = allowInline;
	}

	/// <summary>Adds the security headers and continues the pipeline.</summary>
	public async Task InvokeAsync(HttpContext context)
	{
		IHeaderDictionary headers = context.Response.Headers;
		headers.SetDefaultHeader("X-Content-Type-Options", "nosniff");
		headers.SetDefaultHeader("Referrer-Policy", "no-referrer");
		headers.SetDefaultHeader("X-Frame-Options", "DENY");
		headers.SetDefaultHeader(
			"Content-Security-Policy",
			_allowInline ? InlineFriendlyContentSecurityPolicy : StrictContentSecurityPolicy);
		await _next(context);
	}
}

/// <summary>Extension methods for registering the security-header middleware.</summary>
internal static class SecurityHeadersMiddlewareExtensions
{
	/// <summary>Adds the web-UI security headers to the pipeline.</summary>
	public static IApplicationBuilder UseSecurityHeaders(this IApplicationBuilder builder)
	{
		// Resolve the setting now: the middleware itself stays allocation-free per request.
		WebUiProxyOptions? options = builder.ApplicationServices.GetService<WebUiProxyOptions>();
		return builder.UseMiddleware<SecurityHeadersMiddleware>(options?.AllowInlineScripts ?? false);
	}
}

/// <summary>Small header-writing helper: sets a response header only when the host has not set it yet.</summary>
internal static class HeaderDictionaryExtensions
{
	/// <summary>Sets <paramref name="value"/> for <paramref name="name"/> unless a value is already present.</summary>
	public static void SetDefaultHeader(this IHeaderDictionary headers, string name, string value)
	{
		if (!headers.ContainsKey(name))
		{
			headers[name] = value;
		}
	}
}
