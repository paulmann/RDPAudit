// File:    src/RdpAudit.Web/Proxy/LoopbackHostFilterMiddleware.cs
// Module:  RdpAudit.Web
// Purpose: First-line DNS-rebinding defense of the web-UI proxy. The IIS site is bound to the
//          loopback address only, so the ONLY legitimate Host values are loopback names. A
//          browser tricked into visiting an attacker domain that resolves to 127.0.0.1 sends
//          that domain in the Host header; without this filter the proxy would honor the request
//          and inject the vault bearer token server-side, effectively letting attacker-controlled
//          JavaScript read service data through the loopback. The filter rejects any other Host
//          with 400 BEFORE static files, header injection and proxying run, so a foreign origin
//          can never reach the token-injecting /api pipeline. The allow-list is intentionally
//          hardcoded (no configuration surface): the plan's security model makes loopback-only
//          hosting a fixed property of the product, not an operator choice.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using Microsoft.AspNetCore.Http;

namespace RdpAudit.Web.Proxy;

/// <summary>Rejects requests whose Host header is not a loopback name. Runs before every other
/// middleware so no response (static file, health, proxied API) is produced for a foreign host.</summary>
internal sealed class LoopbackHostFilterMiddleware
{
	private static readonly HashSet<string> AllowedHosts = new(StringComparer.OrdinalIgnoreCase)
	{
		"127.0.0.1",
		"localhost",
		"::1",
	};

	private readonly RequestDelegate _next;

	public LoopbackHostFilterMiddleware(RequestDelegate next)
	{
		_next = next;
	}

	/// <summary>Answers 400 for a foreign / malformed Host header and continues for loopback hosts.</summary>
	public async Task InvokeAsync(HttpContext context)
	{
		string host = context.Request.Host.Host;
		string normalized = host.Trim();
		// HostString keeps the square brackets around an IPv6 literal ("[::1]"); the
		// allow-list stores the bare address. A trailing dot ("localhost.") is an
		// equally valid absolute form of the same host name and is stripped as well.
		if (normalized.Length >= 2 && normalized[0] == '[' && normalized[^1] == ']')
		{
			normalized = normalized[1..^1];
		}

		normalized = normalized.TrimEnd('.');
		if (normalized.Length == 0 || !AllowedHosts.Contains(normalized))
		{
			context.Response.StatusCode = StatusCodes.Status400BadRequest;
			await context.Response.WriteAsync("RdpAudit WebUI: unexpected host header.");
			return;
		}

		await _next(context);
	}
}

/// <summary>Registers the loopback host filter at the start of the pipeline.</summary>
internal static class LoopbackHostFilterExtensions
{
	/// <summary>Adds the DNS-rebinding host filter to the pipeline.</summary>
	public static IApplicationBuilder UseLoopbackHostFilter(this IApplicationBuilder builder)
		=> builder.UseMiddleware<LoopbackHostFilterMiddleware>();
}
