/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 2.3.6
// File   : RestApiBearerAuthMiddleware.cs
// Project: RdpAudit.Service (RdpAudit.Service.RestApi)
// Purpose: Enforces the static bearer token on every routed API endpoint except /healthz.
//          Missing and invalid credentials produce the same observable result (401 + a generic
//          WWW-Authenticate challenge) without revealing whether a token exists.
// Depends: Microsoft.AspNetCore.Http, Microsoft.Net.Http.Headers
// Extends: Add per-endpoint scopes when token kinds/roles are introduced.

using System.Globalization;
using Microsoft.AspNetCore.Http;
using Microsoft.Net.Http.Headers;

namespace RdpAudit.Service.RestApi;

/// <summary>
/// Gatekeeper for the read-only REST API. Installed after the security-header and rate-limit
/// middlewares, so an unauthenticated caller still consumes its request budget (the limiter is
/// the outer defence; auth is the inner one).
/// </summary>
public sealed class RestApiBearerAuthMiddleware
{
	/// <summary>Public health endpoint exempt from the bearer requirement.</summary>
	public const string HealthPath = "/healthz";

	private const string DefaultChallenge = "Bearer realm=\"rdpaudit\"";

	private readonly RequestDelegate _next;
	private readonly ApiTokenResolver _resolver;

	public RestApiBearerAuthMiddleware(RequestDelegate next, ApiTokenResolver resolver)
	{
		_next = next ?? throw new ArgumentNullException(nameof(next));
		_resolver = resolver ?? throw new ArgumentNullException(nameof(resolver));
	}

	public async Task InvokeAsync(HttpContext context)
	{
		ArgumentNullException.ThrowIfNull(context);

		if (IsHealthPath(context.Request.Path))
		{
			await _next(context);
			return;
		}

		string? presentedToken = ApiTokenResolver.ExtractBearerToken(context.Request.Headers);
		if (presentedToken is not null && _resolver.IsValid(presentedToken))
		{
			await _next(context);
			return;
		}

		context.Response.StatusCode = StatusCodes.Status401Unauthorized;
		context.Response.Headers[HeaderNames.WWWAuthenticate] = DefaultChallenge;
		await RestApiProblem.WriteAsync(
			context,
			StatusCodes.Status401Unauthorized,
			"Unauthorized",
			"Bearer token required.").ConfigureAwait(false);
	}

	internal static bool IsHealthPath(PathString path)
		=> string.Equals(path.Value, HealthPath, StringComparison.OrdinalIgnoreCase);
}
