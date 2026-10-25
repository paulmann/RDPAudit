/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 2.3.6
// File   : ApiTokenResolver.cs
// Project: RdpAudit.Service (RdpAudit.Service.RestApi)
// Purpose: Reads the bearer token from the Authorization header and validates it against the
//          configured API token using a constant-time comparison. The expected token itself is
//          resolved (unprotected from the DPAPI envelope) by RestApiPlanBuilder, so the resolver
//          never touches configuration or secret protection directly.
// Depends: Microsoft.AspNetCore.Http, Microsoft.Extensions.Primitives, Microsoft.Net.Http.Headers
// Extends: Add scoped/per-endpoint tokens if the API later grows tenants or roles.

using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Primitives;
using Microsoft.Net.Http.Headers;

namespace RdpAudit.Service.RestApi;

/// <summary>
/// Validates bearer credentials for the read-only REST API. The expected token is held as a
/// UTF-8 byte array and compared with
/// <see cref="CryptographicOperations.FixedTimeEquals(ReadOnlySpan{byte}, ReadOnlySpan{byte})"/>
/// so the comparison does not leak token prefixes via timing.
/// </summary>
public sealed class ApiTokenResolver
{
	private readonly byte[] _expectedTokenUtf8;

	/// <summary>Creates a validator for the supplied expected token.</summary>
	/// <param name="expectedToken">The non-empty expected bearer token. Never logged.</param>
	public ApiTokenResolver(string expectedToken)
	{
		if (string.IsNullOrEmpty(expectedToken))
		{
			throw new ArgumentException(
				"The REST API bearer token must not be null or empty; the fail-closed plan builder rejects empty tokens before this point.",
				nameof(expectedToken));
		}

		_expectedTokenUtf8 = Encoding.UTF8.GetBytes(expectedToken);
	}

	/// <summary>
	/// Extracts the bearer token from an <c>Authorization: Bearer &lt;token&gt;</c> header.
	/// Returns null for missing headers, non-Bearer schemes, multiple header values, or a blank
	/// token so the caller can distinguish "absent" from "invalid".
	/// </summary>
	public static string? ExtractBearerToken(IHeaderDictionary headers)
	{
		ArgumentNullException.ThrowIfNull(headers);

		if (!headers.TryGetValue(HeaderNames.Authorization, out StringValues values) || values.Count != 1)
		{
			return null;
		}

		string? headerValue = values[0];
		if (string.IsNullOrWhiteSpace(headerValue))
		{
			return null;
		}

		int separator = headerValue.IndexOf(' ');
		if (separator <= 0
			|| !string.Equals(headerValue[..separator], "Bearer", StringComparison.OrdinalIgnoreCase))
		{
			return null;
		}

		string token = headerValue[(separator + 1)..].Trim();
		return token.Length == 0 ? null : token;
	}

	/// <summary>
	/// Returns true when <paramref name="presentedToken"/> equals the expected token. Null,
	/// empty, and differently sized values are rejected without echoing any secret.
	/// </summary>
	public bool IsValid(string? presentedToken)
	{
		if (string.IsNullOrEmpty(presentedToken))
		{
			return false;
		}

		byte[] presentedUtf8 = Encoding.UTF8.GetBytes(presentedToken);
		return presentedUtf8.Length == _expectedTokenUtf8.Length
			&& CryptographicOperations.FixedTimeEquals(presentedUtf8, _expectedTokenUtf8);
	}
}
