// File:    src/RdpAudit.Web/Proxy/IWebUiTokenProvider.cs
// Module:  RdpAudit.Web
// Purpose: Abstraction over the source of the shared backend bearer token. The proxy injects
//          whatever this provider returns into the outbound Authorization header and never
//          exposes it to the browser; a provider failure becomes an explicit 503 problem
//          response instead of a forwarded request without credentials.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

namespace RdpAudit.Web.Proxy;

/// <summary>Supplies the backend bearer token for proxied /api/* requests.</summary>
public interface IWebUiTokenProvider
{
	/// <summary>Returns the current backend bearer token (plaintext, used once for the outbound request).</summary>
	/// <exception cref="RdpAudit.Core.Security.SecretProtectionException">When the token cannot be obtained.</exception>
	Task<string> GetTokenAsync(CancellationToken cancellationToken);
}
