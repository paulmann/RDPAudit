// File:    src/RdpAudit.Web/Proxy/Tls/ICertificateValidator.cs
// Module:  RdpAudit.Web
// Purpose: Abstraction for validating the backend TLS certificate during the outbound leg.
//          The web-UI proxy trusts the system validation by default; implementing types may
//          add certificate pinning without bypassing that baseline.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System.Net.Security;
using System.Security.Cryptography.X509Certificates;

namespace RdpAudit.Web.Proxy.Tls;

/// <summary>Decides whether a backend TSL certificate is acceptable.</summary>
public interface ICertificateValidator
{
	/// <summary>Returns true when the presented certificate should be trusted.</summary>
	bool IsValid(X509Certificate2? certificate, X509Chain? chain, SslPolicyErrors sslPolicyErrors);
}
