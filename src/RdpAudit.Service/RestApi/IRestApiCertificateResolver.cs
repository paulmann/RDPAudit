/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 2.3.6
// File   : IRestApiCertificateResolver.cs
// Project: RdpAudit.Service (RdpAudit.Service.RestApi)
// Purpose: Abstraction over server-certificate resolution for the read-only REST API, mirroring
//          the existing nullable-resolution style of the Firewall scanner contracts.
// Depends: System.Security.Cryptography.X509Certificates
// Extends: none.

namespace RdpAudit.Service.RestApi;

/// <summary>Resolves the REST API server certificate from the configured thumbprint/subject.</summary>
public interface IRestApiCertificateResolver
{
	/// <summary>Returns the resolved certificate or a structured reason when none matched.</summary>
	RestApiCertificateResolution Resolve(string? thumbprint, string? subject);
}
