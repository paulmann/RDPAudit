/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 2.3.6
// File   : RestApiPlanBuildResult.cs
// Project: RdpAudit.Service (RdpAudit.Service.RestApi)
// Purpose: Carrier for the fail-closed REST API startup decision plus the resolved bearer token.
//          The token deliberately does NOT live on RestApiPlan (which can be logged and surfaced
//          in diagnostics); it is used exactly once to construct the ApiTokenResolver.
// Depends: none.
// Extends: none.

namespace RdpAudit.Service.RestApi;

/// <summary>Plan plus the resolved bearer token (never logged, never persisted).</summary>
public sealed record RestApiPlanBuildResult(RestApiPlan Plan, string? ResolvedToken)
{
	public bool HasToken => !string.IsNullOrEmpty(ResolvedToken);
}
