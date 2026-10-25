// File:    src/RdpAudit.Core/ThreatIntel/IThreatIntelligenceClient.cs
// Module:  RdpAudit.Core.ThreatIntel
// Purpose: Abstraction over a threat-intelligence reputation lookup provider (Backlog #5). The
//          abstraction lives in Core so unit tests can supply a fake without depending on the
//          Service host or HttpClient internals, mirroring the IAbuseIpDbClient / IMikroTikClient
//          pattern. Implementations MUST be fail-closed, MUST only send public IP literals, and
//          MUST never log provider credentials.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

namespace RdpAudit.Core.ThreatIntel;

/// <summary>Abstraction over a threat-intelligence reputation lookup provider.</summary>
public interface IThreatIntelligenceClient
{
	/// <summary>Performs a single reputation lookup for one public source IP.</summary>
	/// <param name="ip">Canonical, pre-validated IP literal. Callers MUST pass only public,
	/// non-whitelisted addresses (see <c>IpClassifier.IsPublicIp</c>); implementations never
	/// re-send private / loopback values on their own.</param>
	/// <param name="ct">Cancellation token. Honoured by the underlying HTTP call.</param>
	/// <returns>Classified lookup result. NEVER throws for HTTP / transport / parse failures -
	/// every failure path folds into <see cref="ThreatIntelLookupResult"/>.</returns>
	Task<ThreatIntelLookupResult> LookupAsync(string ip, CancellationToken ct);
}
