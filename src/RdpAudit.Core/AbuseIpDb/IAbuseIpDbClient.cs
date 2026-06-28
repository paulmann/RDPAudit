// File:    src/RdpAudit.Core/AbuseIpDb/IAbuseIpDbClient.cs
// Module:  RdpAudit.Core.AbuseIpDb
// Purpose: Abstraction over the AbuseIPDB v2 HTTP API used by the Stage 8 reporting worker. The
//          abstraction lives in Core so unit tests can supply a fake without depending on the
//          Service host or HttpClient internals.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

namespace RdpAudit.Core.AbuseIpDb;

/// <summary>Abstraction over the AbuseIPDB v2 HTTP API used by the Stage 8 reporting worker.</summary>
public interface IAbuseIpDbClient
{
	/// <summary>Submits a single report to the AbuseIPDB /api/v2/report endpoint.</summary>
	/// <param name="request">Report payload (already sanitised).</param>
	/// <param name="ct">Cancellation token. Honoured by the underlying HTTP call.</param>
	Task<AbuseIpDbReportResult> ReportAsync(AbuseIpDbReportRequest request, CancellationToken ct);

	/// <summary>Performs a safe read-only key-validation probe. Does NOT submit a fake report.</summary>
	/// <param name="ct">Cancellation token. Honoured by the underlying HTTP call.</param>
	Task<AbuseIpDbReportResult> ValidateKeyAsync(CancellationToken ct);
}
