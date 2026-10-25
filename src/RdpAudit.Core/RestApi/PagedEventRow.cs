/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 2.2.0
// File   : PagedEventRow.cs
// Project: RdpAudit.Core (RdpAudit.Core.RestApi)
// Purpose: Serializable projection of one RawEvent row for the /events endpoint.
//          Deliberately excludes navigation properties and unknown heavy fields.

namespace RdpAudit.Core.RestApi;

public sealed class PagedEventRow
{
	public long Id { get; init; }

	public int EventId { get; init; }

	public string Channel { get; init; } = string.Empty;

	public DateTime TimeUtc { get; init; }

	public long IngestionSequence { get; init; }

	public int EventLayer { get; init; }

	public string? SourceIp { get; init; }

	public bool SourceIpDerived { get; init; }

	public bool SourceIpUnresolved { get; init; }

	public string? UserName { get; init; }

	public string? Domain { get; init; }

	public int? SessionId { get; init; }

	public int? LogonType { get; init; }

	public string? LogonId { get; init; }

	public string? AuthPackage { get; init; }

	public string? Status { get; init; }

	public string? ProcessName { get; init; }

	public string? CommandLine { get; init; }

	public string? ObjectName { get; init; }

	public string? AccessMask { get; init; }

	public string? Details { get; init; }
}
