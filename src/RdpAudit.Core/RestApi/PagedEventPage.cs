/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 2.2.0
// File   : PagedEventPage.cs
// Project: RdpAudit.Core (RdpAudit.Core.RestApi)
// Purpose: Result model returned by IPagedEventReader for the /events endpoint: one bounded
//          page of serializable event rows plus paging metadata (offset/limit/total) and the
//          optional plan digest produced by SQLite EXPLAIN QUERY PLAN when the caller requests
//          it. Kept free of EF/DB types so REST and tests serialize it directly.

namespace RdpAudit.Core.RestApi;

public sealed class PagedEventPage
{
	public int Offset { get; init; }

	public int Limit { get; init; }

	public int Total { get; init; }

	public IReadOnlyList<PagedEventRow> Events { get; init; } = Array.Empty<PagedEventRow>();

	public string[] ExplainPlan { get; init; } = Array.Empty<string>();
}
