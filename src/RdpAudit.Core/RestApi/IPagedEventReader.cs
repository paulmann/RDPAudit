/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 2.2.0
// File   : IPagedEventReader.cs
// Project: RdpAudit.Core (RdpAudit.Core.RestApi)
// Purpose: Abstraction over the bounded, read-only page query consumed by the REST /events
//          endpoint. Lives in Core so the Service implementation can be swapped with a fake in
//          unit tests, mirroring the IAbuseIpDbClient / IMikroTikClient pattern.

namespace RdpAudit.Core.RestApi;

public interface IPagedEventReader
{
	Task<PagedEventPage> ReadPageAsync(PagedEventsQuery query, CancellationToken cancellationToken);
}
