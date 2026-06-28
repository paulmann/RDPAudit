// File:    tests/RdpAudit.Service.Tests/EventCollectorWorkerSecurityAuthQueryTests.cs
// Module:  RdpAudit.Service.Tests
// Purpose: v1.2.0 invariant. The realtime Security watcher MUST always use the narrow canonical
//          auth XPath (4624/4625/4648/4768/4769/4771/4776/4825) and never fall back to a wildcard
//          or to a wide Security-catalog scan. The push-based EventLogWatcher cannot honour
//          ReverseDirection / MaxEvents, so a wide query stalls on real hosts with multi-GB
//          Security logs and reports Armed-but-zero-events forever. Pinning the narrow XPath
//          here makes any future regression that re-widens the watcher fail immediately.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using RdpAudit.Core.Events;
using RdpAudit.Service.Workers;
using Xunit;

namespace RdpAudit.Service.Tests;

public class EventCollectorWorkerSecurityAuthQueryTests
{
	[Fact]
	public void Security_WithEmptyGlobalFilter_UsesNarrowAuthXPath_NotWildcard()
	{
		(string xpath, IReadOnlyList<int> ids) = EventCollectorWorker.BuildWatcherQuery(
			EventCatalog.ChannelSecurity, Array.Empty<int>());

		Assert.DoesNotContain("System[*]", xpath, StringComparison.Ordinal);
		Assert.NotEqual("*", xpath);
		Assert.Contains("EventID=4625", xpath, StringComparison.Ordinal);
		Assert.Contains("EventID=4624", xpath, StringComparison.Ordinal);

		// Wider non-auth Security catalog ids — process creation, scheduled-task persistence,
		// object access — MUST NOT appear in the realtime Security watcher path; they are
		// reserved for the bounded backfill worker.
		Assert.DoesNotContain("EventID=4688", xpath, StringComparison.Ordinal);
		Assert.DoesNotContain("EventID=4698", xpath, StringComparison.Ordinal);
		Assert.DoesNotContain("EventID=4656", xpath, StringComparison.Ordinal);

		Assert.Equal(SecurityAuthQuery.AuthEventIds.OrderBy(x => x), ids.OrderBy(x => x));
	}

	[Fact]
	public void Security_WithGlobalFilterMissingAuthIds_StillUsesAuthXPath()
	{
		// Operator wrote EnabledEventIds = [4688] — Security process creation only. The catalog
		// filter intersection would otherwise give an empty id list and the prior implementation
		// emitted a wildcard XPath. v1.2.0 contract: Security must STILL use the canonical auth
		// set so the failure of audit policy / collector path can be diagnosed reliably.
		(string xpath, IReadOnlyList<int> ids) = EventCollectorWorker.BuildWatcherQuery(
			EventCatalog.ChannelSecurity, new[] { 4688 });

		Assert.Contains("EventID=4625", xpath, StringComparison.Ordinal);
		Assert.Contains("EventID=4624", xpath, StringComparison.Ordinal);
		Assert.NotEqual("*", xpath);
		Assert.Equal(SecurityAuthQuery.AuthEventIds.OrderBy(x => x), ids.OrderBy(x => x));
	}

	[Fact]
	public void NonSecurityChannel_WithEmptyFilter_UsesCatalogIds()
	{
		const string TsLsm = "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational";
		(string xpath, IReadOnlyList<int> ids) = EventCollectorWorker.BuildWatcherQuery(
			TsLsm, Array.Empty<int>());

		// TS-LSM has narrow session-lifecycle ids; we still cover them all in the watcher when no
		// global filter is set — the bookmark + retention story works fine for those small logs.
		Assert.Contains("EventID=21", xpath, StringComparison.Ordinal);
		Assert.NotEmpty(ids);
	}

	[Fact]
	public void Security_WithGlobalFilterIncludingSomeAuthIds_IntersectsWithCanonicalAuthSet()
	{
		// When the operator picks a sub-set of auth ids, the watcher honours that sub-set but
		// never widens beyond the canonical auth set.
		(string xpath, IReadOnlyList<int> ids) = EventCollectorWorker.BuildWatcherQuery(
			EventCatalog.ChannelSecurity, new[] { 4624, 4625 });

		Assert.Contains("EventID=4624", xpath, StringComparison.Ordinal);
		Assert.Contains("EventID=4625", xpath, StringComparison.Ordinal);
		Assert.DoesNotContain("EventID=4648", xpath, StringComparison.Ordinal);
		Assert.Equal(new[] { 4624, 4625 }.OrderBy(x => x), ids.OrderBy(x => x));
	}
}
