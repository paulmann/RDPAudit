// File:    tests/RdpAudit.Service.Tests/SecurityBackfillWorkerV12ContractTests.cs
// Module:  RdpAudit.Service.Tests
// Purpose: v1.2.0 invariants for the Security backfill path. The previous implementation issued
//          one giant OR-clause XPath covering the full v3 set and timed out on hosts with large
//          Security logs, leaving every poll in QueryFailed. The new path splits per-EventID
//          with ReverseDirection=true and a hard MaxRowsPerEventId ceiling so a per-id timeout
//          never starves the other ids. These tests pin the constants the runtime relies on and
//          the per-id XPath shape; the actual EventLogReader poll path is Windows-only and
//          exercised by manual QA on a real host.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using RdpAudit.Core.Events;
using RdpAudit.Service.Workers;
using Xunit;

namespace RdpAudit.Service.Tests;

public class SecurityBackfillWorkerV12ContractTests
{
	[Fact]
	public void BuildXPathSingleId_BoundsByTimeAndExactlyOneEventId()
	{
		DateTime since = new(2026, 5, 26, 12, 0, 0, DateTimeKind.Utc);
		string xpath = SecurityAuthQuery.BuildXPathSingleId(4625, since);

		Assert.Contains("EventID=4625", xpath, StringComparison.Ordinal);
		Assert.DoesNotContain("EventID=4624", xpath, StringComparison.Ordinal);
		Assert.DoesNotContain("EventID=4648", xpath, StringComparison.Ordinal);
		Assert.Contains("2026-05-26T12:00:00.000Z", xpath, StringComparison.Ordinal);
	}

	[Fact]
	public void PriorityAuthIds_AreTheCanonicalAuthSet()
	{
		// The priority auth set the per-tick poll reads first MUST match the canonical
		// SecurityAuthQuery.AuthEventIds — otherwise the live watcher (also bound to that set)
		// could be starved by tampering / privilege-management ids on a busy host.
		Assert.Equal(
			SecurityAuthQuery.AuthEventIds.OrderBy(x => x),
			SecurityBackfillWorker.PriorityAuthIds.OrderBy(x => x));
	}

	[Fact]
	public void MaxRowsPerEventId_HasASaneCeiling()
	{
		// Hard ceiling guards the live pipeline from a backlog flood — a tick must never read more
		// than ~10s of data per id. The two thresholds are tested for their relative ordering so a
		// future bump to LatestBackfill cannot accidentally fall below the regular cap.
		Assert.True(SecurityBackfillWorker.MaxRowsPerEventId > 0);
		Assert.True(SecurityBackfillWorker.MaxRowsPerEventId <= 1_000);
		Assert.True(SecurityBackfillWorker.LatestBackfillMaxRowsPerEventId >= SecurityBackfillWorker.MaxRowsPerEventId);
	}

	[Fact]
	public void PerRecordReadTimeout_IsBoundedSoOneIdCannotStallTheTick()
	{
		// 50ms per record × 200 records = 10s worst-case per id, then the tick advances to the
		// next id without blocking the others. Catching a regression that bumps this would mean
		// the priority auth ids could stall the secondary backfill ids on a slow host.
		Assert.True(SecurityBackfillWorker.PerRecordReadTimeout > TimeSpan.Zero);
		Assert.True(SecurityBackfillWorker.PerRecordReadTimeout <= TimeSpan.FromMilliseconds(500));
	}

	[Fact]
	public void BackfillEventIds_CoverFullV3SecuritySet()
	{
		// Compatibility with the existing v3 contract test — guard that a future regression that
		// silently narrows the backfill id set fails immediately.
		int[] expected =
		{
			4624, 4625, 4634, 4647, 4648, 4672,
			4719, 4720, 4724, 4732, 4740,
			4768, 4769, 4771, 4776,
			4778, 4779,
			4825,
			1102,
		};

		Assert.Equal(expected.OrderBy(x => x), SecurityBackfillWorker.BackfillEventIds.OrderBy(x => x));
	}
}
