/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 2.0.1
// File   : BookmarkCheckpointLedgerTests.cs
// Project: RdpAudit.Service.Tests (RdpAudit.Service.Tests)
// Purpose: Contract tests for BookmarkCheckpointLedger: the correlation between a captured
//          bookmark and the ingestion sequence of the event it covers. Pins the collect/prune
//          watermark semantics and the ForgetChannel reset path that stops a stale pre-reset
//          bookmark from being re-persisted by the next unified commit.
// Depends: BookmarkCheckpointLedger (RdpAudit.Service.Infrastructure), xUnit
// Extends: Add a fact here whenever a new durability sink joins the unified commit and the
//          watermark advancement semantics change.

using RdpAudit.Service.Infrastructure;
using Xunit;

namespace RdpAudit.Service.Tests;

public sealed class BookmarkCheckpointLedgerTests
{
	[Fact]
	public void CommittedWatermark_StartsAtZero()
	{
		BookmarkCheckpointLedger ledger = new();
		Assert.Equal(0, ledger.CommittedWatermark);
	}

	[Fact]
	public void Record_CollectCommittable_ReturnsNewestQualifyingBookmarkPerChannel()
	{
		BookmarkCheckpointLedger ledger = new();
		ledger.Record("Security", 1, "<bm-1/>");
		ledger.Record("Security", 2, "<bm-2/>");
		ledger.Record("Security", 3, "<bm-3/>");

		Dictionary<string, string> destination = new(StringComparer.OrdinalIgnoreCase);
		int count = ledger.CollectCommittable(3, destination);

		Assert.Equal(1, count);
		Assert.Equal("<bm-3/>", destination["Security"]);
	}

	[Fact]
	public void CollectCommittable_OnlyReturnsBookmarksAtOrBelowSequence()
	{
		BookmarkCheckpointLedger ledger = new();
		ledger.Record("Security", 1, "<bm-1/>");
		ledger.Record("Security", 5, "<bm-5/>");

		Dictionary<string, string> destination = new(StringComparer.OrdinalIgnoreCase);
		int count = ledger.CollectCommittable(3, destination);

		Assert.Equal(1, count);
		Assert.Equal("<bm-1/>", destination["Security"]);
	}

	[Fact]
	public void CollectCommittable_ZeroSequence_ReturnsZero()
	{
		BookmarkCheckpointLedger ledger = new();
		ledger.Record("Security", 1, "<bm-1/>");

		Dictionary<string, string> destination = new(StringComparer.OrdinalIgnoreCase);
		int count = ledger.CollectCommittable(0, destination);

		Assert.Equal(0, count);
		Assert.Empty(destination);
	}

	[Fact]
	public void Prune_AdvancesWatermark_AndKeepsLastCommittedCheckpoint()
	{
		BookmarkCheckpointLedger ledger = new();
		ledger.Record("Security", 1, "<bm-1/>");
		ledger.Record("Security", 2, "<bm-2/>");
		ledger.Record("Security", 3, "<bm-3/>");

		Dictionary<string, string> destination = new(StringComparer.OrdinalIgnoreCase);
		ledger.CollectCommittable(2, destination);
		ledger.Prune(2);

		Assert.Equal(2, ledger.CommittedWatermark);

		// The last committed checkpoint (sequence 2) is retained so an idle channel can still
		// be flushed on shutdown. Collect for the same watermark must still return it.
		Dictionary<string, string> durable = new(StringComparer.OrdinalIgnoreCase);
		int count = ledger.CollectDurable(durable);
		Assert.Equal(1, count);
		Assert.Equal("<bm-2/>", durable["Security"]);
	}

	[Fact]
	public void ForgetChannel_RemovesPendingCheckpoint_SoStaleBookmarkIsNotRepersisted()
	{
		BookmarkCheckpointLedger ledger = new();
		ledger.Record("Security", 1, "<stale-before-reset/>");

		// A bookmark reset must purge the pending checkpoint; otherwise the next unified
		// commit would re-persist the stale pre-reset position.
		ledger.ForgetChannel("Security");

		Dictionary<string, string> destination = new(StringComparer.OrdinalIgnoreCase);
		int count = ledger.CollectCommittable(10, destination);

		Assert.Equal(0, count);
		Assert.False(destination.ContainsKey("Security"));
	}

	[Fact]
	public void ForgetChannel_UnknownChannel_IsIdempotent()
	{
		BookmarkCheckpointLedger ledger = new();
		ledger.ForgetChannel("Missing");
		Assert.Equal(0, ledger.CommittedWatermark);
	}

	[Fact]
	public void ForgetChannel_NullOrEmpty_Throws()
	{
		BookmarkCheckpointLedger ledger = new();
		Assert.Throws<ArgumentNullException>(() => ledger.ForgetChannel(null!));
		Assert.Throws<ArgumentException>(() => ledger.ForgetChannel("  "));
	}

	[Fact]
	public void Record_CollapsesOutOfOrderOrDuplicateOntoTail()
	{
		BookmarkCheckpointLedger ledger = new();
		ledger.Record("Security", 5, "<bm-5/>");
		ledger.Record("Security", 4, "<bm-4-out-of-order/>");

		Dictionary<string, string> destination = new(StringComparer.OrdinalIgnoreCase);
		ledger.CollectCommittable(5, destination);

		// The out-of-order arrival collapses onto the tail (sequence 5), preserving the
		// newest bookmark rather than appending a monotonicity violation.
		Assert.Equal("<bm-4-out-of-order/>", destination["Security"]);
	}
}
