// File:    tests/RdpAudit.Service.Tests/SecurityBackfillPerIdMetricsTests.cs
// Module:  RdpAudit.Service.Tests
// Purpose: v1.2.2 — pin the per-id Security backfill diagnostic surface on ServiceMetrics:
//          per-id snapshots are recorded and recallable, the clear-stale helper drops every
//          Security::Backfill::<id> channel-status entry and every per-id snapshot in one
//          hop, and per-id NoEvents must never set LastSecurityChannelError (a workstation
//          without DC events must NOT paint the top-level Security channel as broken).
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using RdpAudit.Service.Workers;
using Xunit;

namespace RdpAudit.Service.Tests;

public class SecurityBackfillPerIdMetricsTests
{
	[Fact]
	public void RecordSecurityBackfillPerId_RoundTripsThroughSnapshot()
	{
		ServiceMetrics m = new();
		DateTime utc = DateTime.UtcNow;
		m.RecordSecurityBackfillPerId(new SecurityBackfillPerIdSnapshot(
			EventId: 4768,
			LastRunUtc: utc,
			ElapsedMs: 7,
			RecordsRead: 0,
			Forwarded: 0,
			Duplicate: 0,
			Status: "NoEvents",
			LastExceptionType: "EventLogException",
			LastExceptionMessage: "No events were found that match the specified selection criteria."));

		IReadOnlyDictionary<int, SecurityBackfillPerIdSnapshot> snapshot = m.SnapshotSecurityBackfillPerId();
		Assert.True(snapshot.ContainsKey(4768));
		Assert.Equal("NoEvents", snapshot[4768].Status);
		Assert.Equal(7, snapshot[4768].ElapsedMs);
	}

	[Fact]
	public void ClearSecurityBackfillPerIdStatuses_DropsPerIdSnapshots_AndPerIdChannelStatuses()
	{
		ServiceMetrics m = new();
		m.RecordSecurityBackfillPerId(new SecurityBackfillPerIdSnapshot(
			EventId: 4624, LastRunUtc: DateTime.UtcNow, ElapsedMs: 5,
			RecordsRead: 12, Forwarded: 12, Duplicate: 0,
			Status: "OkForwarded", LastExceptionType: null, LastExceptionMessage: null));
		m.SetChannelStatus("Security::Backfill::4624", "OkForwarded");
		m.SetChannelStatus("Security::Backfill::4768", "NoEvents");
		m.SetChannelStatus("Security::Backfill", "Forwarded:12, Duplicate:0, NoEvents:1, TimeoutSkipped:0, Failed:0");
		m.SetChannelStatus("Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational", "Armed");

		m.ClearSecurityBackfillPerIdStatuses();

		Assert.Empty(m.SnapshotSecurityBackfillPerId());
		Dictionary<string, string> channels = m.SnapshotChannels();
		Assert.DoesNotContain("Security::Backfill::4624", channels.Keys);
		Assert.DoesNotContain("Security::Backfill::4768", channels.Keys);
		// Aggregate-level row and unrelated channels survive — only per-id entries are wiped.
		Assert.Contains("Security::Backfill", channels.Keys);
		Assert.Contains(
			"Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational",
			channels.Keys);
	}

	[Fact]
	public void PerIdNoEvents_DoesNotSetLastSecurityChannelError()
	{
		// A per-id NoEvents outcome — the canonical case on a workstation without DC
		// events — must NEVER paint the top-level "Last Security channel error" banner.
		// This is the headline v1.2.2 contract.
		ServiceMetrics m = new();
		m.RecordSecurityBackfillPerId(new SecurityBackfillPerIdSnapshot(
			EventId: 4768, LastRunUtc: DateTime.UtcNow, ElapsedMs: 2,
			RecordsRead: 0, Forwarded: 0, Duplicate: 0,
			Status: "NoEvents", LastExceptionType: "EventLogException",
			LastExceptionMessage: "No events were found that match the specified selection criteria."));
		Assert.Null(m.LastSecurityChannelError);
	}
}
