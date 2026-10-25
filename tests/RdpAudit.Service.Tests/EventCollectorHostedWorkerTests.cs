/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 2.0.0
// File   : EventCollectorHostedWorkerTests.cs
// Project: RdpAudit.Service.Tests (RdpAudit.Service.Tests)
// Purpose: Contract tests for the thin BackgroundService shim EventCollectorHostedWorker. Pins
//          the XPath-building surface (mirrors EventCollectorWorkerSecurityAuthQueryTests), the
//          SkippedUnavailable formatter, and the null-guard behavior of the constructor.
//          Runtime lifecycle tests for the shim itself run on Windows only (they exercise the
//          host's arm loop, which needs EventLog access) — non-Windows CI still verifies the
//          static helpers.
// Depends: xUnit, EventCollectorHostedWorker, EventCatalog, SecurityAuthQuery, EventCollectorHost
// Extends: Add pinning tests here when the Security-auth XPath contract or the SkippedUnavailable
//          formatter change.

using RdpAudit.Core.Events;
using RdpAudit.Service.Workers;
using Xunit;

namespace RdpAudit.Service.Tests;

public sealed class EventCollectorHostedWorkerTests
{
	// ── XPath contract ───────────────────────────────────────────────────────────

	[Fact]
	public void BuildWatcherQuery_Security_EmptyFilter_UsesNarrowAuthXPath()
	{
		(string xpath, IReadOnlyList<int> ids) = EventCollectorHostedWorker.BuildWatcherQuery(
			EventCatalog.ChannelSecurity, Array.Empty<int>());

		Assert.NotEqual("*", xpath);
		Assert.Contains("EventID=4625", xpath, StringComparison.Ordinal);
		Assert.Contains("EventID=4624", xpath, StringComparison.Ordinal);
		Assert.DoesNotContain("EventID=4688", xpath, StringComparison.Ordinal);
		Assert.DoesNotContain("EventID=4698", xpath, StringComparison.Ordinal);
		Assert.Equal(
			SecurityAuthQuery.AuthEventIds.OrderBy(x => x),
			ids.OrderBy(x => x));
	}

	[Fact]
	public void BuildWatcherQuery_Security_FilterMissingAuthIds_StillUsesAuthXPath()
	{
		(string xpath, IReadOnlyList<int> ids) = EventCollectorHostedWorker.BuildWatcherQuery(
			EventCatalog.ChannelSecurity, new[] { 4688 });

		Assert.NotEqual("*", xpath);
		Assert.Contains("EventID=4625", xpath, StringComparison.Ordinal);
		Assert.NotEmpty(ids);
		Assert.All(ids, id => Assert.Contains(id, SecurityAuthQuery.AuthEventIds));
	}

	[Fact]
	public void BuildWatcherQuery_Security_FilterIntersectsAuthIds_UsesIntersection()
	{
		(string xpath, IReadOnlyList<int> ids) = EventCollectorHostedWorker.BuildWatcherQuery(
			EventCatalog.ChannelSecurity, new[] { 4625, 4624, 4688 });

		Assert.Contains("EventID=4625", xpath, StringComparison.Ordinal);
		Assert.Contains("EventID=4624", xpath, StringComparison.Ordinal);
		Assert.DoesNotContain("EventID=4688", xpath, StringComparison.Ordinal);
		Assert.Equal(2, ids.Count);
	}

	[Fact]
	public void BuildWatcherQuery_NonSecurity_EmptyFilter_UsesChannelCatalog()
	{
		(string xpath, IReadOnlyList<int> ids) = EventCollectorHostedWorker.BuildWatcherQuery(
			EventCatalog.ChannelTsLocal, Array.Empty<int>());

		Assert.NotEqual("*", xpath);
		Assert.NotEmpty(ids);
		Assert.StartsWith("*[System[(", xpath, StringComparison.Ordinal);
	}

	[Fact]
	public void BuildWatcherQuery_NonSecurity_FilterEmpties_FallsBackToWildcard()
	{
		// A non-Security channel with a filter that excludes all catalog IDs should collapse
		// to the wildcard XPath so the collector still sees something.
		(string xpath, IReadOnlyList<int> ids) = EventCollectorHostedWorker.BuildWatcherQuery(
			EventCatalog.ChannelSystem, new[] { 999_999 });

		Assert.Equal("*", xpath);
		Assert.Empty(ids);
	}

	[Fact]
	public void BuildWatcherQuery_NullChannel_Throws()
	{
		Assert.Throws<ArgumentNullException>(() =>
			EventCollectorHostedWorker.BuildWatcherQuery(null!, Array.Empty<int>()));
	}

	[Fact]
	public void BuildWatcherQuery_NullFilter_Throws()
	{
		Assert.Throws<ArgumentNullException>(() =>
			EventCollectorHostedWorker.BuildWatcherQuery(EventCatalog.ChannelSecurity, null!));
	}

	// ── SkippedUnavailable formatter ─────────────────────────────────────────────

	[Fact]
	public void BuildSkippedUnavailableStatus_EmptyReason_ReturnsBareToken()
	{
		Assert.Equal("SkippedUnavailable", EventCollectorHostedWorker.BuildSkippedUnavailableStatus(""));
	}

	[Fact]
	public void BuildSkippedUnavailableStatus_NullReason_ReturnsBareToken()
	{
		Assert.Equal("SkippedUnavailable", EventCollectorHostedWorker.BuildSkippedUnavailableStatus(null!));
	}

	[Fact]
	public void BuildSkippedUnavailableStatus_ShortReason_IsPreserved()
	{
		string result = EventCollectorHostedWorker.BuildSkippedUnavailableStatus("ChannelNotEnabled");
		Assert.Equal("SkippedUnavailable: ChannelNotEnabled", result);
	}

	[Fact]
	public void BuildSkippedUnavailableStatus_OverlongReason_IsTruncated()
	{
		string longReason = new('x', 300);
		string result = EventCollectorHostedWorker.BuildSkippedUnavailableStatus(longReason);

		Assert.StartsWith("SkippedUnavailable: ", result, StringComparison.Ordinal);
		Assert.EndsWith("...", result, StringComparison.Ordinal);
		Assert.True(result.Length <= "SkippedUnavailable: ".Length + EventCollectorHostedWorker.SkippedUnavailableReasonMaxLength + 3);
	}
}
