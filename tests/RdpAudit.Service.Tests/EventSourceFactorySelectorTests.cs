// File:    tests/RdpAudit.Service.Tests/EventSourceFactorySelectorTests.cs
// Module:  RdpAudit.Service.Tests
// Purpose: Exercises the pure IngestionMode -> transport selection matrix used by Program.cs
//          when it registers IEventSourceFactory. Covers the three declared IngestionMode
//          values (EventLog / Etw / Auto), the out-of-range defensive branch, and both probe
//          outcomes for the Etw and Auto branches. Runs on any OS (no ETW native calls).
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using RdpAudit.Core.Config;
using RdpAudit.Service.EventSources;
using Xunit;

namespace RdpAudit.Service.Tests;

public class EventSourceFactorySelectorTests
{
	private static Func<(bool Ok, string? Reason)> ProbeOk() => () => (true, null);
	private static Func<(bool Ok, string? Reason)> ProbeDecline(string reason) => () => (false, reason);

	[Fact]
	public void EventLog_AlwaysReturnsEventLog_WithoutProbing()
	{
		int probeCalls = 0;
		Func<(bool Ok, string? Reason)> probe = () => { probeCalls++; return (true, null); };

		var selection = EventSourceFactorySelector.Select(IngestionMode.EventLog, probe);

		Assert.Equal(IngestionMode.EventLog, selection.ChosenTransport);
		Assert.Equal(IngestionMode.EventLog, selection.RequestedMode);
		Assert.Null(selection.FallbackReason);
		Assert.Equal(0, probeCalls);
	}

	[Fact]
	public void Etw_HonoursRequest_WhenProbeSucceeds()
	{
		var selection = EventSourceFactorySelector.Select(IngestionMode.Etw, ProbeOk());

		Assert.Equal(IngestionMode.Etw, selection.ChosenTransport);
		Assert.Equal(IngestionMode.Etw, selection.RequestedMode);
		Assert.Null(selection.FallbackReason);
	}

	[Fact]
	public void Etw_KeepsChosenTransportAsEtw_WhenProbeDeclines_ForFailFastContract()
	{
		var selection = EventSourceFactorySelector.Select(
			IngestionMode.Etw,
			ProbeDecline("advapi32 refused Guid registration"));

		// Caller in Program.cs detects (ChosenTransport==Etw && FallbackReason!=null) and
		// throws — silently degrading to EventLog would violate the operator's explicit
		// fail-fast request.
		Assert.Equal(IngestionMode.Etw, selection.ChosenTransport);
		Assert.Equal(IngestionMode.Etw, selection.RequestedMode);
		Assert.NotNull(selection.FallbackReason);
		Assert.Contains("advapi32", selection.FallbackReason);
	}

	[Fact]
	public void Auto_UsesEtw_WhenProbeSucceeds()
	{
		var selection = EventSourceFactorySelector.Select(IngestionMode.Auto, ProbeOk());

		Assert.Equal(IngestionMode.Etw, selection.ChosenTransport);
		Assert.Equal(IngestionMode.Auto, selection.RequestedMode);
		Assert.Null(selection.FallbackReason);
	}

	[Fact]
	public void Auto_FallsBackToEventLog_WhenProbeDeclines()
	{
		var selection = EventSourceFactorySelector.Select(
			IngestionMode.Auto,
			ProbeDecline("running on Linux"));

		Assert.Equal(IngestionMode.EventLog, selection.ChosenTransport);
		Assert.Equal(IngestionMode.Auto, selection.RequestedMode);
		Assert.NotNull(selection.FallbackReason);
		Assert.Contains("Linux", selection.FallbackReason);
	}

	[Fact]
	public void Auto_SuppliesDefaultReason_WhenProbeReturnsNullReason()
	{
		var selection = EventSourceFactorySelector.Select(
			IngestionMode.Auto,
			() => (false, null));

		Assert.Equal(IngestionMode.EventLog, selection.ChosenTransport);
		Assert.NotNull(selection.FallbackReason);
	}

	[Fact]
	public void OutOfRange_DefaultsToEventLogWithReason()
	{
		var selection = EventSourceFactorySelector.Select(
			(IngestionMode)999,
			ProbeOk());

		Assert.Equal(IngestionMode.EventLog, selection.ChosenTransport);
		Assert.NotNull(selection.FallbackReason);
		Assert.Contains("999", selection.FallbackReason);
	}

	[Fact]
	public void Select_ThrowsWhenProbeIsNull()
	{
		Assert.Throws<ArgumentNullException>(() =>
			EventSourceFactorySelector.Select(IngestionMode.Auto, null!));
	}
}
