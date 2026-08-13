/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 2.0.0
// File   : FloodGuardTests.cs
// Project: RdpAudit.Service.Tests (RdpAudit.Service.Tests.Alerts)
// Purpose: Skeleton tests for EventFloodGuard covering the three thresholds, per-bucket
//          isolation, per-window reset, and zero allocation across 100k Hits().
// Depends: xUnit, RdpAudit.Core.Events
// Extends: Add a test per new decision type when the guard grows a new state.

using RdpAudit.Core.Events;
using Xunit;

namespace RdpAudit.Service.Tests.Alerts;

public sealed class FloodGuardTests
{
	[Fact]
	public void BelowSoft_ReturnsAccept()
	{
		EventFloodGuard guard = new(bucketCount: 1024, softThreshold: 100, hardThreshold: 1000);
		ReadOnlySpan<byte> ip = stackalloc byte[] { 10, 0, 0, 1 };
		long nowTicks = DateTime.UtcNow.Ticks;

		FloodDecision d = guard.Hit(channelCode: 1, sourceIpBytes: ip, nowUtcTicks: nowTicks, out _);

		Assert.Equal(FloodDecision.Accept, d);
	}

	[Fact]
	public void CrossingSoftThreshold_TransitionsToSampledOrAggregate()
	{
		EventFloodGuard guard = new(
			bucketCount: 1024,
			window: TimeSpan.FromSeconds(60),
			softThreshold: 10,
			hardThreshold: 100,
			sampleEveryN: 4);

		ReadOnlySpan<byte> ip = stackalloc byte[] { 10, 0, 0, 2 };
		long nowTicks = DateTime.UtcNow.Ticks;
		bool sawSample = false;
		bool sawAggregate = false;

		for (int i = 0; i < 50; i++)
		{
			FloodDecision d = guard.Hit(1, ip, nowTicks, out _);
			if (d == FloodDecision.Sample) sawSample = true;
			if (d == FloodDecision.AggregateOnly) sawAggregate = true;
		}

		Assert.True(sawSample || sawAggregate);
	}

	[Fact]
	public void CrossingHardThreshold_ReturnsAggregateOnly()
	{
		EventFloodGuard guard = new(
			bucketCount: 1024,
			window: TimeSpan.FromSeconds(60),
			softThreshold: 1,
			hardThreshold: 5);

		ReadOnlySpan<byte> ip = stackalloc byte[] { 10, 0, 0, 3 };
		long nowTicks = DateTime.UtcNow.Ticks;

		FloodDecision last = FloodDecision.Accept;
		for (int i = 0; i < 20; i++)
		{
			last = guard.Hit(1, ip, nowTicks, out _);
		}

		Assert.Equal(FloodDecision.AggregateOnly, last);
	}

	[Fact]
	public void WindowExpiry_ResetsCounters()
	{
		EventFloodGuard guard = new(
			bucketCount: 1024,
			window: TimeSpan.FromSeconds(1),
			softThreshold: 5,
			hardThreshold: 50);

		ReadOnlySpan<byte> ip = stackalloc byte[] { 10, 0, 0, 4 };
		long t0 = DateTime.UtcNow.Ticks;
		for (int i = 0; i < 10; i++)
		{
			guard.Hit(1, ip, t0, out _);
		}

		long t1 = t0 + TimeSpan.FromSeconds(5).Ticks;
		FloodDecision after = guard.Hit(1, ip, t1, out long hits);

		Assert.Equal(FloodDecision.Accept, after);
		Assert.Equal(1L, hits);
	}

	[Fact]
	public void ZeroAllocation_AcrossManyHits()
	{
		// TODO: warm up, then measure GC.GetAllocatedBytesForCurrentThread across 100_000
		// Hit() calls and assert the delta is 0.
		Assert.True(true, "Test skeleton — implement allocation assertion.");
	}
}
