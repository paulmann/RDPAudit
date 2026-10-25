/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 2.0.1
// File   : FloodGuardTests.cs
// Project: RdpAudit.Service.Tests (RdpAudit.Service.Tests.Alerts)
// Purpose: Verifies flood-guard thresholds, isolation, allocation behavior, and critical-evidence bypassing.
// Depends: xUnit, Moq, EventFloodGuard, FloodGuardEventPipe, ServiceMetrics
// Extends: Add a deterministic assertion for every new flood decision or protected evidence category.

using Microsoft.Extensions.Options;
using Moq;
using RdpAudit.Core.Config;
using RdpAudit.Core.Events;
using RdpAudit.Service;
using RdpAudit.Service.Infrastructure;
using Xunit;

namespace RdpAudit.Service.Tests.Alerts;

public sealed class FloodGuardTests
{
	[Fact]
	public void BelowSoftThreshold_ReturnsAccept()
	{
		EventFloodGuard guard = new(bucketCount: 1_024, softThreshold: 100, hardThreshold: 1_000);
		ReadOnlySpan<byte> ip = [10, 0, 0, 1];

		FloodDecision decision = guard.Hit(1, ip, DateTime.UtcNow.Ticks, out long hits);

		Assert.Equal(FloodDecision.Accept, decision);
		Assert.Equal(1L, hits);
	}

	[Fact]
	public void FirstSeenPair_ReturnsAcceptEvenAtTheSoftThreshold()
	{
		EventFloodGuard guard = new(bucketCount: 1_024, softThreshold: 1, hardThreshold: 2);
		ReadOnlySpan<byte> ip = [10, 0, 0, 9];

		FloodDecision decision = guard.Hit(1, ip, DateTime.UtcNow.Ticks, out long hits);

		Assert.Equal(FloodDecision.Accept, decision);
		Assert.Equal(1L, hits);
	}

	[Fact]
	public void CrossingSoftThreshold_UsesDeterministicSampling()
	{
		EventFloodGuard guard = new(
			bucketCount: 1_024,
			window: TimeSpan.FromSeconds(60),
			softThreshold: 4,
			hardThreshold: 12,
			sampleEveryN: 3);
		ReadOnlySpan<byte> ip = [10, 0, 0, 2];
		long nowUtcTicks = DateTime.UtcNow.Ticks;

		FloodDecision[] expected =
		[
			FloodDecision.Accept,
			FloodDecision.Accept,
			FloodDecision.Accept,
			FloodDecision.AggregateOnly,
			FloodDecision.AggregateOnly,
			FloodDecision.Sample,
			FloodDecision.AggregateOnly,
			FloodDecision.AggregateOnly,
			FloodDecision.Sample,
			FloodDecision.AggregateOnly,
			FloodDecision.AggregateOnly,
			FloodDecision.AggregateOnly,
		];

		for (int index = 0; index < expected.Length; index++)
		{
			FloodDecision actual = guard.Hit(1, ip, nowUtcTicks, out long aggregateHits);

			Assert.Equal(index + 1L, aggregateHits);
			Assert.Equal(expected[index], actual);
		}
	}

	[Fact]
	public void WindowExpiry_ResetsCounters()
	{
		EventFloodGuard guard = new(
			bucketCount: 1_024,
			window: TimeSpan.FromSeconds(1),
			softThreshold: 5,
			hardThreshold: 50);
		ReadOnlySpan<byte> ip = [10, 0, 0, 4];
		long initialTicks = DateTime.UtcNow.Ticks;

		for (int index = 0; index < 10; index++)
		{
			guard.Hit(1, ip, initialTicks, out _);
		}

		FloodDecision decision = guard.Hit(
			1,
			ip,
			initialTicks + TimeSpan.FromSeconds(5).Ticks,
			out long aggregateHits);

		Assert.Equal(FloodDecision.Accept, decision);
		Assert.Equal(1L, aggregateHits);
	}

	[Fact]
	public void DifferentSourceIps_DoNotShareFloodState()
	{
		EventFloodGuard guard = new(
			bucketCount: 1_024,
			window: TimeSpan.FromSeconds(60),
			softThreshold: 3,
			hardThreshold: 10);
		ReadOnlySpan<byte> firstIp = [10, 0, 0, 10];
		ReadOnlySpan<byte> secondIp = [10, 0, 0, 11];
		long nowUtcTicks = DateTime.UtcNow.Ticks;

		for (int index = 0; index < 4; index++)
		{
			guard.Hit(1, firstIp, nowUtcTicks, out _);
		}

		FloodDecision secondIpDecision = guard.Hit(1, secondIp, nowUtcTicks, out long secondIpHits);

		Assert.Equal(FloodDecision.Accept, secondIpDecision);
		Assert.Equal(1L, secondIpHits);
	}

	[Fact]
	public void CriticalEvent_BypassesGuardAndAlwaysWrites()
	{
		RdpAuditOptions options = new()
		{
			Monitoring = new MonitoringOptions
			{
				FloodGuardEnabled = true,
			},
		};
		IOptionsMonitor<RdpAuditOptions> optionsMonitor = Mock.Of<IOptionsMonitor<RdpAuditOptions>>(
			monitor => monitor.CurrentValue == options);
		RecordingEventPipe inner = new();
		ServiceMetrics metrics = new();
		FloodGuardEventPipe pipe = new(
			inner,
			new EventFloodGuard(softThreshold: 1, hardThreshold: 2),
			optionsMonitor,
			metrics);
		RawEventDto criticalEvent = new()
		{
			EventId = 4624,
			Channel = EventCatalog.ChannelSecurity,
			SourceIp = "203.0.113.10",
		};

		pipe.TryWrite(criticalEvent);
		pipe.TryWrite(criticalEvent);
		pipe.TryWrite(criticalEvent);

		Assert.Equal(3, inner.WriteCount);
		Assert.Equal(0L, metrics.FloodSuppressedCount);
	}

	[Fact]
	public void ZeroAllocation_AcrossOneHundredThousandHits()
	{
		EventFloodGuard guard = new(bucketCount: 1_024, softThreshold: 1_000, hardThreshold: 10_000);
		ReadOnlySpan<byte> ip = [192, 0, 2, 1];
		long nowUtcTicks = DateTime.UtcNow.Ticks;

		for (int index = 0; index < 1_000; index++)
		{
			guard.Hit(7, ip, nowUtcTicks, out _);
		}

		long before = GC.GetAllocatedBytesForCurrentThread();
		for (int index = 0; index < 100_000; index++)
		{
			guard.Hit(7, ip, nowUtcTicks, out _);
		}
		long after = GC.GetAllocatedBytesForCurrentThread();

		Assert.Equal(0L, after - before);
	}

	private sealed class RecordingEventPipe : IEventPipe
	{
		public int WriteCount { get; private set; }

		public int Capacity => 1;

		public long OverflowCount => 0L;

		public bool TryWrite(RawEventDto dto)
		{
			ArgumentNullException.ThrowIfNull(dto);
			WriteCount++;
			return true;
		}

		public bool TryRead(out RawEventDto dto)
		{
			dto = null!;
			return false;
		}

		public ValueTask<bool> WaitToReadAsync(TimeSpan timeout, CancellationToken ct)
			=> ValueTask.FromResult(false);
	}
}
