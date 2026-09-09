/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 2.0.0
// File   : EventChannelRingBufferTests.cs
// Project: RdpAudit.Service.Tests (RdpAudit.Service.Tests)
// Purpose: Pins EventChannel's Ring Buffer contract — capacity clamping, power-of-two rounding,
//          overflow counter initialization and independence across instances. Formerly part of
//          EventCollectorWorkerRingBufferTests; that class was retired together with the legacy
//          EventCollectorWorker in iter14, and these facts moved here because they never actually
//          exercised the worker — only the underlying EventChannel wrapper.
// Depends: EventChannel, RingBufferEventChannel, RdpAuditOptions, xUnit
// Extends: Add facts here when EventChannel gains a new SLA-shaped invariant (minimum capacity,
//          rounding rule, or metric surface). Do NOT re-introduce EventCollectorWorker references.

using Microsoft.Extensions.Options;
using RdpAudit.Core.Config;
using RdpAudit.Service;
using RdpAudit.Service.Infrastructure;
using Xunit;

namespace RdpAudit.Service.Tests;

/// <summary>
/// Unit tests for the <see cref="EventChannel"/> wrapper over <see cref="RingBufferEventChannel"/>.
/// Verifies capacity clamping, power-of-two rounding, overflow counter initialization and instance
/// independence — the four SLA-shaped invariants callers rely on.
/// </summary>
public sealed class EventChannelRingBufferTests
{
	// ── Fixtures ─────────────────────────────────────────────────────────────────

	private static IOptions<RdpAuditOptions> BuildOptions(int channelCapacity, int batchSize = 10) =>
		Options.Create(new RdpAuditOptions
		{
			Monitoring = new MonitoringOptions
			{
				ChannelCapacity = channelCapacity,
				BatchSize = batchSize,
			},
		});

	// ── Tests ────────────────────────────────────────────────────────────────────

	[Fact]
	public void EventChannel_WrapsRingBufferEventChannel()
	{
		EventChannel channel = new(BuildOptions(channelCapacity: 2));
		Assert.IsType<RingBufferEventChannel>(channel.Channel);
	}

	[Fact]
	public void EventChannel_EnforcesMinimumCapacity_PowerOfTwo()
	{
		// EventChannel enforces Math.Max(1000, capacity) then rounds to next power of two.
		// Math.Max(1000, 2) = 1000 -> next power of two = 1024.
		EventChannel channel = new(BuildOptions(channelCapacity: 2));
		Assert.Equal(1024, channel.Channel.Capacity);
	}

	[Fact]
	public void EventChannel_LargeCapacity_RoundsToNextPowerOfTwo()
	{
		// 2000 -> next power of two = 2048.
		EventChannel channel = new(BuildOptions(channelCapacity: 2000));
		Assert.Equal(2048, channel.Channel.Capacity);
	}

	[Fact]
	public void EventChannel_InitialOverflowCount_IsZero()
	{
		EventChannel channel = new(BuildOptions(channelCapacity: 2));
		Assert.Equal(0, channel.Channel.OverflowCount);
	}

	[Fact]
	public void EventChannel_MultipleChannels_AreIndependent()
	{
		EventChannel channel1 = new(BuildOptions(channelCapacity: 2));
		EventChannel channel2 = new(BuildOptions(channelCapacity: 2));

		Assert.NotSame(channel1.Channel, channel2.Channel);
	}
}
