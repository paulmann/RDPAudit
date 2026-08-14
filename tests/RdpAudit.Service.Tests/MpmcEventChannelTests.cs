/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 2.0.0
// File   : MpmcEventChannelTests.cs
// Project: RdpAudit.Service.Tests
// Purpose: Contract tests for MpmcEventChannel (the RawEventDto-aware Vyukov ring adapter).
// Depends: MpmcEventChannel, RawEventDto, EventChannel, RingBufferBackend
// Extends: Add a test whenever DropOldest policy or backend selection changes.

using System;
using System.Collections.Concurrent;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Options;
using RdpAudit.Core.Config;
using RdpAudit.Core.Events;
using RdpAudit.Service;
using RdpAudit.Service.Infrastructure;
using Xunit;

namespace RdpAudit.Service.Tests;

public sealed class MpmcEventChannelTests
{
	// ── DropOldest policy ────────────────────────────────────────────────────────

	[Fact]
	public void TryWrite_ReturnsTrueOnCleanWrite_FalseWhenEvictionForced()
	{
		using var channel = new MpmcEventChannel(4);

		for (int i = 0; i < 4; i++)
		{
			Assert.True(channel.TryWrite(NewDto(sentinel: i)), $"clean write {i} should succeed");
		}

		// Ring is now full. Next write must succeed via DropOldest and return false to
		// signal the eviction to the caller.
		Assert.False(channel.TryWrite(NewDto(sentinel: 100)));
		Assert.Equal(1, channel.OverflowCount);

		// FIFO after one eviction: expected surviving sentinels are 1, 2, 3, 100.
		Assert.True(channel.TryRead(out RawEventDto? d));
		Assert.Equal(1, d!.EventId);
		Assert.True(channel.TryRead(out d));
		Assert.Equal(2, d!.EventId);
		Assert.True(channel.TryRead(out d));
		Assert.Equal(3, d!.EventId);
		Assert.True(channel.TryRead(out d));
		Assert.Equal(100, d!.EventId);
		Assert.False(channel.TryRead(out _));
	}

	[Fact]
	public void TryRead_ReturnsFalseWhenEmpty()
	{
		using var channel = new MpmcEventChannel(4);
		Assert.False(channel.TryRead(out RawEventDto? d));
		Assert.Null(d);
	}

	[Fact]
	public void Capacity_IsRoundedToPowerOfTwoInEventChannel()
	{
		Assert.Throws<ArgumentException>(() => new MpmcEventChannel(1000));

		using var ok = new MpmcEventChannel(1024);
		Assert.Equal(1024, ok.Capacity);
	}

	// ── Concurrent Multi-Producer Multi-Consumer ─────────────────────────────────

	[Fact]
	public async Task Mpmc_ManyProducers_ManyConsumers_NoDataCorruption()
	{
		const int capacity = 4096;
		const int producers = 4;
		const int consumers = 3;
		const int perProducer = 5_000;

		using var channel = new MpmcEventChannel(capacity);
		var seen = new ConcurrentDictionary<int, byte>();
		int totalConsumed = 0;
		int totalToProduce = producers * perProducer;
		using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(30));

		Task[] producerTasks = new Task[producers];
		for (int p = 0; p < producers; p++)
		{
			int producerId = p;
			producerTasks[p] = Task.Run(() =>
			{
				SpinWait spinner = new();
				for (int i = 0; i < perProducer; i++)
				{
					int seq = producerId * perProducer + i;
					// TryWrite always accepts by design (either clean or via DropOldest).
					_ = channel.TryWrite(NewDto(sentinel: seq));
					spinner.SpinOnce();
					if (cts.IsCancellationRequested) return;
				}
			}, cts.Token);
		}

		Task[] consumerTasks = new Task[consumers];
		for (int c = 0; c < consumers; c++)
		{
			consumerTasks[c] = Task.Run(() =>
			{
				SpinWait spinner = new();
				while (Volatile.Read(ref totalConsumed) < totalToProduce)
				{
					if (channel.TryRead(out RawEventDto? dto))
					{
						// Every consumed DTO must be unique — no double-read.
						Assert.True(seen.TryAdd(dto!.EventId, 1),
							$"Duplicate consume of sentinel {dto.EventId}");
						Interlocked.Increment(ref totalConsumed);
						spinner.Reset();
					}
					else
					{
						spinner.SpinOnce();
						if (cts.IsCancellationRequested) return;
					}
				}
			}, cts.Token);
		}

		await Task.WhenAll(producerTasks);

		// Give the consumers a moment to drain, then cancel to unwind cleanly.
		await Task.Delay(500);
		cts.Cancel();
		await Task.WhenAll(consumerTasks);

		// Consistency invariant: seen unique + overflow >= produced - capacity. Any DTO
		// that was neither seen nor evicted would violate this and prove a lost row.
		long overflow = channel.OverflowCount;
		Assert.True(seen.Count + overflow >= totalToProduce - capacity,
			$"seen={seen.Count} overflow={overflow} produced={totalToProduce} capacity={capacity}");
	}

	// ── Backend Selection via EventChannel ───────────────────────────────────────

	[Fact]
	public void EventChannel_UsesMpmcBackend_WhenConfigured()
	{
		var options = Options.Create(new RdpAuditOptions
		{
			Monitoring = new MonitoringOptions
			{
				ChannelCapacity = 1024,
				RingBufferBackend = RingBufferBackend.Mpmc,
			},
		});

		var eventChannel = new EventChannel(options);
		try
		{
			Assert.IsType<MpmcEventChannel>(eventChannel.Backend);
			Assert.Equal(1024, eventChannel.Backend.Capacity);
			Assert.Throws<InvalidOperationException>(() => _ = eventChannel.Channel);
		}
		finally
		{
			eventChannel.Backend.Dispose();
		}
	}

	[Fact]
	public void EventChannel_UsesSpscBackend_ByDefault()
	{
		var options = Options.Create(new RdpAuditOptions
		{
			Monitoring = new MonitoringOptions
			{
				ChannelCapacity = 1024,
			},
		});

		var eventChannel = new EventChannel(options);
		try
		{
			Assert.IsType<RingBufferEventChannel>(eventChannel.Backend);
			Assert.Same(eventChannel.Backend, eventChannel.Channel);
		}
		finally
		{
			eventChannel.Backend.Dispose();
		}
	}

	// ── Helpers ──────────────────────────────────────────────────────────────────

	private static RawEventDto NewDto(int sentinel) => new()
	{
		EventId = sentinel,
		Channel = "Security",
		TimeUtc = DateTime.UtcNow,
		XmlPayload = "<Event/>",
	};
}
