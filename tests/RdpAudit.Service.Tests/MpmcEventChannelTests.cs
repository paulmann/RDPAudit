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

		// Per-producer accounting: TryWrite attempts, clean writes and DropOldest returns.
		// Purely diagnostic; the invariant only compares seen + overflow to produced.
		int[] producerAttempts = new int[producers];
		int[] producerCleanWrites = new int[producers];
		int[] producerDroppedWrites = new int[producers];

		using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(30));

		Task[] producerTasks = new Task[producers];
		for (int p = 0; p < producers; p++)
		{
			int producerId = p;
			producerTasks[p] = Task.Run(() =>
			{
				// NO SpinWait between TryWrite calls: TryWrite completes in microseconds
				// and never blocks (DropOldest fallback). A shared SpinWait counter would
				// escalate to Thread.Sleep(1) after ~20 iterations and impose ~15 ms per
				// call on Windows, giving 'producer never blocked' AND 'producer finished
				// only ~2000 rows before cts timeout' - the exact pattern that used to
				// look like ring-buffer corruption. A real writer never pauses between
				// events either, so this reflects the production hot path.
				int clean = 0;
				int dropped = 0;
				int attempts = 0;
				for (int i = 0; i < perProducer; i++)
				{
					int seq = producerId * perProducer + i;
					attempts++;
					if (channel.TryWrite(NewDto(sentinel: seq)))
					{
						clean++;
					}
					else
					{
						dropped++;
					}
					if (cts.IsCancellationRequested) break;
				}
				producerAttempts[producerId] = attempts;
				producerCleanWrites[producerId] = clean;
				producerDroppedWrites[producerId] = dropped;
			});
		}

		int[] consumerReads = new int[consumers];
		Task[] consumerTasks = new Task[consumers];
		for (int c = 0; c < consumers; c++)
		{
			int consumerId = c;
			consumerTasks[c] = Task.Run(() =>
			{
				// Consumer: on a read miss, yield the thread instead of using SpinWait so we
				// do not accumulate SpinWait iterations that eventually turn into 15 ms
				// Thread.Sleep(1) calls on Windows. Yielding on miss keeps the CPU free for
				// producers without starving them.
				int localReads = 0;
				while (Volatile.Read(ref totalConsumed) < totalToProduce)
				{
					if (channel.TryRead(out RawEventDto? dto))
					{
						// Every consumed DTO must be unique - no double-read.
						Assert.True(seen.TryAdd(dto!.EventId, 1),
							$"Duplicate consume of sentinel {dto.EventId}");
						localReads++;
						Interlocked.Increment(ref totalConsumed);
					}
					else
					{
						Thread.Yield();
						if (cts.IsCancellationRequested) break;
					}
				}
				consumerReads[consumerId] = localReads;
			});
		}

		await Task.WhenAll(producerTasks);

		// Give the consumers a moment to drain, then cancel to unwind cleanly.
		await Task.Delay(500);
		cts.Cancel();
		await Task.WhenAll(consumerTasks);

		// Consistency invariant: seen unique + overflow >= produced - capacity. Any DTO
		// that was neither seen nor evicted would violate this and prove a lost row.
		long overflow = channel.OverflowCount;
		(long honestEvictions, long hardDrops) = channel.OverflowBreakdown();

		bool invariantHolds = seen.Count + overflow >= totalToProduce - capacity;
		if (!invariantHolds)
		{
			int totalAttempts = 0;
			int totalClean = 0;
			int totalDroppedFromApi = 0;
			for (int i = 0; i < producers; i++)
			{
				totalAttempts += producerAttempts[i];
				totalClean += producerCleanWrites[i];
				totalDroppedFromApi += producerDroppedWrites[i];
			}
			int totalConsumerReads = 0;
			for (int i = 0; i < consumers; i++)
			{
				totalConsumerReads += consumerReads[i];
			}

			var perProducerDetail = new System.Text.StringBuilder();
			for (int pi = 0; pi < producers; pi++)
			{
				if (pi > 0) perProducerDetail.Append(", ");
				perProducerDetail.Append(
					$"p{pi}={producerAttempts[pi]}/{perProducer}(clean={producerCleanWrites[pi]},drop={producerDroppedWrites[pi]})");
			}
			var perConsumerDetail = new System.Text.StringBuilder();
			for (int ci = 0; ci < consumers; ci++)
			{
				if (ci > 0) perConsumerDetail.Append(", ");
				perConsumerDetail.Append($"c{ci}={consumerReads[ci]}");
			}

			Assert.Fail(
				"Mpmc invariant violated (seen + overflow < produced - capacity)." + Environment.NewLine +
				$"  seen.Count            = {seen.Count}" + Environment.NewLine +
				$"  overflow (total)      = {overflow}" + Environment.NewLine +
				$"  overflow.honestEvict  = {honestEvictions}" + Environment.NewLine +
				$"  overflow.hardDrops    = {hardDrops}" + Environment.NewLine +
				$"  produced (nominal)    = {totalToProduce}" + Environment.NewLine +
				$"  capacity              = {capacity}" + Environment.NewLine +
				$"  channel.ApproxCount   = {channel.ApproxCount}" + Environment.NewLine +
				$"  totalConsumed         = {Volatile.Read(ref totalConsumed)}" + Environment.NewLine +
				$"  totalConsumerReads    = {totalConsumerReads}" + Environment.NewLine +
				$"  producerAttemptsSum   = {totalAttempts}" + Environment.NewLine +
				$"  producerCleanSum      = {totalClean}" + Environment.NewLine +
				$"  producerDroppedApiSum = {totalDroppedFromApi}" + Environment.NewLine +
				$"  per-producer          : {perProducerDetail}" + Environment.NewLine +
				$"  per-consumer          : {perConsumerDetail}" + Environment.NewLine +
				$"  cts.IsCancellationRequested = {cts.IsCancellationRequested}" + Environment.NewLine +
				$"  producers                   = {producers}" + Environment.NewLine +
				$"  consumers                   = {consumers}" + Environment.NewLine +
				$"  Environment.ProcessorCount  = {Environment.ProcessorCount}");
		}
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
