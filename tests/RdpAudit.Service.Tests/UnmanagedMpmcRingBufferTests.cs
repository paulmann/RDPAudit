/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 2.0.0
// File   : UnmanagedMpmcRingBufferTests.cs
// Project: RdpAudit.Service.Tests
// Purpose: Behavioural and stress tests for the Vyukov MPMC ring buffer that backs
//          v2.0 multi-producer event ingestion.
// Depends: UnmanagedMpmcRingBuffer, Xunit
// Extends: Add a test whenever the ring buffer contract changes (new eviction policy,
//          new pointer geometry, new zero-alloc invariant).

using System;
using System.Collections.Concurrent;
using System.Threading;
using System.Threading.Tasks;
using RdpAudit.Service.Infrastructure;
using Xunit;

namespace RdpAudit.Service.Tests;

/// <summary>Direct behavioural tests for <see cref="UnmanagedMpmcRingBuffer"/>. The channel
/// layer (<c>MpmcEventChannel</c>) has its own tests; here we exercise the raw byte-oriented
/// ring under adversarial single- and multi-thread scenarios.</summary>
public sealed class UnmanagedMpmcRingBufferTests
{
	// ── Construction ─────────────────────────────────────────────────────────────

	[Theory]
	[InlineData(0)]
	[InlineData(-1)]
	[InlineData(3)]      // not a power of two
	[InlineData(1000)]   // not a power of two
	public void Constructor_RejectsNonPowerOfTwoCapacity(int capacity)
	{
		Assert.Throws<ArgumentException>(() => new UnmanagedMpmcRingBuffer(capacity));
	}

	[Theory]
	[InlineData(1)]
	[InlineData(2)]
	[InlineData(1024)]
	[InlineData(65536)]
	public void Constructor_AcceptsPowerOfTwoCapacity(int capacity)
	{
		using var ring = new UnmanagedMpmcRingBuffer(capacity);
		Assert.Equal(capacity, ring.Capacity);
		Assert.Equal(0, ring.OverflowCount);
		Assert.Equal(0, ring.ApproxCount);
	}

	// ── Single-Thread FIFO ───────────────────────────────────────────────────────

	[Fact]
	public void TryWriteRead_SingleThreadedFifoRoundtrip()
	{
		const int capacity = 16;
		using var ring = new UnmanagedMpmcRingBuffer(capacity);

		Span<byte> outBuf = stackalloc byte[UnmanagedMpmcRingBuffer.SlotSize];
		Span<byte> payload = stackalloc byte[UnmanagedMpmcRingBuffer.SlotSize];

		// Push 12 payloads with unique first-byte sentinels.
		for (byte i = 0; i < 12; i++)
		{
			payload.Clear();
			payload[0] = i;
			payload[UnmanagedMpmcRingBuffer.SlotSize - 1] = (byte)(0xFF - i);
			Assert.True(ring.TryWrite(payload));
		}

		Assert.Equal(12, ring.ApproxCount);

		// Read them back in exactly the same order.
		for (byte i = 0; i < 12; i++)
		{
			outBuf.Clear();
			Assert.True(ring.TryRead(outBuf));
			Assert.Equal(i, outBuf[0]);
			Assert.Equal((byte)(0xFF - i), outBuf[UnmanagedMpmcRingBuffer.SlotSize - 1]);
		}

		Assert.Equal(0, ring.ApproxCount);
		Assert.False(ring.TryRead(outBuf));
	}

	[Fact]
	public void TryWrite_ReturnsFalseWhenFull_AndDoesNotIncrementOverflow()
	{
		using var ring = new UnmanagedMpmcRingBuffer(4);
		Span<byte> payload = stackalloc byte[UnmanagedMpmcRingBuffer.SlotSize];

		for (int i = 0; i < 4; i++) Assert.True(ring.TryWrite(payload));
		Assert.False(ring.TryWrite(payload));
		Assert.Equal(0, ring.OverflowCount);
	}

	[Fact]
	public void TryEvictOldest_FreesOneSlotAndIncrementsOverflow()
	{
		using var ring = new UnmanagedMpmcRingBuffer(4);
		Span<byte> payload = stackalloc byte[UnmanagedMpmcRingBuffer.SlotSize];

		for (int i = 0; i < 4; i++)
		{
			payload[0] = (byte)i;
			Assert.True(ring.TryWrite(payload));
		}

		Assert.True(ring.TryEvictOldest());
		Assert.Equal(1, ring.OverflowCount);
		Assert.Equal(3, ring.ApproxCount);

		// Now a fresh write must succeed.
		payload[0] = 0xAA;
		Assert.True(ring.TryWrite(payload));

		// FIFO ordering: the first surviving byte should be 1 (index 0 was evicted).
		Span<byte> readBuf = stackalloc byte[UnmanagedMpmcRingBuffer.SlotSize];
		Assert.True(ring.TryRead(readBuf));
		Assert.Equal(1, readBuf[0]);
	}

	[Fact]
	public void TryEvictOldest_ReturnsFalseWhenEmpty()
	{
		using var ring = new UnmanagedMpmcRingBuffer(4);
		Assert.False(ring.TryEvictOldest());
		Assert.Equal(0, ring.OverflowCount);
	}

	// ── Wraparound ────────────────────────────────────────────────────────────────

	[Fact]
	public void Wraparound_WritesAndReadsRemainFifo()
	{
		const int capacity = 8;
		using var ring = new UnmanagedMpmcRingBuffer(capacity);
		Span<byte> payload = stackalloc byte[UnmanagedMpmcRingBuffer.SlotSize];
		Span<byte> readBuf = stackalloc byte[UnmanagedMpmcRingBuffer.SlotSize];

		// Drive ~5 full laps through the ring.
		for (int lap = 0; lap < 5; lap++)
		{
			for (byte i = 0; i < capacity; i++)
			{
				payload[0] = (byte)(lap * 100 + i);
				Assert.True(ring.TryWrite(payload));
			}

			for (byte i = 0; i < capacity; i++)
			{
				readBuf.Clear();
				Assert.True(ring.TryRead(readBuf));
				Assert.Equal((byte)(lap * 100 + i), readBuf[0]);
			}
		}
	}

	// ── Multi-Producer Multi-Consumer ────────────────────────────────────────────

	[Fact]
	public async Task MpmcStress_AllProducedItemsAreConsumedExactlyOnce()
	{
		const int capacity = 1024;
		const int producerCount = 4;
		const int consumerCount = 4;
		const int perProducer = 5_000;
		int totalToProduce = producerCount * perProducer;

		using var ring = new UnmanagedMpmcRingBuffer(capacity);
		var consumed = new ConcurrentDictionary<int, byte>();
		using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(30));

		Task[] producers = new Task[producerCount];
		for (int p = 0; p < producerCount; p++)
		{
			int producerId = p;
			producers[p] = Task.Run(() =>
			{
				Span<byte> payload = stackalloc byte[UnmanagedMpmcRingBuffer.SlotSize];
				for (int i = 0; i < perProducer; i++)
				{
					int seq = producerId * perProducer + i;
					BitConverter.TryWriteBytes(payload, seq);

					SpinWait spinner = new();
					while (!ring.TryWrite(payload))
					{
						spinner.SpinOnce();
						if (cts.IsCancellationRequested) return;
					}
				}
			}, cts.Token);
		}

		Task[] consumers = new Task[consumerCount];
		int totalConsumed = 0;
		for (int c = 0; c < consumerCount; c++)
		{
			consumers[c] = Task.Run(() =>
			{
				Span<byte> readBuf = stackalloc byte[UnmanagedMpmcRingBuffer.SlotSize];
				SpinWait spinner = new();
				while (Volatile.Read(ref totalConsumed) < totalToProduce)
				{
					if (ring.TryRead(readBuf))
					{
						int seq = BitConverter.ToInt32(readBuf);
						Assert.True(consumed.TryAdd(seq, 1), $"Duplicate consume of {seq}");
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

		await Task.WhenAll(producers);
		await Task.WhenAll(consumers);

		Assert.Equal(totalToProduce, consumed.Count);
		Assert.Equal(0, ring.OverflowCount); // no DropOldest was invoked
	}

	[Fact]
	public async Task MpmcStress_WithEviction_NoDoubleEviction()
	{
		const int capacity = 32;
		const int producerCount = 8;
		const int perProducer = 2_000;

		using var ring = new UnmanagedMpmcRingBuffer(capacity);
		using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(20));

		// Producers spam the ring flat-out; each eviction failure triggers a manual evict.
		long evictionAttempts = 0;
		long evictionSuccesses = 0;

		Task[] producers = new Task[producerCount];
		for (int p = 0; p < producerCount; p++)
		{
			producers[p] = Task.Run(() =>
			{
				Span<byte> payload = stackalloc byte[UnmanagedMpmcRingBuffer.SlotSize];
				for (int i = 0; i < perProducer; i++)
				{
					while (!ring.TryWrite(payload))
					{
						Interlocked.Increment(ref evictionAttempts);
						if (ring.TryEvictOldest()) Interlocked.Increment(ref evictionSuccesses);
						if (cts.IsCancellationRequested) return;
					}
				}
			}, cts.Token);
		}

		await Task.WhenAll(producers);

		// Invariant: successful evictions equal the OverflowCount tracked internally by
		// the ring. Any discrepancy means a slot was double-evicted (Interlocked bug).
		Assert.Equal(Volatile.Read(ref evictionSuccesses), ring.OverflowCount);
	}

	// ── Zero-Allocation ──────────────────────────────────────────────────────────

	[Fact]
	public void HotPath_TryWriteAndTryRead_AllocateZeroBytes()
	{
		const int iterations = 10_000;
		using var ring = new UnmanagedMpmcRingBuffer(1024);
		Span<byte> payload = stackalloc byte[UnmanagedMpmcRingBuffer.SlotSize];
		Span<byte> readBuf = stackalloc byte[UnmanagedMpmcRingBuffer.SlotSize];

		// Warm the JIT so the measurement isn't skewed by first-hit compilation.
		for (int i = 0; i < 100; i++)
		{
			ring.TryWrite(payload);
			ring.TryRead(readBuf);
		}

		long before = GC.GetAllocatedBytesForCurrentThread();
		for (int i = 0; i < iterations; i++)
		{
			ring.TryWrite(payload);
			ring.TryRead(readBuf);
		}
		long delta = GC.GetAllocatedBytesForCurrentThread() - before;

		Assert.Equal(0, delta);
	}
}
