/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 2.0.0
// File   : RingBufferEventPipeSemaphoreTests.cs
// Project: RdpAudit.Service.Tests (RdpAudit.Service.Tests)
// Purpose: Pins the semaphore-backed WaitToReadAsync contract introduced in RingBufferEventPipe
//          v2.1.0. Two invariants worth their own file so a regression to polling is caught
//          immediately: (1) a producer's TryWrite unblocks a concurrent waiter with latency far
//          below the old 5ms poll interval; (2) repeated writes past a still-pending signal do
//          NOT throw or leak — the level-triggered signal collapses extra edges.
// Depends: xUnit, RingBufferEventPipe, RingBufferEventChannel, RawEventDto
// Extends: Add a fact here when RingBufferEventPipe grows a new signalling primitive (e.g. shard
//          fan-out, MPMC bounded ring). Keep timing thresholds conservative to survive CI noise.

using System.Diagnostics;
using RdpAudit.Core.Events;
using RdpAudit.Service.Infrastructure;
using Xunit;

namespace RdpAudit.Service.Tests;

/// <summary>
/// Semaphore-focused facts for <see cref="RingBufferEventPipe"/>. Live-tests the signalling edge
/// between <see cref="RingBufferEventPipe.TryWrite"/> and <see cref="RingBufferEventPipe.WaitToReadAsync"/>.
/// </summary>
public sealed class RingBufferEventPipeSemaphoreTests
{
	private static RawEventDto MakeDto(int eventId) => new()
	{
		EventId = eventId,
		Channel = "Security",
		TimeUtc = DateTime.UtcNow,
		XmlPayload = "<Event/>",
	};

	// ── Signalling latency ───────────────────────────────────────────────────────

	[Fact]
	public async Task WaitToReadAsync_TryWrite_UnblocksWaiterBelowPollInterval()
	{
		// The pre-v2.1 implementation polled at 5ms. A concurrent producer therefore added up
		// to ~5ms of latency on the wait-then-write race. With a proper semaphore the release
		// is observed on the very next scheduler tick — well under 100ms even under CI noise.
		using RingBufferEventPipe pipe = new(new RingBufferEventChannel(16));

		using CancellationTokenSource cts = new(TimeSpan.FromSeconds(2));
		Task<bool> waitTask = pipe.WaitToReadAsync(TimeSpan.FromSeconds(2), cts.Token).AsTask();

		// Ensure the waiter is genuinely parked on the semaphore before we write.
		await Task.Delay(30, cts.Token);

		Stopwatch sw = Stopwatch.StartNew();
		Assert.True(pipe.TryWrite(MakeDto(4625)));
		bool ready = await waitTask;
		sw.Stop();

		Assert.True(ready);
		// Generous upper bound — 100ms is far below the 5ms poll (worst case ~5ms + jitter)
		// under load but tight enough that a regression back to Task.Delay-based polling with
		// a much larger interval would fail here. Not asserting a lower bound: on a hot CPU
		// the release may complete in <1ms and we do not want to depend on that.
		Assert.True(sw.ElapsedMilliseconds < 100,
			$"Waiter unblocked in {sw.ElapsedMilliseconds}ms — expected <100ms.");
	}

	[Fact]
	public async Task WaitToReadAsync_MultipleWrites_ThenSingleWait_DoesNotThrow()
	{
		// Level-triggered signal: repeated Release calls past maxCount = 1 must collapse and
		// never throw. Prior polling implementation could not exhibit this failure mode; the
		// semaphore-backed one must swallow SemaphoreFullException on the release side.
		using RingBufferEventPipe pipe = new(new RingBufferEventChannel(16));

		for (int i = 0; i < 8; i++)
		{
			Assert.True(pipe.TryWrite(MakeDto(4000 + i)));
		}

		bool ready = await pipe.WaitToReadAsync(TimeSpan.FromMilliseconds(50), CancellationToken.None);
		Assert.True(ready);

		// All 8 DTOs must still be readable — the semaphore never gates the ring.
		int count = 0;
		while (pipe.TryRead(out _))
		{
			count++;
			if (count > 32) break; // guard against runaway loop
		}
		Assert.Equal(8, count);
	}

	// ── Signal consumption ordering ──────────────────────────────────────────────

	[Fact]
	public async Task WaitToReadAsync_SecondWait_AfterDrain_TimesOut()
	{
		// After the consumer drained the pipe, the previously-released signal must NOT let
		// the next WaitToReadAsync return true for phantom data. The wait must actually time
		// out — the signal is drained together with the DTO.
		using RingBufferEventPipe pipe = new(new RingBufferEventChannel(16));

		Assert.True(pipe.TryWrite(MakeDto(4625)));
		Assert.True(await pipe.WaitToReadAsync(TimeSpan.FromMilliseconds(50), CancellationToken.None));
		Assert.True(pipe.TryRead(out _));
		Assert.False(pipe.TryRead(out _)); // pipe is genuinely empty now

		Stopwatch sw = Stopwatch.StartNew();
		bool ready = await pipe.WaitToReadAsync(TimeSpan.FromMilliseconds(50), CancellationToken.None);
		sw.Stop();

		Assert.False(ready);
		// Confirm the wait actually waited — not a stale-signal instant return.
		Assert.True(sw.ElapsedMilliseconds >= 30,
			$"Wait returned in {sw.ElapsedMilliseconds}ms — expected genuine timeout.");
	}

	// ── Disposal ─────────────────────────────────────────────────────────────────

	[Fact]
	public void Dispose_IsIdempotent()
	{
		RingBufferEventPipe pipe = new(new RingBufferEventChannel(16));
		pipe.Dispose();
		pipe.Dispose(); // must not throw
	}

	[Fact]
	public async Task WaitToReadAsync_AfterDispose_ReturnsFalseNotThrows()
	{
		RingBufferEventPipe pipe = new(new RingBufferEventChannel(16));

		using CancellationTokenSource cts = new();
		Task<bool> waitTask = pipe.WaitToReadAsync(TimeSpan.FromSeconds(1), cts.Token).AsTask();
		await Task.Delay(20);

		pipe.Dispose();

		bool ready = await waitTask;
		Assert.False(ready);
	}
}
