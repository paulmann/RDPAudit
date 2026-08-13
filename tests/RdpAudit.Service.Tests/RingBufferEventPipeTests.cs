/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 2.0.0
// File   : RingBufferEventPipeTests.cs
// Project: RdpAudit.Service.Tests (RdpAudit.Service.Tests)
// Purpose: Verifies RingBufferEventPipe honours the IEventPipe contract on top of the shipped
//          RingBufferEventChannel. Pins the invariants Producers/Consumers rely on:
//          write-then-read round-trip, prefetch/consume ordering under WaitToReadAsync, timeout
//          semantics, cancellation-safe wait, and forwarded OverflowCount metrics.
// Depends: xUnit, RdpAudit.Core.Events.IEventPipe, RdpAudit.Core.Events.RawEventDto,
//          RdpAudit.Service.Infrastructure.RingBufferEventChannel,
//          RdpAudit.Service.Infrastructure.RingBufferEventPipe
// Extends: When adding new IEventPipe methods, add a fact here that exercises them against
//          the ring-buffer adapter — the interface contract must remain observably intact.

using RdpAudit.Core.Events;
using RdpAudit.Service.Infrastructure;
using Xunit;

namespace RdpAudit.Service.Tests;

public sealed class RingBufferEventPipeTests
{
	private static RawEventDto MakeDto(int eventId, string channel = "Security")
	{
		return new RawEventDto
		{
			EventId = eventId,
			Channel = channel,
			TimeUtc = DateTime.UtcNow,
			XmlPayload = "<Event/>",
		};
	}

	private static RingBufferEventPipe CreatePipe(int capacity = 16)
	{
		return new RingBufferEventPipe(new RingBufferEventChannel(capacity));
	}

	[Fact]
	public void TryWrite_TryRead_RoundTripsSingleDto()
	{
		IEventPipe pipe = CreatePipe();
		Assert.True(pipe.TryWrite(MakeDto(4625)));
		Assert.True(pipe.TryRead(out RawEventDto dto));
		Assert.Equal(4625, dto.EventId);
	}

	[Fact]
	public void TryRead_EmptyPipe_ReturnsFalse()
	{
		IEventPipe pipe = CreatePipe();
		Assert.False(pipe.TryRead(out _));
	}

	[Fact]
	public void Capacity_MatchesUnderlyingRing()
	{
		IEventPipe pipe = CreatePipe(capacity: 8);
		Assert.Equal(8, pipe.Capacity);
	}

	[Fact]
	public void OverflowCount_IncrementsOnRingOverflow()
	{
		IEventPipe pipe = CreatePipe(capacity: 4);

		// Fill the ring to capacity.
		Assert.True(pipe.TryWrite(MakeDto(1)));
		Assert.True(pipe.TryWrite(MakeDto(2)));
		Assert.True(pipe.TryWrite(MakeDto(3)));
		Assert.True(pipe.TryWrite(MakeDto(4)));

		Assert.Equal(0, pipe.OverflowCount);

		// The fifth write forces a DropOldest — TryWrite still returns false-by-contract to
		// signal overflow, but the DTO lands and OverflowCount ticks.
		pipe.TryWrite(MakeDto(5));
		Assert.Equal(1, pipe.OverflowCount);
	}

	[Fact]
	public async Task WaitToReadAsync_ReturnsTrueWhenDataAvailable()
	{
		IEventPipe pipe = CreatePipe();
		Assert.True(pipe.TryWrite(MakeDto(4625)));

		bool ready = await pipe.WaitToReadAsync(TimeSpan.FromMilliseconds(50), CancellationToken.None);

		Assert.True(ready);
	}

	[Fact]
	public async Task WaitToReadAsync_TimesOutOnEmptyPipe()
	{
		IEventPipe pipe = CreatePipe();

		bool ready = await pipe.WaitToReadAsync(TimeSpan.FromMilliseconds(30), CancellationToken.None);

		Assert.False(ready);
	}

	[Fact]
	public async Task WaitToReadAsync_CancellationExitsPromptly()
	{
		IEventPipe pipe = CreatePipe();
		using CancellationTokenSource cts = new();

		Task<bool> waitTask = pipe.WaitToReadAsync(TimeSpan.FromSeconds(30), cts.Token).AsTask();
		cts.CancelAfter(TimeSpan.FromMilliseconds(20));

		bool ready = await waitTask;

		Assert.False(ready);
	}

	[Fact]
	public async Task WaitToReadAsync_PrefetchedDto_IsReturnedByNextTryRead()
	{
		IEventPipe pipe = CreatePipe();
		RawEventDto expected = MakeDto(4624);
		Assert.True(pipe.TryWrite(expected));

		bool ready = await pipe.WaitToReadAsync(TimeSpan.FromMilliseconds(50), CancellationToken.None);
		Assert.True(ready);

		// The prefetch slot must return the SAME dto on the next TryRead — no double-consume,
		// no loss.
		Assert.True(pipe.TryRead(out RawEventDto actual));
		Assert.Equal(expected.EventId, actual.EventId);

		// And there is nothing left in the pipe.
		Assert.False(pipe.TryRead(out _));
	}

	[Fact]
	public async Task WaitToReadAsync_DoubleCall_IsIdempotentWhilePrefetchIsLoaded()
	{
		IEventPipe pipe = CreatePipe();
		Assert.True(pipe.TryWrite(MakeDto(4625)));

		Assert.True(await pipe.WaitToReadAsync(TimeSpan.FromMilliseconds(50), CancellationToken.None));
		Assert.True(await pipe.WaitToReadAsync(TimeSpan.FromMilliseconds(50), CancellationToken.None));

		// Only one DTO ever gets returned even though we asked twice.
		Assert.True(pipe.TryRead(out _));
		Assert.False(pipe.TryRead(out _));
	}

	[Fact]
	public void Ctor_NullChannel_Throws()
	{
		Assert.Throws<ArgumentNullException>(() => new RingBufferEventPipe((EventChannel)null!));
		Assert.Throws<ArgumentNullException>(() => new RingBufferEventPipe((RingBufferEventChannel)null!));
	}
}
