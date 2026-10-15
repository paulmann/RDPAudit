/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 2.0.0
// File   : EventLogWatcherEventSourceTests.cs
// Project: RdpAudit.Service.Tests (RdpAudit.Service.Tests)
// Purpose: Verifies the state machine, callback contract, and idempotency of
//          EventLogWatcherEventSource without requiring a live Windows Event Log. The tests
//          exercise the observable transitions (Idle → Running → Stopped, Running → Faulted)
//          and the guard rails around disposal / double-start / double-stop.
//          A live Windows-only smoke test lives in a separate integration project so the CI
//          matrix can skip it on Linux runners.
// Depends: xUnit, Microsoft.Extensions.Logging.Abstractions, RdpAudit.Core.Events,
//          RdpAudit.Service.EventSources.EventLogWatcherEventSource,
//          RdpAudit.Service.Infrastructure.RingBufferEventPipe / RingBufferEventChannel
// Extends: When adding a new EventSourceStatus, add a fact here to pin the transition into or
//          out of it. When adding a new IEventSource implementation, mirror this test file.

using Microsoft.Extensions.Logging.Abstractions;
using RdpAudit.Core.Events;
using RdpAudit.Service.EventSources;
using RdpAudit.Service.Infrastructure;
using Xunit;

namespace RdpAudit.Service.Tests;

public sealed class EventLogWatcherEventSourceTests
{
	private static RingBufferEventPipe CreatePipe(int capacity = 16)
	{
		return new RingBufferEventPipe(new RingBufferEventChannel(capacity));
	}

	private static EventLogWatcherEventSource CreateSource(
		IEventPipe? pipe = null,
		Action<string, string, long>? onBookmark = null,
		Action<string, Exception, bool>? onWatcherFault = null,
		string? initialBookmarkXml = null)
	{
		return new EventLogWatcherEventSource(
			channel: "Security",
			xpathQuery: "*",
			pipe: pipe ?? CreatePipe(),
			logger: NullLogger<EventLogWatcherEventSource>.Instance,
			initialBookmarkXml: initialBookmarkXml,
			onBookmark: onBookmark,
			onWatcherFault: onWatcherFault);
	}

	[Fact]
	public void Ctor_ExposesChannelNameAndPipe()
	{
		IEventPipe pipe = CreatePipe();
		using EventLogWatcherEventSource source = new(
			"Security", "*", pipe, NullLogger<EventLogWatcherEventSource>.Instance);

		Assert.Equal("Security", source.Name);
		Assert.Same(pipe, source.Pipe);
		Assert.Equal(EventSourceStatus.Idle, source.Status);
	}

	[Theory]
	[InlineData(null, "*")]
	[InlineData("", "*")]
	[InlineData("   ", "*")]
	[InlineData("Security", null)]
	[InlineData("Security", "")]
	[InlineData("Security", "   ")]
	public void Ctor_RejectsEmptyChannelOrQuery(string? channel, string? query)
	{
		Assert.ThrowsAny<ArgumentException>(() => new EventLogWatcherEventSource(
			channel!, query!, CreatePipe(), NullLogger<EventLogWatcherEventSource>.Instance));
	}

	[Fact]
	public void Ctor_RejectsNullPipe()
	{
		Assert.Throws<ArgumentNullException>(() => new EventLogWatcherEventSource(
			"Security", "*", null!, NullLogger<EventLogWatcherEventSource>.Instance));
	}

	[Fact]
	public void Ctor_RejectsNullLogger()
	{
		Assert.Throws<ArgumentNullException>(() => new EventLogWatcherEventSource(
			"Security", "*", CreatePipe(), null!));
	}

	[Fact]
	public async Task StopAsync_OnFreshSource_IsNoOp()
	{
		using EventLogWatcherEventSource source = CreateSource();
		List<EventSourceStatusChangedEventArgs> events = new();
		source.StatusChanged += (_, e) => events.Add(e);

		await source.StopAsync(CancellationToken.None);

		Assert.Equal(EventSourceStatus.Idle, source.Status);
		Assert.Empty(events);
	}

	[Fact]
	public void Dispose_OnFreshSource_DoesNotThrowOrRaise()
	{
		EventLogWatcherEventSource source = CreateSource();
		List<EventSourceStatusChangedEventArgs> events = new();
		source.StatusChanged += (_, e) => events.Add(e);

		source.Dispose();
		source.Dispose(); // idempotent second dispose

		Assert.Empty(events);
	}

	[Fact]
	public async Task StartAsync_OnDisposedSource_Throws()
	{
		EventLogWatcherEventSource source = CreateSource();
		source.Dispose();

		await Assert.ThrowsAsync<ObjectDisposedException>(async () =>
			await source.StartAsync(CancellationToken.None));
	}

	[Fact]
	public async Task StartAsync_CancelledToken_Throws()
	{
		using EventLogWatcherEventSource source = CreateSource();
		using CancellationTokenSource cts = new();
		cts.Cancel();

		await Assert.ThrowsAsync<OperationCanceledException>(async () =>
			await source.StartAsync(cts.Token));

		Assert.Equal(EventSourceStatus.Idle, source.Status);
	}

	[Fact]
	public async Task StartAsync_OnNonWindowsHost_TransitionsToFaulted()
	{
		// On Linux CI, EventLogQuery construction throws PlatformNotSupportedException. That is
		// exactly the failure surface a supervisor must observe: Status = Faulted plus the
		// fault callback fires exactly once with isCallback=false.
		if (OperatingSystem.IsWindows())
		{
			// This test only meaningfully asserts on non-Windows. On Windows, the Security
			// channel may or may not be readable depending on the runner's privileges, so we
			// skip the assertion side.
			return;
		}

		int faultCount = 0;
		string? capturedChannel = null;
		Exception? capturedException = null;
		bool? capturedIsCallback = null;

		using EventLogWatcherEventSource source = CreateSource(
			onWatcherFault: (ch, ex, cb) =>
			{
				Interlocked.Increment(ref faultCount);
				capturedChannel = ch;
				capturedException = ex;
				capturedIsCallback = cb;
			});

		List<EventSourceStatusChangedEventArgs> events = new();
		source.StatusChanged += (_, e) => events.Add(e);

		await Assert.ThrowsAnyAsync<Exception>(async () =>
			await source.StartAsync(CancellationToken.None));

		Assert.Equal(EventSourceStatus.Faulted, source.Status);
		Assert.Equal(1, faultCount);
		Assert.Equal("Security", capturedChannel);
		Assert.NotNull(capturedException);
		Assert.False(capturedIsCallback);

		Assert.Contains(events, e =>
			e.Previous == EventSourceStatus.Idle && e.Current == EventSourceStatus.Faulted);
	}

	[Fact]
	public async Task StopAsync_AfterFault_ReachesStopped()
	{
		if (OperatingSystem.IsWindows())
		{
			return; // see rationale in StartAsync_OnNonWindowsHost_TransitionsToFaulted
		}

		using EventLogWatcherEventSource source = CreateSource();
		try
		{
			await source.StartAsync(CancellationToken.None);
		}
		catch
		{
			// expected on Linux — the state machine must still land in Faulted
		}

		Assert.Equal(EventSourceStatus.Faulted, source.Status);

		await source.StopAsync(CancellationToken.None);

		Assert.Equal(EventSourceStatus.Stopped, source.Status);
	}

	[Fact]
	public void StatusChanged_SubscriberThatThrows_IsSwallowed()
	{
		if (OperatingSystem.IsWindows())
		{
			return; // exercising Faulted transition requires the non-Windows fault path
		}

		using EventLogWatcherEventSource source = CreateSource();
		source.StatusChanged += (_, _) => throw new InvalidOperationException("subscriber blew up");

		// The subscriber throwing must never propagate out of the source — StartAsync will
		// bubble the underlying watcher-construction failure, not the subscriber's exception.
		Exception thrown = Assert.ThrowsAny<Exception>(() =>
			source.StartAsync(CancellationToken.None).GetAwaiter().GetResult());

		Assert.IsNotType<InvalidOperationException>(thrown);
		Assert.Equal(EventSourceStatus.Faulted, source.Status);
	}

	[Fact]
	public async Task StopAsync_OnDisposedSource_IsSilent()
	{
		EventLogWatcherEventSource source = CreateSource();
		source.Dispose();

		await source.StopAsync(CancellationToken.None);
		// no throw, no state change observable — Status is still whatever Dispose set it to
	}

	[Fact]
	public void Ctor_AcceptsOptionalCallbacks()
	{
		Action<string, string, long> bookmark = (_, _, _) => { };
		Action<string, Exception, bool> fault = (_, _, _) => { };

		using EventLogWatcherEventSource source = new(
			"Security", "*", CreatePipe(), NullLogger<EventLogWatcherEventSource>.Instance,
			initialBookmarkXml: "<BookmarkList/>",
			onBookmark: bookmark,
			onWatcherFault: fault);

		Assert.Equal(EventSourceStatus.Idle, source.Status);
	}
}
