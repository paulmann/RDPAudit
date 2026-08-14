// File:    tests/RdpAudit.Service.Tests/EtwEventSourceSkeletonTests.cs
// Module:  RdpAudit.Service.Tests
// Purpose: Locks down the v0.1.0 EtwEventSource skeleton behaviour: StartAsync transitions
//          to Unsupported (with a StatusChanged fire), StopAsync transitions to Stopped, no
//          DTO ever reaches the pipe, and the source refuses null / whitespace constructor
//          arguments. Runs on any OS because the skeleton never touches native ETW APIs;
//          real TraceEventSession integration tests will be Windows-only when they land in
//          the commit-3 payload work.
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System.Runtime.Versioning;
using Microsoft.Extensions.Logging.Abstractions;
using RdpAudit.Core.Events;
using RdpAudit.Service.EventSources;
using Xunit;

namespace RdpAudit.Service.Tests;

[SupportedOSPlatform("windows")]
public class EtwEventSourceSkeletonTests
{
	[Fact]
	public async Task StartAsync_TransitionsToUnsupported_AndFiresStatusChanged()
	{
		CountingPipe pipe = new();
		EtwEventSource source = new("RdpAudit-Security", pipe, NullLogger<EtwEventSource>.Instance);

		List<EventSourceStatusChangedEventArgs> transitions = new();
		source.StatusChanged += (_, args) => transitions.Add(args);

		Assert.Equal(EventSourceStatus.Idle, source.Status);

		await source.StartAsync(CancellationToken.None);

		Assert.Equal(EventSourceStatus.Unsupported, source.Status);
		Assert.Single(transitions);
		Assert.Equal(EventSourceStatus.Idle, transitions[0].Previous);
		Assert.Equal(EventSourceStatus.Unsupported, transitions[0].Current);
		Assert.NotNull(transitions[0].Reason);
	}

	[Fact]
	public async Task StopAsync_TransitionsToStopped_EvenWhenNotStarted()
	{
		CountingPipe pipe = new();
		EtwEventSource source = new("RdpAudit-Security", pipe, NullLogger<EtwEventSource>.Instance);

		await source.StopAsync(CancellationToken.None);

		Assert.Equal(EventSourceStatus.Stopped, source.Status);
	}

	[Fact]
	public async Task Skeleton_DoesNotWriteAnyDtoToPipe()
	{
		CountingPipe pipe = new();
		EtwEventSource source = new("RdpAudit-Security", pipe, NullLogger<EtwEventSource>.Instance);

		await source.StartAsync(CancellationToken.None);
		await source.StopAsync(CancellationToken.None);

		Assert.Equal(0, pipe.Writes);
	}

	[Fact]
	public void Constructor_RejectsInvalidArguments()
	{
		CountingPipe pipe = new();

		Assert.Throws<ArgumentException>(() =>
			new EtwEventSource("", pipe, NullLogger<EtwEventSource>.Instance));
		Assert.Throws<ArgumentException>(() =>
			new EtwEventSource("   ", pipe, NullLogger<EtwEventSource>.Instance));
		Assert.Throws<ArgumentNullException>(() =>
			new EtwEventSource("RdpAudit-Security", null!, NullLogger<EtwEventSource>.Instance));
		Assert.Throws<ArgumentNullException>(() =>
			new EtwEventSource("RdpAudit-Security", pipe, null!));
	}

	private sealed class CountingPipe : IEventPipe
	{
		public int Writes;
		public int Capacity => int.MaxValue;
		public long OverflowCount => 0;

		public bool TryWrite(RawEventDto dto)
		{
			Interlocked.Increment(ref Writes);
			return true;
		}

		public bool TryRead(out RawEventDto dto)
		{
			dto = default!;
			return false;
		}

		public ValueTask<bool> WaitToReadAsync(TimeSpan timeout, CancellationToken ct) =>
			ValueTask.FromResult(false);
	}
}
