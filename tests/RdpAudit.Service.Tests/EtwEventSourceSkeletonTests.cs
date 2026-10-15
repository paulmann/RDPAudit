// File:    tests/RdpAudit.Service.Tests/EtwEventSourceSkeletonTests.cs
// Module:  RdpAudit.Service.Tests
// Purpose: v0.2.0 EtwEventSource contract tests. Constructor validation runs on any OS; the
//          full TraceEventSession lifecycle test is Windows-only and skips silently on other
//          platforms so the suite stays green on Linux CI.
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using Microsoft.Extensions.Logging.Abstractions;
using RdpAudit.Core.Events;
using RdpAudit.Service.EventSources;
using Xunit;

namespace RdpAudit.Service.Tests;

public class EtwEventSourceSkeletonTests
{
	private const string RealTimeChannel = "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational";
	private const string NonRealTimeChannel = "Security";

	[Fact]
	public void Constructor_RejectsNonRealTimeChannel()
	{
		var pipe = new CountingPipe();

		var ex = Assert.Throws<ArgumentException>(() =>
			new EtwEventSource(NonRealTimeChannel, pipe, NullLogger<EtwEventSource>.Instance));
		Assert.Contains("real-time", ex.Message, StringComparison.OrdinalIgnoreCase);
	}

	[Fact]
	public void Constructor_RejectsUnknownChannel()
	{
		var pipe = new CountingPipe();

		Assert.Throws<ArgumentException>(() =>
			new EtwEventSource("Definitely-Not-A-Channel", pipe, NullLogger<EtwEventSource>.Instance));
	}

	[Fact]
	public void Constructor_RejectsInvalidArguments()
	{
		var pipe = new CountingPipe();

		Assert.Throws<ArgumentException>(() =>
			new EtwEventSource("", pipe, NullLogger<EtwEventSource>.Instance));
		Assert.Throws<ArgumentException>(() =>
			new EtwEventSource("   ", pipe, NullLogger<EtwEventSource>.Instance));
		Assert.Throws<ArgumentNullException>(() =>
			new EtwEventSource(RealTimeChannel, null!, NullLogger<EtwEventSource>.Instance));
		Assert.Throws<ArgumentNullException>(() =>
			new EtwEventSource(RealTimeChannel, pipe, null!));
	}

	[Fact]
	public void Constructor_OnRealTimeChannel_TransitionsToIdle_AndDoesNotWrite()
	{
		if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
		{
			// EtwEventSource is [SupportedOSPlatform("windows")]; do not exercise it on
			// non-Windows CI runners.
			return;
		}

		RunConstructorSmoke();
	}

	[SupportedOSPlatform("windows")]
	private static void RunConstructorSmoke()
	{
		var pipe = new CountingPipe();
		var source = new EtwEventSource(
			RealTimeChannel,
			pipe,
			NullLogger<EtwEventSource>.Instance);

		Assert.Equal(EventSourceStatus.Idle, source.Status);
		Assert.Same(pipe, source.Pipe);
		Assert.Equal(RealTimeChannel, source.Name);
		Assert.Equal(0, pipe.Writes);
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
