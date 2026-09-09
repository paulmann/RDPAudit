// File:    tests/RdpAudit.Service.Tests/HybridEventSourceFactoryTests.cs
// Module:  RdpAudit.Service.Tests
// Purpose: Contract tests for HybridEventSourceFactory. Verifies channel-by-channel routing
//          against EtwProviderMap: real-time capable channels go to EtwEventSourceFactory,
//          all others go to EventLogWatcherEventSourceFactory. Cross-platform: only inspects
//          the returned IEventSource type, never calls StartAsync (which is Windows-only).
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using Microsoft.Extensions.Logging.Abstractions;
using RdpAudit.Core.Events;
using RdpAudit.Service.EventSources;
using Xunit;

namespace RdpAudit.Service.Tests;

public class HybridEventSourceFactoryTests
{
	private static HybridEventSourceFactory NewFactory(IEventPipe pipe)
	{
		var etwFactory = new EtwEventSourceFactory(pipe, NullLoggerFactory.Instance);
		var eventLogFactory = new EventLogWatcherEventSourceFactory(pipe, NullLoggerFactory.Instance);
		return new HybridEventSourceFactory(
			etwFactory,
			eventLogFactory,
			NullLogger<HybridEventSourceFactory>.Instance);
	}

	private static IEventSource Create(HybridEventSourceFactory factory, string channel) =>
		factory.Create(
			channel: channel,
			xpathQuery: "*",
			bookmarkXml: null,
			onBookmark: (_, _, _) => { },
			onWatcherFault: (_, _, _) => { });

	[Theory]
	[InlineData("Microsoft-Windows-TerminalServices-LocalSessionManager/Operational")]
	[InlineData("Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational")]
	[InlineData("Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational")]
	[InlineData("Microsoft-Windows-TerminalServices-Gateway/Operational")]
	[InlineData("Microsoft-Windows-TerminalServices-RDPClient/Operational")]
	public void Create_RoutesRealTimeChannelsToEtw(string channel)
	{
		Assert.True(EtwProviderMap.IsRealTimeCapable(channel),
			$"Fixture requires {channel} to remain RealTimeCapable in EtwProviderMap.");

		var pipe = new CountingPipe();
		var factory = NewFactory(pipe);

		IEventSource source = Create(factory, channel);

		Assert.IsType<EtwEventSource>(source);
		Assert.Equal(channel, source.Name);
	}

	[Theory]
	[InlineData("Security")]
	[InlineData("System")]
	public void Create_RoutesNonRealTimeChannelsToEventLogWatcher(string channel)
	{
		Assert.False(EtwProviderMap.IsRealTimeCapable(channel),
			$"Fixture requires {channel} to remain non-RealTimeCapable in EtwProviderMap.");

		var pipe = new CountingPipe();
		var factory = NewFactory(pipe);

		IEventSource source = Create(factory, channel);

		Assert.IsType<EventLogWatcherEventSource>(source);
	}

	[Fact]
	public void Create_ChannelsUnknownToEtwProviderMap_FallBackToEventLogWatcher()
	{
		var pipe = new CountingPipe();
		var factory = NewFactory(pipe);

		IEventSource source = Create(factory, "Application");

		// Application is not registered in EtwProviderMap at all, so IsRealTimeCapable returns
		// false and we should fall back to the EventLogWatcher transport.
		Assert.IsType<EventLogWatcherEventSource>(source);
	}

	[Fact]
	public void Create_RejectsInvalidArguments()
	{
		var pipe = new CountingPipe();
		var factory = NewFactory(pipe);

		Assert.Throws<ArgumentException>(() =>
			factory.Create("", "*", null, (_, _, _) => { }, (_, _, _) => { }));
		Assert.Throws<ArgumentException>(() =>
			factory.Create("Application", "", null, (_, _, _) => { }, (_, _, _) => { }));
		Assert.Throws<ArgumentNullException>(() =>
			factory.Create("Application", "*", null, null!, (_, _, _) => { }));
		Assert.Throws<ArgumentNullException>(() =>
			factory.Create("Application", "*", null, (_, _, _) => { }, null!));
	}

	[Fact]
	public void Constructor_RejectsNullDependencies()
	{
		var pipe = new CountingPipe();
		var etwFactory = new EtwEventSourceFactory(pipe, NullLoggerFactory.Instance);
		var eventLogFactory = new EventLogWatcherEventSourceFactory(pipe, NullLoggerFactory.Instance);

		Assert.Throws<ArgumentNullException>(() =>
			new HybridEventSourceFactory(null!, eventLogFactory, NullLogger<HybridEventSourceFactory>.Instance));
		Assert.Throws<ArgumentNullException>(() =>
			new HybridEventSourceFactory(etwFactory, null!, NullLogger<HybridEventSourceFactory>.Instance));
		Assert.Throws<ArgumentNullException>(() =>
			new HybridEventSourceFactory(etwFactory, eventLogFactory, null!));
	}

	private sealed class CountingPipe : IEventPipe
	{
		public int Capacity => int.MaxValue;
		public long OverflowCount => 0;
		public bool TryWrite(RawEventDto dto) => true;
		public bool TryRead(out RawEventDto dto) { dto = default!; return false; }
		public ValueTask<bool> WaitToReadAsync(TimeSpan timeout, CancellationToken ct) =>
			ValueTask.FromResult(false);
	}
}
