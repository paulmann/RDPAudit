/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 2.0.0
// File   : EventSourceStatusChangedEventArgsTests.cs
// Project: RdpAudit.Core.Tests (RdpAudit.Core.Tests.Events)
// Purpose: Contract tests for the EventSourceStatusChangedEventArgs record — pins the
//          constructor arity, ordering, and TimestampUtc "instant of construction" semantics
//          so downstream subscribers can reason about ordering even when dispatch is deferred.
// Depends: xUnit, RdpAudit.Core.Events.EventSourceStatus, EventSourceStatusChangedEventArgs
// Extends: When adding a new state to EventSourceStatus, add a fact here that constructs the
//          args from the new state and asserts round-trip.

using RdpAudit.Core.Events;
using Xunit;

namespace RdpAudit.Core.Tests.Events;

public sealed class EventSourceStatusChangedEventArgsTests
{
	[Fact]
	public void Ctor_PropertiesRoundTrip()
	{
		DateTime before = DateTime.UtcNow;
		EventSourceStatusChangedEventArgs args = new(
			previous: EventSourceStatus.Idle,
			current: EventSourceStatus.Running,
			reason: "test");
		DateTime after = DateTime.UtcNow;

		Assert.Equal(EventSourceStatus.Idle, args.Previous);
		Assert.Equal(EventSourceStatus.Running, args.Current);
		Assert.Equal("test", args.Reason);
		Assert.InRange(args.TimestampUtc, before, after);
	}

	[Fact]
	public void Ctor_ReasonDefaultsToNull()
	{
		EventSourceStatusChangedEventArgs args = new(
			EventSourceStatus.Running,
			EventSourceStatus.Restarting);
		Assert.Null(args.Reason);
	}

	[Theory]
	[InlineData(EventSourceStatus.Idle, EventSourceStatus.Running)]
	[InlineData(EventSourceStatus.Running, EventSourceStatus.Restarting)]
	[InlineData(EventSourceStatus.Restarting, EventSourceStatus.Running)]
	[InlineData(EventSourceStatus.Running, EventSourceStatus.Stopped)]
	[InlineData(EventSourceStatus.Idle, EventSourceStatus.Unsupported)]
	[InlineData(EventSourceStatus.Running, EventSourceStatus.Faulted)]
	public void Ctor_AllValidTransitionsSurfaceIntact(EventSourceStatus prev, EventSourceStatus curr)
	{
		EventSourceStatusChangedEventArgs args = new(prev, curr, reason: null);
		Assert.Equal(prev, args.Previous);
		Assert.Equal(curr, args.Current);
	}

	[Fact]
	public void EventSourceStatus_HasStableEnumValues()
	{
		// Wire-order guard: these values are baked into observability tables and MUST NOT be
		// renumbered. When adding a new state, append; never insert in the middle.
		Assert.Equal(0, (int)EventSourceStatus.Idle);
		Assert.Equal(1, (int)EventSourceStatus.Running);
		Assert.Equal(2, (int)EventSourceStatus.Restarting);
		Assert.Equal(3, (int)EventSourceStatus.Stopped);
		Assert.Equal(4, (int)EventSourceStatus.Unsupported);
		Assert.Equal(5, (int)EventSourceStatus.Faulted);
	}
}
