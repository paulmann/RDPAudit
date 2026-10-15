// File:    tests/RdpAudit.Service.Tests/UtcTimestampEnricherTests.cs
// Module:  RdpAudit.Service.Tests
// Purpose: Pins the Serilog enricher that provides the UTC 'UtcTimestamp' property consumed by
//          the DEBUG text mirror's output template ({UtcTimestamp:...'Z'}). The built-in
//          {Timestamp} token reads LogEvent.Timestamp directly, so the enricher must add a
//          property with a distinct name. The event's original timestamp must never be
//          mutated, and events already captured at offset zero still get the property.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System;
using RdpAudit.Service.Infrastructure;
using Serilog.Core;
using Serilog.Events;
using Xunit;

namespace RdpAudit.Service.Tests;

public sealed class UtcTimestampEnricherTests
{
	private static readonly UtcTimestampEnricher Enricher = new();
	private static readonly ILogEventPropertyFactory PropertyFactory = new SimplePropertyFactory();

	private static LogEvent CreateEvent(DateTimeOffset timestamp) =>
		new(timestamp, LogEventLevel.Information, null, MessageTemplate.Empty, Array.Empty<LogEventProperty>());

	[Fact]
	public void Enrich_AddsUtcTimestampProperty_WithZeroOffset()
	{
		DateTimeOffset local = new(2026, 8, 25, 23, 5, 11, TimeSpan.FromHours(3)); // +03:00
		LogEvent evt = CreateEvent(local);

		Enricher.Enrich(evt, PropertyFactory);

		Assert.True(evt.Properties.TryGetValue("UtcTimestamp", out LogEventPropertyValue? value));
		DateTimeOffset utc = Assert.IsType<ScalarValue>(value).Value is DateTimeOffset dto
			? dto
			: throw new Xunit.Sdk.XunitException("UtcTimestamp must be a DateTimeOffset ScalarValue.");
		Assert.Equal(TimeSpan.Zero, utc.Offset);
		Assert.Equal(local.UtcDateTime, utc.UtcDateTime);
	}

	[Fact]
	public void Enrich_PreservesOriginalTimestamp()
	{
		DateTimeOffset local = new(2026, 8, 25, 23, 5, 11, TimeSpan.FromHours(3)); // +03:00
		LogEvent evt = CreateEvent(local);

		Enricher.Enrich(evt, PropertyFactory);

		Assert.Equal(local, evt.Timestamp);
		Assert.Equal(local.Offset, evt.Timestamp.Offset);
	}

	[Fact]
	public void Enrich_AlreadyUtcTimestamp_StillAddsProperty()
	{
		DateTimeOffset utc = new(2026, 8, 25, 20, 5, 11, TimeSpan.Zero);
		LogEvent evt = CreateEvent(utc);

		Enricher.Enrich(evt, PropertyFactory);

		Assert.True(evt.Properties.TryGetValue("UtcTimestamp", out LogEventPropertyValue? value));
		Assert.Equal(utc, Assert.IsType<ScalarValue>(value).Value is DateTimeOffset dto
			? dto
			: throw new Xunit.Sdk.XunitException("UtcTimestamp must be a DateTimeOffset ScalarValue."));
	}

	/// <summary>Minimal ILogEventPropertyFactory so the enricher is exercised in isolation.
	/// Serilog's own <see cref="Serilog.Core.Logger"/> does not implement the factory seam.</summary>
	private sealed class SimplePropertyFactory : ILogEventPropertyFactory
	{
		public LogEventProperty CreateProperty(string name, object? value, bool destructureObjects = false)
			=> new(name, new ScalarValue(value));
	}
}
