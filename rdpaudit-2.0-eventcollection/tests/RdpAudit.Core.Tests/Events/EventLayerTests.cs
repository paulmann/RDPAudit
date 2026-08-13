/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 2.0.0
// File   : EventLayerTests.cs
// Project: RdpAudit.Core.Tests (RdpAudit.Core.Tests.Events)
// Purpose: Round-trip and stability tests for the EventLayer enum and its string parser.
//          Guards against silent renumbering (persisted rows compare against numeric values)
//          and label drift (Configurator UI groups by label).
// Depends: xUnit, RdpAudit.Core.Events
// Extends: When adding a new layer, add its numeric value to KnownLayers below and add a
//          catalog-coverage assertion if an event should be classified into it.

using RdpAudit.Core.Events;
using Xunit;

namespace RdpAudit.Core.Tests.Events;

public sealed class EventLayerTests
{
	// Numeric values that must remain stable — persisted rows reference them.
	private static readonly (EventLayer Value, byte Numeric, string Label)[] KnownLayers =
	{
		(EventLayer.Unknown,        0,  "Unknown"),
		(EventLayer.Authentication, 1,  "Authentication"),
		(EventLayer.Kerberos,       2,  "Kerberos"),
		(EventLayer.Session,        3,  "Session"),
		(EventLayer.Reconnect,      4,  "Reconnect"),
		(EventLayer.Network,        5,  "Network"),
		(EventLayer.RdpCore,        6,  "RdpCore"),
		(EventLayer.Process,        7,  "Process"),
		(EventLayer.Persistence,    8,  "Persistence"),
		(EventLayer.Account,        9,  "Account"),
		(EventLayer.Tampering,      10, "Tampering"),
		(EventLayer.ObjectAccess,   11, "ObjectAccess"),
		(EventLayer.Logoff,         12, "Logoff"),
		(EventLayer.Gateway,        13, "Gateway"),
		(EventLayer.Client,         14, "Client"),
		(EventLayer.System,         15, "System"),
	};

	[Fact]
	public void NumericValues_AreStable()
	{
		// Persisted RawEvents.EventLayer references the numeric value. Anyone renumbering
		// an existing enum member will break this test on purpose.
		foreach ((EventLayer value, byte numeric, _) in KnownLayers)
		{
			Assert.Equal(numeric, (byte)value);
		}
	}

	[Fact]
	public void ToLabel_RoundTripsThroughParse()
	{
		foreach ((EventLayer value, _, string label) in KnownLayers)
		{
			Assert.Equal(label, EventLayers.ToLabel(value));
			Assert.Equal(value, EventLayers.Parse(label));
		}
	}

	[Fact]
	public void Parse_IsCaseInsensitive()
	{
		Assert.Equal(EventLayer.Authentication, EventLayers.Parse("authentication"));
		Assert.Equal(EventLayer.Authentication, EventLayers.Parse("AUTHENTICATION"));
		Assert.Equal(EventLayer.RdpCore, EventLayers.Parse("rdpcore"));
	}

	[Fact]
	public void Parse_ReturnsUnknown_ForNullOrEmptyOrUnrecognised()
	{
		Assert.Equal(EventLayer.Unknown, EventLayers.Parse(null));
		Assert.Equal(EventLayer.Unknown, EventLayers.Parse(string.Empty));
		Assert.Equal(EventLayer.Unknown, EventLayers.Parse("NotARealLayer"));
	}

	[Fact]
	public void EventDescriptor_LayerKind_MatchesStringLayer()
	{
		// Cover every known layer through the catalog so a mistyped Layer string on a
		// catalog entry surfaces immediately.
		foreach (EventDescriptor d in EventCatalog.All)
		{
			EventLayer expected = EventLayers.Parse(d.Layer);
			Assert.Equal(expected, d.LayerKind);
		}
	}

	[Fact]
	public void EventCatalog_ClassifiesCoreEventsIntoExpectedLayers()
	{
		Assert.Equal(EventLayer.Authentication, EventCatalog.LayerKindOf(4624));
		Assert.Equal(EventLayer.Authentication, EventCatalog.LayerKindOf(4625));
		Assert.Equal(EventLayer.Session,        EventCatalog.LayerKindOf(21));
		Assert.Equal(EventLayer.Session,        EventCatalog.LayerKindOf(22));
		Assert.Equal(EventLayer.Reconnect,      EventCatalog.LayerKindOf(4778));
		Assert.Equal(EventLayer.Reconnect,      EventCatalog.LayerKindOf(4779));
		Assert.Equal(EventLayer.Network,        EventCatalog.LayerKindOf(1149));
		Assert.Equal(EventLayer.Network,        EventCatalog.LayerKindOf(1158));
		Assert.Equal(EventLayer.Account,        EventCatalog.LayerKindOf(4740));
		Assert.Equal(EventLayer.Tampering,      EventCatalog.LayerKindOf(4719));
		Assert.Equal(EventLayer.Tampering,      EventCatalog.LayerKindOf(1102));
	}

	[Fact]
	public void EventCatalog_LayerKindOf_ReturnsUnknown_ForMissingEventId()
	{
		Assert.Equal(EventLayer.Unknown, EventCatalog.LayerKindOf(999_999));
		Assert.Equal("Unknown", EventCatalog.LayerOf(999_999));
	}
}
