/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 2.0.3
// File   : EventLayerTests.cs
// Project: RdpAudit.Core.Tests (RdpAudit.Core.Tests.Events)
// Purpose: Protects the persisted event-layer numeric and label contracts.
// Depends: EventCatalog, EventDescriptor, EventLayer, EventLayers, xUnit
// Extends: Add each new persisted layer to KnownLayers and the catalog coverage assertions.

using RdpAudit.Core.Events;
using Xunit;

namespace RdpAudit.Core.Tests.Events;

public sealed class EventLayerTests
{
	private static readonly (EventLayer Value, byte Numeric, string Label)[] KnownLayers =
	[
		(EventLayer.Unknown, 0, "Unknown"),
		(EventLayer.Authentication, 1, "Authentication"),
		(EventLayer.Kerberos, 2, "Kerberos"),
		(EventLayer.Session, 3, "Session"),
		(EventLayer.Reconnect, 4, "Reconnect"),
		(EventLayer.Network, 5, "Network"),
		(EventLayer.RdpCore, 6, "RdpCore"),
		(EventLayer.Process, 7, "Process"),
		(EventLayer.Persistence, 8, "Persistence"),
		(EventLayer.Account, 9, "Account"),
		(EventLayer.Tampering, 10, "Tampering"),
		(EventLayer.ObjectAccess, 11, "ObjectAccess"),
		(EventLayer.Logoff, 12, "Logoff"),
		(EventLayer.Gateway, 13, "Gateway"),
		(EventLayer.Client, 14, "Client"),
		(EventLayer.System, 15, "System"),
	];

	[Fact]
	public void NumericValuesAndLabels_AreStableAndRoundTrip()
	{
		foreach ((EventLayer value, byte numeric, string label) in KnownLayers)
		{
			Assert.Equal(numeric, (byte)value);
			Assert.Equal(label, EventLayers.ToLabel(value));
			Assert.Equal(value, EventLayers.Parse(label));
		}
	}

	[Fact]
	public void Parse_IsCaseInsensitiveAndReturnsUnknownForInvalidValues()
	{
		Assert.Equal(EventLayer.Authentication, EventLayers.Parse("authentication"));
		Assert.Equal(EventLayer.RdpCore, EventLayers.Parse("RDPCORE"));
		Assert.Equal(EventLayer.Unknown, EventLayers.Parse(null));
		Assert.Equal(EventLayer.Unknown, EventLayers.Parse(string.Empty));
		Assert.Equal(EventLayer.Unknown, EventLayers.Parse("NotALayer"));
	}

	[Fact]
	public void CatalogDescriptorLayerKinds_AgreeWithTheirStringLayers()
	{
		foreach (EventDescriptor descriptor in EventCatalog.All)
		{
			Assert.Equal(EventLayers.Parse(descriptor.Layer), descriptor.LayerKind);
		}
	}

	[Theory]
	[InlineData(4624, EventLayer.Authentication)]
	[InlineData(21, EventLayer.Session)]
	[InlineData(4778, EventLayer.Reconnect)]
	[InlineData(1149, EventLayer.Network)]
	[InlineData(4740, EventLayer.Account)]
	[InlineData(4719, EventLayer.Tampering)]
	public void Catalog_ClassifiesRepresentativeEvents(int eventId, EventLayer expected)
	{
		Assert.Equal(expected, EventCatalog.LayerKindOf(eventId));
	}

	[Fact]
	public void Catalog_ReturnsUnknownForAnUncataloguedEvent()
	{
		Assert.Equal(EventLayer.Unknown, EventCatalog.LayerKindOf(999_999));
		Assert.Equal("Unknown", EventCatalog.LayerOf(999_999));
	}
}
