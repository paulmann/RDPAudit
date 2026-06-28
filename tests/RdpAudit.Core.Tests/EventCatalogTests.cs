// File:    tests/RdpAudit.Core.Tests/EventCatalogTests.cs
// Module:  RdpAudit.Core.Tests
// Purpose: Smoke tests over the EventCatalog metadata.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using RdpAudit.Core.Events;
using Xunit;

namespace RdpAudit.Core.Tests;

/// <summary>Smoke tests over the EventCatalog metadata.</summary>
public class EventCatalogTests
{
	[Fact]
	public void All_ContainsCriticalLogonAndKerberosEvents()
	{
		Assert.Contains(EventCatalog.All, d => d.EventId == 4624);
		Assert.Contains(EventCatalog.All, d => d.EventId == 4625);
		Assert.Contains(EventCatalog.All, d => d.EventId == 4769);
		Assert.Contains(EventCatalog.All, d => d.EventId == 4688);
		Assert.Contains(EventCatalog.All, d => d.EventId == 1149);
	}

	[Fact]
	public void AllChannels_HasNoDuplicates()
	{
		List<string> channels = EventCatalog.AllChannels().ToList();
		Assert.Equal(channels.Count, channels.Distinct(StringComparer.OrdinalIgnoreCase).Count());
	}

	[Fact]
	public void EventIdsForChannel_ReturnsOnlyChannelEvents()
	{
		IEnumerable<int> ids = EventCatalog.EventIdsForChannel(EventCatalog.ChannelTsLocal);
		Assert.Contains(21, ids);
		Assert.DoesNotContain(4624, ids);
	}

	[Fact]
	public void All_CoversV3SecuritySet()
	{
		// Detect_Attack_Strategy_v3.md §5.2 — every Security id must be live-watched so the
		// pipeline never relies on backfill alone for visibility. Pin the v3 set here.
		int[] required = { 4624, 4625, 4634, 4647, 4648, 4672, 4719, 4720, 4724, 4732, 4740,
			4768, 4769, 4771, 4776, 4778, 4779, 4825, 1102 };
		IEnumerable<int> securityIds = EventCatalog.EventIdsForChannel(EventCatalog.ChannelSecurity);
		foreach (int id in required)
		{
			Assert.Contains(id, securityIds);
		}
	}

	[Fact]
	public void All_CoversV3LocalSessionManagerSet()
	{
		int[] required = { 21, 22, 23, 24, 25, 39, 40 };
		IEnumerable<int> ids = EventCatalog.EventIdsForChannel(EventCatalog.ChannelTsLocal);
		foreach (int id in required)
		{
			Assert.Contains(id, ids);
		}
	}

	[Fact]
	public void All_CoversV3RemoteConnectionManagerSet()
	{
		int[] required = { 1148, 1149, 261 };
		IEnumerable<int> ids = EventCatalog.EventIdsForChannel(EventCatalog.ChannelTsRemote);
		foreach (int id in required)
		{
			Assert.Contains(id, ids);
		}
	}

	[Fact]
	public void All_CoversV3RdpCoreTsSet()
	{
		int[] required = { 65, 82, 131, 140, 141 };
		IEnumerable<int> ids = EventCatalog.EventIdsForChannel(EventCatalog.ChannelRdpCore);
		foreach (int id in required)
		{
			Assert.Contains(id, ids);
		}
	}

	[Fact]
	public void All_CoversV3GatewaySet()
	{
		int[] required = { 302, 303, 304, 305 };
		IEnumerable<int> ids = EventCatalog.EventIdsForChannel(EventCatalog.ChannelTsGateway);
		foreach (int id in required)
		{
			Assert.Contains(id, ids);
		}
	}
}
