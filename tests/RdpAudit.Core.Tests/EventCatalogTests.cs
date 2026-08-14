/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 2.0.3
// File   : EventCatalogTests.cs
// Project: RdpAudit.Core.Tests (RdpAudit.Core.Tests)
// Purpose: Verifies catalog coverage, preset relationships, metadata lookup, and legacy enumeration contracts.
// Depends: EventCatalog, EventDescriptor, EventPreset, EventCriticality, xUnit
// Extends: Add contract coverage when introducing an event, preset, or descriptor metadata field.

using RdpAudit.Core.Events;
using Xunit;

namespace RdpAudit.Core.Tests;

public sealed class EventCatalogTests
{
	[Fact]
	public void All_ContainsCriticalLogonAndKerberosEvents()
	{
		Assert.Contains(EventCatalog.All, descriptor => descriptor.EventId == 4624);
		Assert.Contains(EventCatalog.All, descriptor => descriptor.EventId == 4625);
		Assert.Contains(EventCatalog.All, descriptor => descriptor.EventId == 4769);
		Assert.Contains(EventCatalog.All, descriptor => descriptor.EventId == 4688);
		Assert.Contains(EventCatalog.All, descriptor => descriptor.EventId == 1149);
	}

	[Fact]
	public void EveryEventId_IsUniqueAndResolvable()
	{
		HashSet<int> eventIds = [];
		foreach (EventDescriptor descriptor in EventCatalog.All)
		{
			Assert.True(eventIds.Add(descriptor.EventId), $"Duplicate event ID {descriptor.EventId} in the catalog.");
			Assert.True(EventCatalog.TryGet(descriptor.EventId, out EventDescriptor? found));
			Assert.Same(descriptor, found);
		}
	}

	[Fact]
	public void AllChannels_HasNoDuplicatesAndMatchesCatalogEntries()
	{
		HashSet<string> declared = new(StringComparer.OrdinalIgnoreCase);
		foreach (EventDescriptor descriptor in EventCatalog.All)
		{
			declared.Add(descriptor.Channel);
		}

		HashSet<string> exposed = new(EventCatalog.AllChannels(), StringComparer.OrdinalIgnoreCase);
		Assert.True(declared.SetEquals(exposed));
	}

	[Fact]
	public void EventIdsForChannel_ReturnsOnlyEventsOnThatChannel()
	{
		foreach (string channel in EventCatalog.AllChannels())
		{
			HashSet<int> expected = new();
			foreach (EventDescriptor descriptor in EventCatalog.All)
			{
				if (string.Equals(descriptor.Channel, channel, StringComparison.OrdinalIgnoreCase))
				{
					expected.Add(descriptor.EventId);
				}
			}

			HashSet<int> actual = new(EventCatalog.EventIdsForChannel(channel));
			Assert.True(expected.SetEquals(actual));
		}
	}

	[Fact]
	public void Presets_AreNestedAndFullContainsEveryCatalogEvent()
	{
		HashSet<int> minimal = new(EventCatalog.EventIdsByPreset(EventPreset.Minimal));
		HashSet<int> essential = new(EventCatalog.EventIdsByPreset(EventPreset.Essential));
		HashSet<int> full = new(EventCatalog.EventIdsByPreset(EventPreset.Full));

		Assert.NotEmpty(minimal);
		Assert.True(minimal.IsSubsetOf(essential));
		Assert.True(essential.IsSubsetOf(full));
		foreach (EventDescriptor descriptor in EventCatalog.All)
		{
			Assert.Contains(descriptor.EventId, full);
		}
	}

	[Fact]
	public void RequiredClosure_IncludesDependenciesAndIsIdempotent()
	{
		IReadOnlyList<int> once = EventCatalog.RequiredClosure([4624, 4778, 4624, 4779, 4778]);
		IReadOnlyList<int> twice = EventCatalog.RequiredClosure(once);

		Assert.Contains(4624, once);
		Assert.Contains(4778, once);
		Assert.Equal(once, twice);
		Assert.Equal(once.Count, new HashSet<int>(once).Count);
	}

	[Fact]
	public void ClassifyActiveSet_RecognizesNamedPresetsAndCustomSets()
	{
		Assert.Equal(EventPreset.Minimal, EventCatalog.ClassifyActiveSet(EventCatalog.EventIdsByPreset(EventPreset.Minimal)));
		Assert.Equal(EventPreset.Essential, EventCatalog.ClassifyActiveSet(EventCatalog.EventIdsByPreset(EventPreset.Essential)));
		Assert.Equal(EventPreset.Full, EventCatalog.ClassifyActiveSet(EventCatalog.EventIdsByPreset(EventPreset.Full)));

		List<int> custom = new(EventCatalog.EventIdsByPreset(EventPreset.Essential));
		custom.Remove(4740);
		custom.Add(4688);
		Assert.Equal(EventPreset.Custom, EventCatalog.ClassifyActiveSet(custom));
	}

	[Fact]
	public void ForensicCriticalEvents_AreCriticalAndRetainedForever()
	{
		Assert.Equal(EventCriticality.Critical, EventCatalog.CriticalityOf(4719));
		Assert.Equal(EventCriticality.Critical, EventCatalog.CriticalityOf(1102));
		Assert.Equal(0, EventCatalog.DefaultRetentionFor(4719));
		Assert.Equal(0, EventCatalog.DefaultRetentionFor(1102));
		Assert.Equal(-1, EventCatalog.DefaultRetentionFor(999_999));
	}

	[Theory]
	[InlineData(4624, EventCatalog.ChannelSecurity)]
	[InlineData(22, EventCatalog.ChannelTsLocal)]
	[InlineData(4778, EventCatalog.ChannelSecurity)]
	[InlineData(1150, EventCatalog.ChannelTsRemote)]
	[InlineData(1158, EventCatalog.ChannelTsRemote)]
	public void ExpandedEvents_AreAssignedToTheirCorrectChannel(int eventId, string expectedChannel)
	{
		Assert.True(EventCatalog.TryGet(eventId, out EventDescriptor? descriptor));
		Assert.Equal(expectedChannel, descriptor!.Channel);
	}

	[Fact]
	public void All_CoversTheSecuritySessionRemoteCoreAndGatewayWatchSets()
	{
		AssertChannelContains(EventCatalog.ChannelSecurity, [4624, 4625, 4634, 4647, 4648, 4672, 4719, 4720, 4724, 4732, 4740, 4768, 4769, 4771, 4776, 4778, 4779, 4825, 1102]);
		AssertChannelContains(EventCatalog.ChannelTsLocal, [21, 22, 23, 24, 25, 39, 40]);
		AssertChannelContains(EventCatalog.ChannelTsRemote, [1148, 1149, 261]);
		AssertChannelContains(EventCatalog.ChannelRdpCore, [65, 82, 131, 140, 141]);
		AssertChannelContains(EventCatalog.ChannelTsGateway, [302, 303, 304, 305]);
	}

	private static void AssertChannelContains(string channel, ReadOnlySpan<int> requiredIds)
	{
		HashSet<int> eventIds = new(EventCatalog.EventIdsForChannel(channel));
		foreach (int eventId in requiredIds)
		{
			Assert.Contains(eventId, eventIds);
		}
	}
}
