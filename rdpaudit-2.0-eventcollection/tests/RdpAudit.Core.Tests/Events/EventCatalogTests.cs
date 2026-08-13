/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 2.0.0
// File   : EventCatalogTests.cs
// Project: RdpAudit.Core.Tests (RdpAudit.Core.Tests.Events)
// Purpose: Guardrail tests for the extended EventCatalog: preset nesting, required-closure
//          idempotence, uniqueness of event ids, criticality invariants, and backward
//          compatibility of the legacy AllChannels/EventIdsForChannel API.
// Depends: xUnit, RdpAudit.Core.Events
// Extends: When adding a new descriptor field, add a schema-drift test here so a partial
//          initializer that forgets to set the field is caught in CI.

using RdpAudit.Core.Events;
using Xunit;

namespace RdpAudit.Core.Tests.Events;

public sealed class EventCatalogTests
{
	[Fact]
	public void EveryEventId_IsUnique()
	{
		HashSet<int> seen = new();
		foreach (EventDescriptor d in EventCatalog.All)
		{
			Assert.True(seen.Add(d.EventId), $"Duplicate event id {d.EventId} in catalog");
		}
	}

	[Fact]
	public void TryGet_ResolvesEveryDescriptor()
	{
		foreach (EventDescriptor d in EventCatalog.All)
		{
			Assert.True(EventCatalog.TryGet(d.EventId, out EventDescriptor? found));
			Assert.Equal(d.EventId, found!.EventId);
			Assert.Same(d, found);
		}
	}

	[Fact]
	public void PresetNesting_MinimalIsSubsetOfEssential_EssentialIsSubsetOfFull()
	{
		HashSet<int> minimal = new(EventCatalog.EventIdsByPreset(EventPreset.Minimal));
		HashSet<int> essential = new(EventCatalog.EventIdsByPreset(EventPreset.Essential));
		HashSet<int> full = new(EventCatalog.EventIdsByPreset(EventPreset.Full));

		Assert.True(minimal.IsSubsetOf(essential), "Minimal must be a subset of Essential");
		Assert.True(essential.IsSubsetOf(full), "Essential must be a subset of Full");
		Assert.True(minimal.Count > 0, "Minimal cannot be empty");
	}

	[Fact]
	public void FullPreset_ContainsEveryEventInTheCatalog()
	{
		HashSet<int> full = new(EventCatalog.EventIdsByPreset(EventPreset.Full));
		foreach (EventDescriptor d in EventCatalog.All)
		{
			Assert.True(full.Contains(d.EventId),
				$"Event {d.EventId} is in the catalog but not in the Full preset");
		}
	}

	[Fact]
	public void MinimalPreset_ContainsCoreSecurityEvents()
	{
		HashSet<int> minimal = new(EventCatalog.EventIdsByPreset(EventPreset.Minimal));

		Assert.Contains(4624, minimal); // Successful logon
		Assert.Contains(4625, minimal); // Failed logon
		Assert.Contains(4740, minimal); // Account locked out
		Assert.Contains(21, minimal);   // Session logon succeeded
	}

	[Fact]
	public void RequiredClosure_IncludesDependencies()
	{
		IReadOnlyList<int> closure = EventCatalog.RequiredClosure(new[] { 4778 });

		Assert.Contains(4778, closure);
		Assert.Contains(4624, closure);
	}

	[Fact]
	public void RequiredClosure_IsIdempotent_AndDeduplicates()
	{
		int[] seeds = { 4624, 4778, 4624, 4779, 4778 };
		IReadOnlyList<int> once = EventCatalog.RequiredClosure(seeds);
		IReadOnlyList<int> twice = EventCatalog.RequiredClosure(once);

		Assert.Equal(once.Count, twice.Count);
		Assert.Equal(once, twice);
		Assert.Equal(once.Count, new HashSet<int>(once).Count);
	}

	[Fact]
	public void ClassifyActiveSet_MatchesEachNamedPreset()
	{
		Assert.Equal(EventPreset.Minimal,
			EventCatalog.ClassifyActiveSet(EventCatalog.EventIdsByPreset(EventPreset.Minimal)));
		Assert.Equal(EventPreset.Essential,
			EventCatalog.ClassifyActiveSet(EventCatalog.EventIdsByPreset(EventPreset.Essential)));
		Assert.Equal(EventPreset.Full,
			EventCatalog.ClassifyActiveSet(EventCatalog.EventIdsByPreset(EventPreset.Full)));
	}

	[Fact]
	public void ClassifyActiveSet_ReturnsCustom_WhenSetDivergesFromEveryPreset()
	{
		List<int> divergent = new(EventCatalog.EventIdsByPreset(EventPreset.Essential)) { 4688 };
		divergent.Remove(4740);

		Assert.Equal(EventPreset.Custom, EventCatalog.ClassifyActiveSet(divergent));
	}

	[Fact]
	public void ForensicCriticalEvents_AreKeptForever()
	{
		// Audit-policy tampering and log clearing must never be pruned.
		Assert.Equal(0, EventCatalog.DefaultRetentionFor(4719));
		Assert.Equal(0, EventCatalog.DefaultRetentionFor(1102));

		Assert.Equal(EventCriticality.Critical, EventCatalog.CriticalityOf(4719));
		Assert.Equal(EventCriticality.Critical, EventCatalog.CriticalityOf(1102));
	}

	[Fact]
	public void NewEventIds_ArePresentAndOnCorrectChannels()
	{
		AssertEventOnChannel(22, EventCatalog.ChannelTsLocal);
		AssertEventOnChannel(39, EventCatalog.ChannelTsLocal);
		AssertEventOnChannel(40, EventCatalog.ChannelTsLocal);
		AssertEventOnChannel(4778, EventCatalog.ChannelSecurity);
		AssertEventOnChannel(4779, EventCatalog.ChannelSecurity);
		AssertEventOnChannel(1150, EventCatalog.ChannelTsRemote);
		AssertEventOnChannel(1158, EventCatalog.ChannelTsRemote);
	}

	[Fact]
	public void LegacyApi_AllChannels_StillEnumeratesEveryChannelInUse()
	{
		HashSet<string> declared = new(StringComparer.OrdinalIgnoreCase);
		foreach (EventDescriptor d in EventCatalog.All)
		{
			declared.Add(d.Channel);
		}

		HashSet<string> exposed = new(EventCatalog.AllChannels(), StringComparer.OrdinalIgnoreCase);
		Assert.Equal(declared, exposed);
	}

	[Fact]
	public void LegacyApi_EventIdsForChannel_MatchesCatalogFilter()
	{
		foreach (string channel in EventCatalog.AllChannels())
		{
			HashSet<int> expected = new();
			foreach (EventDescriptor d in EventCatalog.All)
			{
				if (string.Equals(d.Channel, channel, StringComparison.OrdinalIgnoreCase))
				{
					expected.Add(d.EventId);
				}
			}

			HashSet<int> actual = new(EventCatalog.EventIdsForChannel(channel));
			Assert.Equal(expected, actual);
		}
	}

	[Fact]
	public void DefaultRetentionFor_UnknownEventId_ReturnsSentinel()
	{
		Assert.Equal(-1, EventCatalog.DefaultRetentionFor(999_999));
	}

	private static void AssertEventOnChannel(int eventId, string channel)
	{
		Assert.True(EventCatalog.TryGet(eventId, out EventDescriptor? d),
			$"Event {eventId} missing from catalog");
		Assert.Equal(channel, d!.Channel);
	}
}
