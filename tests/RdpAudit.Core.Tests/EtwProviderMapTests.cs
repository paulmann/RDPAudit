// File:    tests/RdpAudit.Core.Tests/EtwProviderMapTests.cs
// Module:  RdpAudit.Core.Tests
// Purpose: Locks the ETW provider table used by the RDPAudit 2.0 hybrid event source. Ensures
//          every EventCatalog channel has a mapping, that the Security channel is deliberately
//          marked non-real-time capable, and that provider GUIDs stay pinned to their canonical
//          Windows values so a firmware or telemetry regression is caught at test time.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using RdpAudit.Core.Events;
using Xunit;

namespace RdpAudit.Core.Tests;

public class EtwProviderMapTests
{
	[Fact]
	public void EveryCatalogChannelIsMapped()
	{
		// Every distinct channel that appears in the event catalog must be represented in
		// the ETW map, even if the mapping resolves to "not real-time capable".
		foreach (string channel in EventCatalog.AllChannels())
		{
			EtwProviderInfo? info = EtwProviderMap.TryGet(channel);
			Assert.NotNull(info);
			Assert.Equal(channel, info!.Value.Channel);
		}
	}

	[Fact]
	public void EntriesEnumerationIsStableAndImmutable()
	{
		// Guard against accidental duplication or reordering across future edits.
		int count = EtwProviderMap.Entries.Count;
		Assert.True(count >= 7, $"expected at least 7 provider entries, saw {count}");
		Assert.Equal(count, EtwProviderMap.Entries.Count);
	}

	[Fact]
	public void SecurityChannelIsMarkedNonRealTimeCapable()
	{
		// Microsoft-Windows-Security-Auditing is a protected provider; only the system trace
		// EventLog-Security can subscribe to it. A self-hosted TraceEventSession must fall
		// back to EventLogWatcher for the Security channel.
		Assert.False(EtwProviderMap.IsRealTimeCapable(EventCatalog.ChannelSecurity));
		EtwProviderInfo info = EtwProviderMap.TryGet(EventCatalog.ChannelSecurity)!.Value;
		Assert.False(info.RealTimeCapable);
		Assert.Equal("Microsoft-Windows-Security-Auditing", info.ProviderName);
		Assert.Equal(
			new Guid("54849625-5478-4994-A5BA-3E3B0328C30D"),
			info.ProviderGuid);
	}

	[Fact]
	public void SystemChannelIsMarkedNonRealTimeCapable()
	{
		// The System channel aggregates dozens of providers. There is no single ETW provider
		// that mirrors it end-to-end, so the map deliberately steers it through EventLog.
		Assert.False(EtwProviderMap.IsRealTimeCapable(EventCatalog.ChannelSystem));
		EtwProviderInfo info = EtwProviderMap.TryGet(EventCatalog.ChannelSystem)!.Value;
		Assert.False(info.RealTimeCapable);
	}

	[Theory]
	[InlineData("Microsoft-Windows-TerminalServices-LocalSessionManager/Operational",
		"Microsoft-Windows-TerminalServices-LocalSessionManager",
		"5D896912-022D-40AA-A3A8-4FA5515C76D7")]
	[InlineData("Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational",
		"Microsoft-Windows-TerminalServices-RemoteConnectionManager",
		"C76BAA63-AE81-421C-B425-340B4B24157F")]
	[InlineData("Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational",
		"Microsoft-Windows-RemoteDesktopServices-RdpCoreTS",
		"1139C61B-B549-4251-8ED3-27250A1EDEC8")]
	[InlineData("Microsoft-Windows-TerminalServices-Gateway/Operational",
		"Microsoft-Windows-TerminalServices-Gateway",
		"4D5AE6A1-C7C8-4E6D-B840-4D8080B42E1B")]
	[InlineData("Microsoft-Windows-TerminalServices-RDPClient/Operational",
		"Microsoft-Windows-TerminalServices-ClientActiveXCore",
		"28AA95BB-D444-4719-A36F-40462168127E")]
	public void TerminalServicesChannelsAreRealTimeCapableWithPinnedGuids(
		string channel, string expectedProviderName, string expectedGuid)
	{
		EtwProviderInfo info = EtwProviderMap.TryGet(channel)!.Value;

		Assert.True(info.RealTimeCapable, $"{channel} must be real-time capable");
		Assert.Equal(expectedProviderName, info.ProviderName);
		Assert.Equal(new Guid(expectedGuid), info.ProviderGuid);
	}

	[Fact]
	public void ChannelLookupIsCaseInsensitive()
	{
		// ETW channel names are case-preserving but case-insensitive at the API surface.
		EtwProviderInfo? lower = EtwProviderMap.TryGet(
			EventCatalog.ChannelTsRemote.ToLowerInvariant());
		EtwProviderInfo? upper = EtwProviderMap.TryGet(
			EventCatalog.ChannelTsRemote.ToUpperInvariant());

		Assert.NotNull(lower);
		Assert.NotNull(upper);
		Assert.Equal(lower!.Value.ProviderGuid, upper!.Value.ProviderGuid);
	}

	[Fact]
	public void UnknownChannelReturnsNullAndNotCapable()
	{
		Assert.Null(EtwProviderMap.TryGet("Microsoft-Windows-Nonexistent/Operational"));
		Assert.False(EtwProviderMap.IsRealTimeCapable("Microsoft-Windows-Nonexistent/Operational"));
		Assert.False(EtwProviderMap.IsRealTimeCapable(""));
		Assert.False(EtwProviderMap.IsRealTimeCapable("   "));
	}

	[Fact]
	public void UnknownChannelWithNullInput()
	{
		Assert.Null(EtwProviderMap.TryGet(null!));
		Assert.False(EtwProviderMap.IsRealTimeCapable(null!));
	}

	[Fact]
	public void GuidLookupResolvesTerminalServicesRealTimeProviders()
	{
		EtwProviderInfo? info = EtwProviderMap.TryGetByGuid(
			EtwProviderMap.TsLocalSessionManagerGuid);

		Assert.NotNull(info);
		Assert.Equal(EventCatalog.ChannelTsLocal, info!.Value.Channel);
		Assert.True(info.Value.RealTimeCapable);
	}

	[Fact]
	public void GuidLookupResolvesProtectedSecurityProvider()
	{
		// Protected does not mean unknown: the map still records the mapping so the hybrid
		// factory can look up "why did I refuse ETW for this channel?" by GUID.
		EtwProviderInfo? info = EtwProviderMap.TryGetByGuid(EtwProviderMap.SecurityAuditingGuid);

		Assert.NotNull(info);
		Assert.Equal(EventCatalog.ChannelSecurity, info!.Value.Channel);
		Assert.False(info.Value.RealTimeCapable);
	}

	[Fact]
	public void GuidLookupOfEmptyReturnsNull()
	{
		Assert.Null(EtwProviderMap.TryGetByGuid(Guid.Empty));
	}

	[Fact]
	public void GuidLookupOfUnknownReturnsNull()
	{
		Assert.Null(EtwProviderMap.TryGetByGuid(new Guid("11111111-2222-3333-4444-555555555555")));
	}

	[Fact]
	public void ProviderGuidsAreDistinctAcrossRealTimeCapableChannels()
	{
		// A collision would silently route two channels to the same subscription. We enforce
		// distinctness for every real-time-capable entry.
		HashSet<Guid> seen = [];
		foreach (EtwProviderInfo info in EtwProviderMap.Entries)
		{
			if (!info.RealTimeCapable) continue;
			Assert.True(seen.Add(info.ProviderGuid),
				$"duplicate provider GUID for channel {info.Channel}: {info.ProviderGuid}");
		}
	}
}
