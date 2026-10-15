/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 0.1.0
// File   : EtwProviderMap.cs
// Project: RdpAudit.Core (RdpAudit.Core.Events)
// Purpose: Static map from a Windows event-log channel name (as declared in EventCatalog) to the
//          ETW provider that supplies its events in real time, along with a boolean flag that
//          says whether an in-process TraceEventSession can subscribe to that provider without
//          administrative work-arounds.
// Depends: EventCatalog (channel constants)
// Extends: To add a new channel: (1) append a new EtwProviderInfo entry to Entries with the
//          canonical provider name, provider GUID, and RealTimeCapable flag; (2) if a channel is
//          served by a protected provider (Microsoft-Windows-Security-Auditing) or is otherwise
//          unreachable from a self-hosted session, set RealTimeCapable = false so the hybrid
//          factory falls back to EventLogWatcher for that channel.
// Notes  : This module is pure data — it has no Windows-specific dependency and can be unit
//          tested on any platform. All provider GUIDs are canonical Windows values verified
//          against Microsoft documentation and multiple independent references (SigmaHQ, Elastic,
//          Fluent Bit, Microsoft Q&A). Do not translate them; ETW matches providers by exact GUID.

using System.Collections.Frozen;

namespace RdpAudit.Core.Events;

/// <summary>
/// Immutable description of the ETW provider that fronts a given Windows event-log channel.
/// </summary>
/// <param name="Channel">Event-log channel name (matches an <see cref="EventCatalog"/> constant).</param>
/// <param name="ProviderName">Canonical ETW provider name as declared in the Windows manifest.</param>
/// <param name="ProviderGuid">Canonical provider GUID. ETW matches providers by GUID, not name.</param>
/// <param name="RealTimeCapable">
/// <see langword="true"/> if a self-hosted, in-process <c>TraceEventSession</c> running as
/// LocalSystem can enable this provider and receive events in real time; <see langword="false"/>
/// if the provider is protected or otherwise unreachable from a user-space session and the
/// channel must be served by <c>EventLogWatcher</c>.
/// </param>
public readonly record struct EtwProviderInfo(
	string Channel,
	string ProviderName,
	Guid ProviderGuid,
	bool RealTimeCapable);

/// <summary>
/// Static, immutable map from a Windows event-log channel to the ETW provider that emits its
/// events. Used by the hybrid event-source factory to decide whether a channel should be served
/// by an in-process ETW session or by <c>EventLogWatcher</c>.
/// </summary>
public static class EtwProviderMap
{
	// ── Canonical provider GUIDs ─────────────────────────────────────────────────
	// These GUIDs are fixed by Windows. They are declared as static readonly fields (not
	// const, because Guid is not a legal const type) but are effectively constants.

	/// <summary>Microsoft-Windows-Security-Auditing. Protected provider — reserved for the
	/// system trace <c>EventLog-Security</c>; a self-hosted TraceEventSession cannot subscribe
	/// even from LocalSystem. All Security-channel events are therefore served by EventLog.</summary>
	public static readonly Guid SecurityAuditingGuid =
		new("54849625-5478-4994-A5BA-3E3B0328C30D");

	/// <summary>Microsoft-Windows-TerminalServices-LocalSessionManager. Regular provider.</summary>
	public static readonly Guid TsLocalSessionManagerGuid =
		new("5D896912-022D-40AA-A3A8-4FA5515C76D7");

	/// <summary>Microsoft-Windows-TerminalServices-RemoteConnectionManager. Regular provider.</summary>
	public static readonly Guid TsRemoteConnectionManagerGuid =
		new("C76BAA63-AE81-421C-B425-340B4B24157F");

	/// <summary>Microsoft-Windows-RemoteDesktopServices-RdpCoreTS. Regular provider.</summary>
	public static readonly Guid RdpCoreTsGuid =
		new("1139C61B-B549-4251-8ED3-27250A1EDEC8");

	/// <summary>Microsoft-Windows-TerminalServices-Gateway. Regular provider.</summary>
	public static readonly Guid TsGatewayGuid =
		new("4D5AE6A1-C7C8-4E6D-B840-4D8080B42E1B");

	/// <summary>Microsoft-Windows-TerminalServices-ClientActiveXCore. Regular provider that
	/// backs the RDPClient/Operational channel on client-side Windows installations.</summary>
	public static readonly Guid TsClientActiveXCoreGuid =
		new("28AA95BB-D444-4719-A36F-40462168127E");

	// ── Provider entries in canonical channel order ──────────────────────────────

	private static readonly EtwProviderInfo[] EntriesArray =
	[
		new(
			Channel: EventCatalog.ChannelSecurity,
			ProviderName: "Microsoft-Windows-Security-Auditing",
			ProviderGuid: SecurityAuditingGuid,
			RealTimeCapable: false),

		// System channel aggregates dozens of providers; there is no single ETW provider
		// that mirrors it end-to-end. Serve it via EventLogWatcher.
		new(
			Channel: EventCatalog.ChannelSystem,
			ProviderName: string.Empty,
			ProviderGuid: Guid.Empty,
			RealTimeCapable: false),

		new(
			Channel: EventCatalog.ChannelTsLocal,
			ProviderName: "Microsoft-Windows-TerminalServices-LocalSessionManager",
			ProviderGuid: TsLocalSessionManagerGuid,
			RealTimeCapable: true),

		new(
			Channel: EventCatalog.ChannelTsRemote,
			ProviderName: "Microsoft-Windows-TerminalServices-RemoteConnectionManager",
			ProviderGuid: TsRemoteConnectionManagerGuid,
			RealTimeCapable: true),

		new(
			Channel: EventCatalog.ChannelRdpCore,
			ProviderName: "Microsoft-Windows-RemoteDesktopServices-RdpCoreTS",
			ProviderGuid: RdpCoreTsGuid,
			RealTimeCapable: true),

		new(
			Channel: EventCatalog.ChannelTsGateway,
			ProviderName: "Microsoft-Windows-TerminalServices-Gateway",
			ProviderGuid: TsGatewayGuid,
			RealTimeCapable: true),

		new(
			Channel: EventCatalog.ChannelTsClient,
			ProviderName: "Microsoft-Windows-TerminalServices-ClientActiveXCore",
			ProviderGuid: TsClientActiveXCoreGuid,
			RealTimeCapable: true),
	];

	// ── Frozen lookups ───────────────────────────────────────────────────────────

	private static readonly FrozenDictionary<string, EtwProviderInfo> ByChannel
		= EntriesArray.ToFrozenDictionary(e => e.Channel, StringComparer.OrdinalIgnoreCase);

	private static readonly FrozenDictionary<Guid, EtwProviderInfo> ByGuid
		= EntriesArray
			.Where(e => e.ProviderGuid != Guid.Empty)
			.ToFrozenDictionary(e => e.ProviderGuid);

	// ── Public API ───────────────────────────────────────────────────────────────

	/// <summary>Every registered mapping, in canonical channel order.</summary>
	public static IReadOnlyList<EtwProviderInfo> Entries => EntriesArray;

	/// <summary>Return the provider entry for a channel, or <see langword="null"/> if unknown.</summary>
	/// <param name="channel">Channel name (case-insensitive).</param>
	public static EtwProviderInfo? TryGet(string channel)
	{
		if (string.IsNullOrWhiteSpace(channel)) return null;
		return ByChannel.TryGetValue(channel, out EtwProviderInfo info) ? info : null;
	}

	/// <summary>
	/// True when the specified channel can be served by an in-process ETW real-time session.
	/// Returns <see langword="false"/> for unknown channels and for channels served by
	/// protected providers such as Microsoft-Windows-Security-Auditing.
	/// </summary>
	public static bool IsRealTimeCapable(string channel)
	{
		EtwProviderInfo? info = TryGet(channel);
		return info is not null && info.Value.RealTimeCapable;
	}

	/// <summary>Return the provider entry that matches a GUID, or <see langword="null"/>.</summary>
	public static EtwProviderInfo? TryGetByGuid(Guid providerGuid)
	{
		if (providerGuid == Guid.Empty) return null;
		return ByGuid.TryGetValue(providerGuid, out EtwProviderInfo info) ? info : null;
	}
}
