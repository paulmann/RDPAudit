/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 0.1.0
// File   : HybridEventSourceFactory.cs
// Project: RdpAudit.Service (RdpAudit.Service.EventSources)
// Purpose: Composite IEventSourceFactory that routes each channel to the best transport at Create
//          time. Channels flagged as real-time capable in EtwProviderMap are handed to the ETW
//          factory; the rest fall back to the EventLogWatcher factory. This is the transport the
//          service ships when the operator selects IngestionMode.Etw (or IngestionMode.Auto and
//          the ETW probe succeeds) — pure ETW is never adequate for the Security channel because
//          Microsoft-Windows-Security-Auditing is a protected system provider that non-kernel
//          real-time consumers cannot enable.
// Depends: IEventSourceFactory, EtwEventSourceFactory, EventLogWatcherEventSourceFactory,
//          EtwProviderMap, ILogger
// Extends: When a channel gains real-time ETW support (e.g. Microsoft opens the Security manifest
//          for user-mode real-time sessions in a future Windows release), flip its
//          RealTimeCapable flag in EtwProviderMap and this factory automatically routes it.

using Microsoft.Extensions.Logging;
using RdpAudit.Core.Events;

namespace RdpAudit.Service.EventSources;

/// <summary>
/// Routes each requested channel to either <see cref="EtwEventSourceFactory"/> (real-time ETW)
/// or <see cref="EventLogWatcherEventSourceFactory"/> (Event Log subscription) based on the
/// per-channel real-time capability declared in <see cref="EtwProviderMap"/>.
/// </summary>
/// <remarks>
/// The decision is made per Create call rather than per host lifetime, so a change in
/// <see cref="EtwProviderMap"/> takes effect the next time the collector re-arms a channel.
/// The chosen transport is logged at Information level exactly once per channel so operators
/// can confirm the routing without turning on Debug logs.
/// </remarks>
public sealed class HybridEventSourceFactory : IEventSourceFactory
{
	// ── Fields & DI ──────────────────────────────────────────────────────────────

	private readonly EtwEventSourceFactory _etwFactory;
	private readonly EventLogWatcherEventSourceFactory _eventLogFactory;
	private readonly ILogger<HybridEventSourceFactory> _logger;

	// ── Construction ─────────────────────────────────────────────────────────────

	public HybridEventSourceFactory(
		EtwEventSourceFactory etwFactory,
		EventLogWatcherEventSourceFactory eventLogFactory,
		ILogger<HybridEventSourceFactory> logger)
	{
		ArgumentNullException.ThrowIfNull(etwFactory);
		ArgumentNullException.ThrowIfNull(eventLogFactory);
		ArgumentNullException.ThrowIfNull(logger);

		_etwFactory = etwFactory;
		_eventLogFactory = eventLogFactory;
		_logger = logger;
	}

	// ── Public API ───────────────────────────────────────────────────────────────

	/// <inheritdoc />
	public IEventSource Create(
		string channel,
		string xpathQuery,
		string? bookmarkXml,
		Action<string, string, long> onBookmark,
		Action<string, Exception, bool> onWatcherFault)
	{
		ArgumentException.ThrowIfNullOrWhiteSpace(channel);
		ArgumentException.ThrowIfNullOrWhiteSpace(xpathQuery);
		ArgumentNullException.ThrowIfNull(onBookmark);
		ArgumentNullException.ThrowIfNull(onWatcherFault);

		bool useEtw = EtwProviderMap.IsRealTimeCapable(channel);

		if (useEtw)
		{
			_logger.LogInformation(
				"Channel {Channel} routed to ETW transport (real-time capable in EtwProviderMap).",
				channel);
			return _etwFactory.Create(channel, xpathQuery, bookmarkXml, onBookmark, onWatcherFault);
		}

		_logger.LogInformation(
			"Channel {Channel} routed to EventLogWatcher transport (not real-time capable in EtwProviderMap).",
			channel);
		return _eventLogFactory.Create(channel, xpathQuery, bookmarkXml, onBookmark, onWatcherFault);
	}
}
