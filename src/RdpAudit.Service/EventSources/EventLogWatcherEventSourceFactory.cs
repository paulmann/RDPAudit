/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 2.0.0
// File   : EventLogWatcherEventSourceFactory.cs
// Project: RdpAudit.Service (RdpAudit.Service.EventSources)
// Purpose: Production IEventSourceFactory that materializes EventLogWatcherEventSource instances.
//          Trivial wrapper — the interesting behavior is inside the source itself; this class only
//          plumbs DI (ILoggerFactory + IEventPipe) into the ctor.
// Depends: IEventSourceFactory, EventLogWatcherEventSource, IEventPipe, ILoggerFactory
// Extends: When you swap the default transport (e.g. to an ETW-based source), register a new
//          IEventSourceFactory implementation in Program.cs instead of editing this class.

using System.Runtime.Versioning;
using Microsoft.Extensions.Logging;
using RdpAudit.Core.Events;

namespace RdpAudit.Service.EventSources;

/// <summary>Default factory that wires <see cref="EventLogWatcherEventSource"/>.</summary>
[SupportedOSPlatform("windows")]
public sealed class EventLogWatcherEventSourceFactory : IEventSourceFactory
{
	// ── Fields & DI ──────────────────────────────────────────────────────────────

	private readonly IEventPipe _pipe;
	private readonly ILoggerFactory _loggerFactory;

	// ── Construction ─────────────────────────────────────────────────────────────

	public EventLogWatcherEventSourceFactory(IEventPipe pipe, ILoggerFactory loggerFactory)
	{
		ArgumentNullException.ThrowIfNull(pipe);
		ArgumentNullException.ThrowIfNull(loggerFactory);

		_pipe = pipe;
		_loggerFactory = loggerFactory;
	}

	// ── Public API ───────────────────────────────────────────────────────────────

	/// <inheritdoc />
	public IEventSource Create(
		string channel,
		string xpathQuery,
		string? bookmarkXml,
		Action<string, string> onBookmark,
		Action<string, Exception, bool> onWatcherFault)
	{
		ArgumentException.ThrowIfNullOrWhiteSpace(channel);
		ArgumentException.ThrowIfNullOrWhiteSpace(xpathQuery);
		ArgumentNullException.ThrowIfNull(onBookmark);
		ArgumentNullException.ThrowIfNull(onWatcherFault);

		return new EventLogWatcherEventSource(
			channel: channel,
			xpathQuery: xpathQuery,
			pipe: _pipe,
			logger: _loggerFactory.CreateLogger<EventLogWatcherEventSource>(),
			initialBookmarkXml: bookmarkXml,
			onBookmark: onBookmark,
			onWatcherFault: onWatcherFault);
	}
}
