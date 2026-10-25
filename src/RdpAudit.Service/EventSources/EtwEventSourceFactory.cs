/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 0.2.0
// File   : EtwEventSourceFactory.cs
// Project: RdpAudit.Service (RdpAudit.Service.EventSources)
// Purpose: IEventSourceFactory that materializes EtwEventSource instances per Event Log channel
//          name. Version 0.2.0 wires the real TraceEventSession backed source. Bookmarks are
//          intentionally ignored because ETW real-time sessions do not have a resume cursor;
//          the onBookmark callback stays in the signature so we honour IEventSourceFactory.
// Depends: IEventSourceFactory, EtwEventSource, IEventPipe, ILoggerFactory
// Extends: When adding a new real-time ETW provider (Microsoft-Windows-TerminalServices-*),
//          register it in EtwProviderMap. This factory continues to hand out one IEventSource
//          per Event Log channel name because that is the shape EventCollectorHost expects for
//          its per-channel supervision, health policy, and restart logic.

using System.Runtime.Versioning;
using Microsoft.Extensions.Logging;
using RdpAudit.Core.Events;

namespace RdpAudit.Service.EventSources;

/// <summary>
/// Production factory that wires <see cref="EtwEventSource"/> per Event Log channel name.
/// The channel name is used as a stable identifier for the host's supervisor and diagnostic
/// logs — the concrete ETW provider is resolved from that channel via <see cref="EtwProviderMap"/>
/// inside <see cref="EtwEventSource"/>.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class EtwEventSourceFactory : IEventSourceFactory
{
	// ── Fields & DI ──────────────────────────────────────────────────────────────

	private readonly IEventPipe _pipe;
	private readonly ILoggerFactory _loggerFactory;

	// ── Construction ─────────────────────────────────────────────────────────────

	public EtwEventSourceFactory(IEventPipe pipe, ILoggerFactory loggerFactory)
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
		Action<string, string, long> onBookmark,
		Action<string, Exception, bool> onWatcherFault)
	{
		ArgumentException.ThrowIfNullOrWhiteSpace(channel);
		ArgumentException.ThrowIfNullOrWhiteSpace(xpathQuery);
		ArgumentNullException.ThrowIfNull(onBookmark);
		ArgumentNullException.ThrowIfNull(onWatcherFault);

		// xpathQuery is unused: TraceEventSession filters by provider keywords, not XPath.
		// bookmarkXml is unused: ETW real-time sessions do not resume from a cursor after a
		// restart, which is exactly why EtwProviderMap advertises the covered channels as
		// RealTimeCapable (a Windows-level trade-off surfaced to the operator).
		// onBookmark stays wired but is never invoked from this transport.
		return new EtwEventSource(
			channel: channel,
			pipe: _pipe,
			logger: _loggerFactory.CreateLogger<EtwEventSource>(),
			onWatcherFault: onWatcherFault);
	}
}
