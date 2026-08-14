/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 0.1.0
// File   : EtwEventSourceFactory.cs
// Project: RdpAudit.Service (RdpAudit.Service.EventSources)
// Purpose: IEventSourceFactory that materializes EtwEventSource instances. Skeleton (v0.1.0):
//          returns a per-channel EtwEventSource that transitions to Unsupported on start. The
//          per-channel shape mirrors the EventLogWatcher factory contract so nothing downstream
//          needs to know which transport is active. Commit 3 will consolidate all channels behind
//          a single TraceEventSession while keeping this factory-per-channel view intact — the
//          factory simply hands out lightweight session-projection instances at that point.
// Depends: IEventSourceFactory, EtwEventSource, IEventPipe, ILoggerFactory
// Extends: When adding a new ETW provider (Microsoft-Windows-TerminalServices-*), wire it inside
//          EtwEventSource; this factory continues to hand out one IEventSource per Event Log
//          channel name because that is what the host expects for bookmark bookkeeping.

using System.Runtime.Versioning;
using Microsoft.Extensions.Logging;
using RdpAudit.Core.Events;

namespace RdpAudit.Service.EventSources;

/// <summary>
/// Production factory that wires <see cref="EtwEventSource"/> per Event Log channel name.
/// The channel name is used purely as a stable identifier for the host's bookmark ledger and
/// diagnostic logs — ETW providers themselves are enrolled inside <see cref="EtwEventSource"/>.
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

		// The skeleton EtwEventSource does not yet consume xpathQuery, bookmarkXml, onBookmark,
		// or onWatcherFault — they are captured here so the signature contract with
		// IEventSourceFactory stays honest, and commit 3 wires them through without disturbing
		// the outer DI graph. See RdpAudit.Service/EventSources/EtwEventSource.cs.
		return new EtwEventSource(
			sessionName: $"RdpAudit-{channel}",
			pipe: _pipe,
			logger: _loggerFactory.CreateLogger<EtwEventSource>());
	}
}
