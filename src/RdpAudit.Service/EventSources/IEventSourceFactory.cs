/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 2.0.0
// File   : IEventSourceFactory.cs
// Project: RdpAudit.Service (RdpAudit.Service.EventSources)
// Purpose: Abstract factory used by EventCollectorHost to materialize a fresh IEventSource for a
//          given channel + XPath + optional persisted bookmark. Keeps the host testable — real
//          runs get an EventLogWatcherEventSource factory; unit tests inject a fake that produces
//          controllable in-memory sources.
// Depends: IEventSource
// Extends: Add a new factory implementation (EtwEventSourceFactory, EvtxReplaySourceFactory)
//          when you introduce a new event ingestion transport. The host contract never
//          changes — only the source implementation does.

using RdpAudit.Core.Events;

namespace RdpAudit.Service.EventSources;

/// <summary>
/// Creates <see cref="IEventSource"/> instances on demand for the <see cref="EventCollectorHost"/>.
/// The factory owns the choice of transport (EventLogWatcher, ETW, EVTX replay) but delegates all
/// lifecycle, health, and bookmark bookkeeping to the caller.
/// </summary>
public interface IEventSourceFactory
{
	/// <summary>
	/// Build a source for <paramref name="channel"/>. The source MUST be returned in
	/// <see cref="EventSourceStatus.Idle"/>; the host calls <see cref="IEventSource.StartAsync"/>
	/// itself.
	/// </summary>
	/// <param name="channel">Windows Event Log channel name (case-insensitive).</param>
	/// <param name="xpathQuery">Prebuilt XPath filter. Use <c>"*"</c> to disable filtering.</param>
	/// <param name="bookmarkXml">Serialized <see cref="System.Diagnostics.Eventing.Reader.EventBookmark"/>
	/// to resume from, or <c>null</c> to start from the current tail.</param>
	/// <param name="onBookmark">Callback invoked with each captured event's serialized bookmark
	/// XML and the ingestion sequence stamped on that event (channel, bookmarkXml,
	/// ingestionSequence). The host records the pair so the bookmark is only persisted once the
	/// covered event has been committed; see <c>BookmarkCheckpointLedger</c>.</param>
	/// <param name="onWatcherFault">Callback invoked when the underlying transport reports a
	/// fault (channel, exception, isCallback). <c>isCallback=true</c> means the fault surfaced
	/// inside the transport's event delivery path; <c>false</c> means it surfaced during arm.</param>
	IEventSource Create(
		string channel,
		string xpathQuery,
		string? bookmarkXml,
		Action<string, string, long> onBookmark,
		Action<string, Exception, bool> onWatcherFault);
}
