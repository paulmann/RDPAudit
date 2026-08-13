/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 2.0.0
// File   : EventLogWatcherEventSource.cs
// Project: RdpAudit.Service (RdpAudit.Service.EventSources)
// Purpose: Concrete IEventSource that adapts a single Windows Event Log channel (via
//          System.Diagnostics.Eventing.Reader.EventLogWatcher) into the RawEventDto pipeline.
//          One instance = one channel. Owns the watcher lifecycle (start/stop/dispose), records
//          bookmark XML for every captured event, and exposes status transitions so a supervisor
//          can drive health-policy decisions (backoff, disable, reset bookmark) without leaking
//          transport details into the domain layer.
// Depends: IEventSource, IEventPipe, EventSourceStatus, RawEventDto, BookmarkSerializer,
//          EventLogWatcher, EventLogQuery
// Extends: For an ETW-backed source, implement IEventSource in a sibling class
//          (EtwRealtimeEventSource) and register it identically — the pipe / status contract
//          is transport-agnostic. To bolt richer health policy on, wrap this class in a
//          supervisor that subscribes to StatusChanged and restarts on Faulted.

using System.Diagnostics.Eventing.Reader;
using System.Runtime.Versioning;
using Microsoft.Extensions.Logging;
using RdpAudit.Core.Events;
using RdpAudit.Service.Collectors;

namespace RdpAudit.Service.EventSources;

/// <summary>
/// <see cref="IEventSource"/> backed by a single <see cref="EventLogWatcher"/> subscription.
/// The class is deliberately narrow: it starts and stops the watcher, converts every incoming
/// <see cref="EventRecord"/> into a <see cref="RawEventDto"/>, publishes each DTO into the
/// supplied <see cref="IEventPipe"/>, and raises <see cref="StatusChanged"/> for any observable
/// transition. Retry / backoff / bookmark storage live in a supervisor above this class so the
/// source can be reused across ETW and EVTX-file variants.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class EventLogWatcherEventSource : IEventSource, IDisposable
{
	// ── Fields & DI ──────────────────────────────────────────────────────────────

	private const int MaxEventXmlLength = 65_536;

	private readonly string _channel;
	private readonly string _xpathQuery;
	private readonly IEventPipe _pipe;
	private readonly ILogger<EventLogWatcherEventSource> _logger;
	private readonly Action<string, string>? _onBookmark;
	private readonly Action<string, Exception, bool>? _onWatcherFault;
	private readonly object _lifecycleGate = new();

	private EventLogWatcher? _watcher;
	private EventHandler<EventRecordWrittenEventArgs>? _handler;
	private string? _initialBookmarkXml;
	private EventSourceStatus _status = EventSourceStatus.Idle;
	private volatile bool _disposed;

	// ── Construction ─────────────────────────────────────────────────────────────

	/// <summary>Create a new source bound to a single Windows Event Log channel.</summary>
	/// <param name="channel">Windows Event Log channel name (e.g. "Security"). Non-empty.</param>
	/// <param name="xpathQuery">XPath filter passed to <see cref="EventLogQuery"/>; use "*" to
	/// disable filtering. Non-empty.</param>
	/// <param name="pipe">Downstream pipe. Every successfully-captured DTO is written here.</param>
	/// <param name="logger">Structured logger; the source never allocates format strings.</param>
	/// <param name="initialBookmarkXml">Optional serialized bookmark to resume from. If the
	/// bookmark is rejected by the runtime, the source falls back to a bookmark-less
	/// subscription and reports the failure via <paramref name="onWatcherFault"/>.</param>
	/// <param name="onBookmark">Optional per-event callback invoked with the serialized
	/// bookmark XML for each captured event (channel, bookmarkXml). Nullable so the source is
	/// usable in tests without a bookmark supervisor.</param>
	/// <param name="onWatcherFault">Optional supervisor callback for watcher-level faults
	/// (channel, exception, isCallback). Nullable so tests can drive the source without a
	/// health policy.</param>
	public EventLogWatcherEventSource(
		string channel,
		string xpathQuery,
		IEventPipe pipe,
		ILogger<EventLogWatcherEventSource> logger,
		string? initialBookmarkXml = null,
		Action<string, string>? onBookmark = null,
		Action<string, Exception, bool>? onWatcherFault = null)
	{
		ArgumentException.ThrowIfNullOrWhiteSpace(channel);
		ArgumentException.ThrowIfNullOrWhiteSpace(xpathQuery);
		ArgumentNullException.ThrowIfNull(pipe);
		ArgumentNullException.ThrowIfNull(logger);

		_channel = channel;
		_xpathQuery = xpathQuery;
		_pipe = pipe;
		_logger = logger;
		_initialBookmarkXml = initialBookmarkXml;
		_onBookmark = onBookmark;
		_onWatcherFault = onWatcherFault;
	}

	// ── Public API ───────────────────────────────────────────────────────────────

	/// <inheritdoc />
	public string Name => _channel;

	/// <inheritdoc />
	public IEventPipe Pipe => _pipe;

	/// <inheritdoc />
	public EventSourceStatus Status
	{
		get
		{
			lock (_lifecycleGate)
			{
				return _status;
			}
		}
	}

	/// <inheritdoc />
	public event EventHandler<EventSourceStatusChangedEventArgs>? StatusChanged;

	/// <inheritdoc />
	public Task StartAsync(CancellationToken ct)
	{
		ObjectDisposedException.ThrowIf(_disposed, this);

		ct.ThrowIfCancellationRequested();

		lock (_lifecycleGate)
		{
			if (_status == EventSourceStatus.Running)
			{
				return Task.CompletedTask;
			}

			if (_status == EventSourceStatus.Faulted)
			{
				TransitionTo_NoLock(EventSourceStatus.Restarting, reason: "restart after fault");
			}

			try
			{
				CreateAndArmWatcher_NoLock();
				TransitionTo_NoLock(EventSourceStatus.Running, reason: "watcher armed");
			}
			catch (Exception ex)
			{
				TransitionTo_NoLock(EventSourceStatus.Faulted, reason: ex.Message);
				DisposeWatcher_NoLock();
				// Invoke's parameter list is arg1/arg2/arg3 (Action<,,>) so the fault bit
				// travels positionally; `false` = "not raised from a callback thread".
				_onWatcherFault?.Invoke(_channel, ex, false);
				throw;
			}
		}

		return Task.CompletedTask;
	}

	/// <inheritdoc />
	public Task StopAsync(CancellationToken ct)
	{
		if (_disposed)
		{
			return Task.CompletedTask;
		}

		lock (_lifecycleGate)
		{
			if (_status is EventSourceStatus.Stopped or EventSourceStatus.Idle)
			{
				return Task.CompletedTask;
			}

			DisposeWatcher_NoLock();
			TransitionTo_NoLock(EventSourceStatus.Stopped, reason: "stop requested");
		}

		return Task.CompletedTask;
	}

	// ── Core Logic ───────────────────────────────────────────────────────────────

	private void CreateAndArmWatcher_NoLock()
	{
		EventLogQuery query = new(_channel, PathType.LogName, _xpathQuery)
		{
			ReverseDirection = false,
		};

		EventLogWatcher watcher;

		if (_initialBookmarkXml is null)
		{
			watcher = new EventLogWatcher(query);
		}
		else
		{
			try
			{
				EventBookmark bookmark = BookmarkSerializer.Deserialize(_initialBookmarkXml);
				watcher = new EventLogWatcher(query, bookmark);
			}
			catch (EventLogException ex)
			{
				_logger.LogWarning(
					ex,
					"Watcher constructor rejected bookmark for {Channel}; arming without bookmark",
					_channel);

				// One-shot fallback — a supervisor deciding to keep restarting will notice via
				// the fault callback and can wipe the persisted bookmark.
				_initialBookmarkXml = null;
				watcher = new EventLogWatcher(query);
				// Positional args on Action<,,>: (channel, exception, isCallback=false).
				_onWatcherFault?.Invoke(_channel, ex, false);
			}
		}

		EventHandler<EventRecordWrittenEventArgs> handler = (_, args) => OnEventRecordWritten(args);
		watcher.EventRecordWritten += handler;
		watcher.Enabled = true;

		_watcher = watcher;
		_handler = handler;
	}

	private void OnEventRecordWritten(EventRecordWrittenEventArgs args)
	{
		if (args.EventException is not null)
		{
			ReportFault(args.EventException, isCallback: true);
			return;
		}

		if (args.EventRecord is null)
		{
			// EventLogWatcher signals a stalled subscription with a null record; treat it as a
			// callback-side fault so a supervisor can restart us.
			ReportFault(new EventLogException("EventLogWatcher signalled a null EventRecord — subscription stalled"), isCallback: true);
			return;
		}

		if (!TryCaptureDto(args.EventRecord, out RawEventDto dto, out string? bookmarkXml))
		{
			return;
		}

		// Best-effort publish. The pipe is bounded with DropOldest semantics — the source does
		// not treat overflow as a fault because a supervisor is expected to track OverflowCount
		// via metrics.
		_pipe.TryWrite(dto);

		if (bookmarkXml is not null && _onBookmark is not null)
		{
			try
			{
				_onBookmark(_channel, bookmarkXml);
			}
			catch (Exception ex)
			{
				_logger.LogWarning(ex, "onBookmark callback threw for {Channel}", _channel);
			}
		}
	}

	private bool TryCaptureDto(EventRecord record, out RawEventDto dto, out string? bookmarkXml)
	{
		dto = default!;
		bookmarkXml = null;

		try
		{
			using (record)
			{
				string xml = record.ToXml();
				if (xml.Length > MaxEventXmlLength)
				{
					_logger.LogWarning(
						"Event XML for {Channel} EventID {EventId} truncated from {ActualLength} to {MaxLength}",
						_channel,
						record.Id,
						xml.Length,
						MaxEventXmlLength);

					xml = xml[..MaxEventXmlLength];
				}

				dto = new RawEventDto
				{
					EventId = record.Id,
					Channel = record.LogName ?? _channel,
					TimeUtc = record.TimeCreated?.ToUniversalTime() ?? DateTime.UtcNow,
					XmlPayload = xml,
				};

				try
				{
					bookmarkXml = BookmarkSerializer.Serialize(record.Bookmark);
				}
				catch (Exception ex)
				{
					_logger.LogDebug(ex, "Bookmark capture failed for {Channel}", _channel);
				}

				return true;
			}
		}
		catch (EventLogException ex)
		{
			_logger.LogError(ex, "Failed reading EventRecord for {Channel}", _channel);
			return false;
		}
	}

	// ── Error Handling & Retry ───────────────────────────────────────────────────

	private void ReportFault(Exception ex, bool isCallback)
	{
		bool shouldNotify = false;

		lock (_lifecycleGate)
		{
			if (_disposed || _status == EventSourceStatus.Stopped)
			{
				return;
			}

			DisposeWatcher_NoLock();
			TransitionTo_NoLock(EventSourceStatus.Faulted, reason: ex.Message);
			shouldNotify = true;
		}

		if (shouldNotify)
		{
			_onWatcherFault?.Invoke(_channel, ex, isCallback);
		}
	}

	private void TransitionTo_NoLock(EventSourceStatus next, string? reason)
	{
		EventSourceStatus previous = _status;
		if (previous == next)
		{
			return;
		}

		_status = next;

		EventHandler<EventSourceStatusChangedEventArgs>? handler = StatusChanged;
		if (handler is null)
		{
			return;
		}

		EventSourceStatusChangedEventArgs args = new(previous, next, reason);

		try
		{
			handler(this, args);
		}
		catch (Exception ex)
		{
			// StatusChanged subscribers must never take the source down. Swallow and log.
			_logger.LogWarning(ex, "StatusChanged subscriber threw for {Channel}", _channel);
		}
	}

	// ── Disposal & Pool Returns ──────────────────────────────────────────────────

	private void DisposeWatcher_NoLock()
	{
		if (_watcher is null)
		{
			return;
		}

		try
		{
			_watcher.Enabled = false;
		}
		catch (Exception ex)
		{
			_logger.LogDebug(ex, "Disabling watcher for {Channel} threw", _channel);
		}

		if (_handler is not null)
		{
			try
			{
				_watcher.EventRecordWritten -= _handler;
			}
			catch (Exception ex)
			{
				_logger.LogDebug(ex, "Detaching handler for {Channel} threw", _channel);
			}
		}

		try
		{
			_watcher.Dispose();
		}
		catch (Exception ex)
		{
			_logger.LogDebug(ex, "Disposing watcher for {Channel} threw", _channel);
		}

		_watcher = null;
		_handler = null;
	}

	/// <inheritdoc />
	public void Dispose()
	{
		if (_disposed)
		{
			return;
		}

		lock (_lifecycleGate)
		{
			if (_disposed)
			{
				return;
			}

			DisposeWatcher_NoLock();

			if (_status is not EventSourceStatus.Stopped and not EventSourceStatus.Idle)
			{
				TransitionTo_NoLock(EventSourceStatus.Stopped, reason: "disposed");
			}

			_disposed = true;
		}
	}
}
