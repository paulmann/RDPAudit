/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 0.2.0
// File   : EtwEventSource.cs
// Project: RdpAudit.Service (RdpAudit.Service.EventSources)
// Purpose: Real-time ETW consumer implementing IEventSource. Owns a dedicated TraceEventSession
//          bound to a single ETW provider (resolved from the channel name via EtwProviderMap),
//          projects each incoming TraceEvent onto EtwEventPayload, renders canonical Windows XML
//          via EtwPayloadXmlFormatter, and hands the resulting RawEventDto to the shared pipe.
//          Bookmarks are not applicable to ETW real-time sessions (there is no read cursor to
//          resume from after a restart), so onBookmark stays wired but is never invoked from
//          this transport — the covered channels are advertised as RealTimeCapable in
//          EtwProviderMap so operators know the trade-off.
// Depends: IEventSource, IEventPipe, EtwProviderMap, EtwEventPayload, EtwPayloadXmlFormatter,
//          TraceEventSession, ETWTraceEventSource (Microsoft.Diagnostics.Tracing.TraceEvent)
// Extends: When adding a keyword filter or manifest-scoped subscription, extend StartAsync
//          around the EnableProvider call. Do NOT change the public IEventSource contract —
//          keep the transport swap invisible to EventCollectorHost.

using System.Diagnostics.CodeAnalysis;
using System.Runtime.Versioning;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Diagnostics.Tracing;
using Microsoft.Diagnostics.Tracing.Session;
using Microsoft.Extensions.Logging;
using RdpAudit.Core.Events;

namespace RdpAudit.Service.EventSources;

/// <summary>
/// Real-time ETW-backed <see cref="IEventSource"/>. Owns a single <see cref="TraceEventSession"/>
/// for a single provider (resolved from the channel name via <see cref="EtwProviderMap"/>).
/// </summary>
/// <remarks>
/// <para>Threading model. TraceEvent's dispatch thread invokes <see cref="OnDynamicEvent"/>
/// synchronously. That thread is created and owned by the session; we do not block on it and
/// we do not perform I/O beyond <see cref="IEventPipe.TryWrite"/>, which is documented as
/// non-blocking on the RingBufferEventPipe implementation.</para>
/// <para>Failure model. Any unexpected exception on the dispatch thread transitions the source
/// to <see cref="EventSourceStatus.Faulted"/> and notifies <c>onWatcherFault</c>; the collector
/// host schedules an out-of-band restart. Fault handling is idempotent — repeated exceptions in
/// the same session only transition once.</para>
/// </remarks>
[SupportedOSPlatform("windows")]
[SuppressMessage("Design", "CA1001",
	Justification = "Disposal is externalised through the IEventSource contract: callers invoke StopAsync which drops the TraceEventSession.")]
public sealed class EtwEventSource : IEventSource
{
	// ── Fields & DI ──────────────────────────────────────────────────────────────

	private readonly ILogger<EtwEventSource> _logger;
	private readonly string _channel;
	private readonly string _sessionName;
	private readonly EtwProviderInfo _providerInfo;
	private readonly Action<string, Exception, bool>? _onWatcherFault;

	private int _statusInt = (int)EventSourceStatus.Idle;
	private readonly object _lifecycleGate = new();

	private TraceEventSession? _session;
	private Thread? _dispatchThread;
	private bool _disposed;

	// ── Construction ─────────────────────────────────────────────────────────────

	/// <summary>Create a new ETW source bound to <paramref name="channel"/>.</summary>
	/// <param name="channel">Windows event log channel name. Must be mapped in
	/// <see cref="EtwProviderMap"/> and marked <see cref="EtwProviderInfo.RealTimeCapable"/>.
	/// The constructor throws <see cref="ArgumentException"/> when the channel is not mapped
	/// or when the mapping is not real-time capable — <see cref="HybridEventSourceFactory"/>
	/// is expected to have filtered those out before Create is called.</param>
	/// <param name="pipe">Downstream pipe every produced DTO is written to.</param>
	/// <param name="logger">Structured logger.</param>
	/// <param name="onWatcherFault">Optional fault sink invoked from the dispatch thread when
	/// the session or its providers report an unrecoverable error. Callers use it to schedule
	/// an out-of-band restart via <c>EventCollectorHost</c>.</param>
	public EtwEventSource(
		string channel,
		IEventPipe pipe,
		ILogger<EtwEventSource> logger,
		Action<string, Exception, bool>? onWatcherFault = null)
	{
		ArgumentException.ThrowIfNullOrWhiteSpace(channel);
		ArgumentNullException.ThrowIfNull(pipe);
		ArgumentNullException.ThrowIfNull(logger);

		EtwProviderInfo? info = EtwProviderMap.TryGet(channel);
		if (info is null || !info.Value.RealTimeCapable)
		{
			throw new ArgumentException(
				$"Channel '{channel}' is not real-time ETW capable. HybridEventSourceFactory should have routed this to EventLogWatcher.",
				nameof(channel));
		}

		_channel = channel;
		_providerInfo = info.Value;
		_logger = logger;
		_onWatcherFault = onWatcherFault;
		Pipe = pipe;
		_sessionName = BuildSessionName(channel);
	}

	// ── Public API ───────────────────────────────────────────────────────────────

	/// <inheritdoc />
	public string Name => _channel;

	/// <inheritdoc />
	public IEventPipe Pipe { get; }

	/// <inheritdoc />
	public EventSourceStatus Status => (EventSourceStatus)Volatile.Read(ref _statusInt);

	/// <inheritdoc />
	public event EventHandler<EventSourceStatusChangedEventArgs>? StatusChanged;

	/// <inheritdoc />
	public Task StartAsync(CancellationToken ct)
	{
		ct.ThrowIfCancellationRequested();

		lock (_lifecycleGate)
		{
			if (_disposed)
			{
				throw new InvalidOperationException($"EtwEventSource for '{_channel}' has been stopped.");
			}
			if (_session is not null)
			{
				// Idempotent: already running.
				return Task.CompletedTask;
			}

			try
			{
				// Best-effort: an orphan session from a previous crashed process would refuse
				// EnableProvider with ERROR_ALREADY_EXISTS. Stop it silently before we try.
				try { TraceEventSession.GetActiveSession(_sessionName)?.Stop(noThrow: true); }
				catch { /* ignored — session may not exist */ }

				_session = new TraceEventSession(_sessionName)
				{
					StopOnDispose = true,
				};

				// Buffer sizing: default TraceEvent session buffers are 64 KiB × 2. For a
				// low-volume RDP-scoped provider this is more than enough; we keep defaults so
				// operators can override via WPR profiles if needed.
				_session.EnableProvider(
					_providerInfo.ProviderGuid,
					TraceEventLevel.Verbose,
					matchAnyKeywords: unchecked((ulong)-1L),
					options: (TraceEventProviderOptions?)null);

				_session.Source.Dynamic.All += OnDynamicEvent;

				// The dispatch loop is blocking: TraceEventSource.Process() only returns when
				// the session is stopped or the buffers can no longer be delivered. Run it on
				// a dedicated foreground=false thread so shutdown does not have to wait for it.
				_dispatchThread = new Thread(RunDispatchLoop)
				{
					IsBackground = true,
					Name = _sessionName,
				};
				_dispatchThread.Start();

				TransitionTo(EventSourceStatus.Running, "ETW session started.");
				_logger.LogInformation(
					"ETW session '{Session}' armed on provider {Provider} ({Guid}) for channel {Channel}",
					_sessionName, _providerInfo.ProviderName, _providerInfo.ProviderGuid, _channel);
			}
			catch (Exception ex)
			{
				DisposeSession_NoLock();
				TransitionTo(EventSourceStatus.Faulted, ex.Message);
				_logger.LogError(ex,
					"Failed to start ETW session '{Session}' for channel {Channel}",
					_sessionName, _channel);
					_onWatcherFault?.Invoke(_channel, ex, false);
				throw;
			}
		}

		return Task.CompletedTask;
	}

	/// <inheritdoc />
	public Task StopAsync(CancellationToken ct)
	{
		Thread? dispatchThread;
		lock (_lifecycleGate)
		{
			if (_disposed)
			{
				return Task.CompletedTask;
			}
			_disposed = true;
			dispatchThread = _dispatchThread;
			DisposeSession_NoLock();
			TransitionTo(EventSourceStatus.Stopped, "Stop requested.");
		}

		// Best-effort join. TraceEventSource.Process() returns promptly after Stop(); if it
		// somehow blocks we simply move on — the thread is a background thread and will die
		// with the process.
		if (dispatchThread is not null && dispatchThread.IsAlive)
		{
			try { dispatchThread.Join(TimeSpan.FromSeconds(2)); }
			catch { /* ignored */ }
		}

		return Task.CompletedTask;
	}

	// ── Core Logic ───────────────────────────────────────────────────────────────

	private void RunDispatchLoop()
	{
		try
		{
			// Blocking. Returns only when Stop() is called on the session or the kernel
			// closes the trace handle.
			_session?.Source.Process();
		}
		catch (Exception ex)
		{
			_logger.LogError(ex, "ETW dispatch loop crashed for '{Session}'", _sessionName);
			ReportFault(ex, isCallback: true);
		}
	}

	private void OnDynamicEvent(TraceEvent evt)
	{
		// Fast filter: manifest-based providers emit a stream of task-specific events plus
		// TraceEvent's own "ManifestData" events (EventID 0xFFFE). Drop those without work.
		int eventId = (int)evt.ID;
		if (eventId == 0xFFFE || eventId == 0xFFFF)
		{
			return;
		}

		try
		{
			// Snapshot the payload synchronously — TraceEvent objects are recycled by the
			// underlying parser as soon as this callback returns.
			EtwEventPayload payload = ProjectPayload(evt);
			string xml = EtwPayloadXmlFormatter.Format(payload);

			var dto = new RawEventDto
			{
				EventId = eventId,
				Channel = _channel,
				TimeUtc = payload.TimeStampUtc,
				XmlPayload = xml,
			};

			Pipe.TryWrite(dto);
		}
		catch (Exception ex)
		{
			// Never take down the dispatch thread for a single malformed event.
			_logger.LogWarning(ex,
				"ETW callback failed for event {EventId} on channel {Channel}",
				eventId, _channel);
		}
	}

	private EtwEventPayload ProjectPayload(TraceEvent evt)
	{
		string[] names = evt.PayloadNames ?? Array.Empty<string>();
		object?[] values = new object?[names.Length];
		for (int i = 0; i < names.Length; i++)
		{
			try
			{
				values[i] = evt.PayloadValue(i);
			}
			catch
			{
				// Some manifest-declared payloads throw on decode when the manifest lags the
				// on-disk provider (e.g. a Windows patch that added a field). Fall back to the
				// string form; if that also fails, leave null.
				try { values[i] = evt.PayloadString(i, System.Globalization.CultureInfo.InvariantCulture); }
				catch { values[i] = null; }
			}
		}

		DateTime tsUtc = evt.TimeStamp.Kind switch
		{
			DateTimeKind.Utc => evt.TimeStamp,
			DateTimeKind.Local => evt.TimeStamp.ToUniversalTime(),
			// TraceEvent normally emits Local. Any Unspecified is interpreted as UTC by us —
			// this is a defensive branch; in production TraceEvent always sets Kind.
			_ => DateTime.SpecifyKind(evt.TimeStamp, DateTimeKind.Utc),
		};

		return new EtwEventPayload
		{
			EventId = (int)evt.ID,
			ProviderName = evt.ProviderName ?? _providerInfo.ProviderName,
			ProviderGuid = evt.ProviderGuid == Guid.Empty ? _providerInfo.ProviderGuid : evt.ProviderGuid,
			Channel = _channel,
			TimeStampUtc = tsUtc,
			Computer = Environment.MachineName,
			ActivityId = evt.ActivityID,
			ProcessId = evt.ProcessID,
			ThreadId = evt.ThreadID,
			Keywords = (ulong)evt.Keywords,
			Task = (int)evt.Task,
			Opcode = (int)evt.Opcode,
			Version = evt.Version,
			Level = (int)evt.Level,
			Names = names,
			Values = values,
		};
	}

	// ── Error Handling & Retry ───────────────────────────────────────────────────

	private void ReportFault(Exception ex, bool isCallback)
	{
		bool shouldNotify = false;
		lock (_lifecycleGate)
		{
			if (_disposed || (EventSourceStatus)_statusInt == EventSourceStatus.Faulted)
			{
				return;
			}
			DisposeSession_NoLock();
			TransitionTo_NoLock(EventSourceStatus.Faulted, ex.Message);
			shouldNotify = true;
		}
		if (shouldNotify)
		{
			_onWatcherFault?.Invoke(_channel, ex, isCallback);
		}
	}

	// ── Disposal & Pool Returns ──────────────────────────────────────────────────

	[SuppressMessage("Reliability", "CA2000",
		Justification = "Session is captured on _session and disposed by StopAsync/ReportFault.")]
	private void DisposeSession_NoLock()
	{
		TraceEventSession? session = _session;
		_session = null;
		if (session is null) return;

		try { session.Source.Dynamic.All -= OnDynamicEvent; }
		catch { /* ignored */ }

		try { session.Stop(noThrow: true); }
		catch { /* ignored */ }

		try { session.Dispose(); }
		catch { /* ignored */ }
	}

	// ── State transitions ────────────────────────────────────────────────────────

	private void TransitionTo(EventSourceStatus target, string? reason)
	{
		lock (_lifecycleGate)
		{
			TransitionTo_NoLock(target, reason);
		}
	}

	private void TransitionTo_NoLock(EventSourceStatus target, string? reason)
	{
		EventSourceStatus previous = (EventSourceStatus)_statusInt;
		if (previous == target)
		{
			return;
		}
		Volatile.Write(ref _statusInt, (int)target);

		try
		{
			StatusChanged?.Invoke(this, new EventSourceStatusChangedEventArgs(previous, target, reason));
		}
		catch (Exception ex)
		{
			_logger.LogWarning(ex, "StatusChanged subscriber threw for ETW source '{Session}'", _sessionName);
		}
	}

	// ── Session naming ───────────────────────────────────────────────────────────

	private static string BuildSessionName(string channel)
	{
		// TraceEventSession names must be <=1024 chars and cannot contain path separators. The
		// channel name is already restricted to safe characters by Windows, but we sanitise
		// anyway to be defensive.
		Span<char> buf = stackalloc char[64];
		const string Prefix = "RdpAudit-";
		Prefix.AsSpan().CopyTo(buf);
		int len = Prefix.Length;

		foreach (char c in channel)
		{
			if (len >= buf.Length) break;
			char safe = char.IsLetterOrDigit(c) ? c : '-';
			buf[len++] = safe;
		}

		return new string(buf[..len]);
	}
}
