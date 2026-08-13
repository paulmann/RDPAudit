/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 2.0.0
// File   : EventCollectorHost.cs
// Project: RdpAudit.Service (RdpAudit.Service.EventSources)
// Purpose: Composes one IEventSource per Windows Event Log channel, drives ChannelHealthPolicy
//          decisions (cooldown, bookmark reset, permanent disable) on watcher faults, aggregates
//          per-event bookmark XML into an in-memory pending map that is flushed to BookmarkStore
//          either periodically, on demand, or during shutdown, and enforces single-restart-in-
//          flight per channel so a fault storm cannot spawn parallel arm attempts.
//          This class replaces the tangled arm/restart/flush code inside EventCollectorWorker;
//          the worker will become a thin BackgroundService shim in a follow-up iteration.
// Depends: IEventSourceFactory, IEventSource, ChannelHealthPolicy, BookmarkStore,
//          IChannelStatusSink, ILogger
// Extends: Add a new channel by calling StartChannelAsync with its XPath. Add a new restart
//          strategy by extending ChannelHealthPolicy — the host consumes ChannelDecision
//          values only through the switch in HandleFaultAsync.

using System.Collections.Concurrent;
using Microsoft.Extensions.Logging;
using RdpAudit.Core.Events;
using RdpAudit.Service.Collectors;

namespace RdpAudit.Service.EventSources;

/// <summary>
/// Optional sink for per-channel status transitions. Wire this to <c>ServiceMetrics</c> in
/// production and to a fake in tests. Keeping it as an interface avoids a hard dependency on the
/// service-metrics implementation from the host.
/// </summary>
public interface IChannelStatusSink
{
	/// <summary>Called on every observable channel state change; the string is a short label
	/// (e.g. "Armed", "RestartScheduled", "BookmarkReset", "DisabledAfterFailures").</summary>
	void SetChannelStatus(string channel, string status);

	/// <summary>Called when the pipe reports a dropped event (host does not currently measure
	/// this itself; the source-facing pipe drives it). Included for interface parity with the
	/// legacy ServiceMetrics surface.</summary>
	void IncrementDropped();
}

/// <summary>
/// Composes and supervises <see cref="IEventSource"/> instances per Windows Event Log channel.
/// The host is transport-agnostic: it never touches EventLogWatcher directly, it only speaks the
/// <see cref="IEventSource"/> contract.
/// </summary>
public sealed class EventCollectorHost : IAsyncDisposable
{
	// ── Fields & DI ──────────────────────────────────────────────────────────────

	private const int PendingFlushEventThreshold = 100;

	private readonly IEventSourceFactory _sourceFactory;
	private readonly ChannelHealthPolicy _health;
	private readonly BookmarkStore _bookmarks;
	private readonly IChannelStatusSink? _statusSink;
	private readonly ILogger<EventCollectorHost> _logger;

	private readonly ConcurrentDictionary<string, ChannelRuntime> _channels =
		new(StringComparer.OrdinalIgnoreCase);

	private readonly ConcurrentDictionary<string, byte> _restartInFlight =
		new(StringComparer.OrdinalIgnoreCase);

	private readonly object _bookmarkGate = new();
	private readonly Dictionary<string, string> _pendingBookmarks =
		new(StringComparer.OrdinalIgnoreCase);
	private readonly Dictionary<string, string> _flushedBookmarks =
		new(StringComparer.OrdinalIgnoreCase);
	private readonly Dictionary<string, int> _pendingBookmarkEventCounts =
		new(StringComparer.OrdinalIgnoreCase);

	private volatile bool _shuttingDown;

	// ── Construction ─────────────────────────────────────────────────────────────

	public EventCollectorHost(
		IEventSourceFactory sourceFactory,
		ChannelHealthPolicy health,
		BookmarkStore bookmarks,
		ILogger<EventCollectorHost> logger,
		IChannelStatusSink? statusSink = null)
	{
		ArgumentNullException.ThrowIfNull(sourceFactory);
		ArgumentNullException.ThrowIfNull(health);
		ArgumentNullException.ThrowIfNull(bookmarks);
		ArgumentNullException.ThrowIfNull(logger);

		_sourceFactory = sourceFactory;
		_health = health;
		_bookmarks = bookmarks;
		_logger = logger;
		_statusSink = statusSink;
	}

	// ── Public API ───────────────────────────────────────────────────────────────

	/// <summary>Currently tracked channel names, for diagnostics / tests. Snapshot semantics.</summary>
	public IReadOnlyCollection<string> Channels
	{
		get
		{
			// ConcurrentDictionary<TKey, TValue>.Keys returns a snapshot ICollection<TKey>; we
			// materialize it into a List so callers get IReadOnlyCollection semantics without
			// exposing the mutable ICollection surface.
			List<string> snapshot = new();
			foreach (string k in _channels.Keys)
			{
				snapshot.Add(k);
			}

			return snapshot;
		}
	}

	/// <summary>
	/// Whether the pending-bookmark map contains channels whose newest bookmark is not yet
	/// persisted. Used by shutdown code to decide whether a final flush is needed.
	/// </summary>
	public bool HasUnflushedBookmarks()
	{
		lock (_bookmarkGate)
		{
			foreach (KeyValuePair<string, string> entry in _pendingBookmarks)
			{
				if (!_flushedBookmarks.TryGetValue(entry.Key, out string? previous) ||
					!string.Equals(previous, entry.Value, StringComparison.Ordinal))
				{
					return true;
				}
			}

			return false;
		}
	}

	/// <summary>
	/// Arm (or re-arm) the given channel. Idempotent: calling twice for the same channel while
	/// a source is already running is a no-op that logs debug-only. If the channel was disabled
	/// by the health policy, the call is refused with a warning.
	/// </summary>
	public async Task StartChannelAsync(string channel, string xpathQuery, CancellationToken ct)
	{
		ArgumentException.ThrowIfNullOrWhiteSpace(channel);
		ArgumentException.ThrowIfNullOrWhiteSpace(xpathQuery);

		if (_shuttingDown || ct.IsCancellationRequested)
		{
			return;
		}

		if (_health.IsDisabled(channel))
		{
			_logger.LogDebug("Channel {Channel} is disabled by health policy; skipping arm", channel);
			return;
		}

		string? bookmarkXml = _bookmarks.GetBookmarkXml(channel);

		IEventSource source = _sourceFactory.Create(
			channel,
			xpathQuery,
			bookmarkXml,
			onBookmark: TrackBookmark,
			onWatcherFault: (ch, ex, isCallback) => _ = HandleFaultAsync(ch, xpathQuery, ex, isCallback));

		ChannelRuntime runtime = new(channel, xpathQuery, source);

		// Race protection: if a runtime already exists, swap it and dispose the loser.
		if (_channels.TryGetValue(channel, out ChannelRuntime? existing))
		{
			_logger.LogDebug("Replacing existing runtime for {Channel}", channel);
			_channels[channel] = runtime;
			await DisposeRuntimeSafelyAsync(existing).ConfigureAwait(false);
		}
		else
		{
			_channels[channel] = runtime;
		}

		try
		{
			await source.StartAsync(ct).ConfigureAwait(false);
			_health.ReportSuccess(channel);
			_statusSink?.SetChannelStatus(channel, "Armed");
			_logger.LogInformation("Watcher armed for channel {Channel}", channel);
		}
		catch (Exception ex)
		{
			_logger.LogWarning(ex, "Arm failed for {Channel}; delegating to fault handler", channel);
			await HandleFaultAsync(channel, xpathQuery, ex, isCallback: false).ConfigureAwait(false);
		}
	}

	/// <summary>Stop a single channel. Idempotent when the channel is unknown or already stopped.</summary>
	public async Task StopChannelAsync(string channel, CancellationToken ct)
	{
		ArgumentException.ThrowIfNullOrWhiteSpace(channel);

		if (!_channels.TryRemove(channel, out ChannelRuntime? runtime))
		{
			return;
		}

		await DisposeRuntimeSafelyAsync(runtime, ct).ConfigureAwait(false);
		_statusSink?.SetChannelStatus(channel, "Stopped");
	}

	/// <summary>Stop every channel currently held by the host.</summary>
	public async Task StopAllAsync(CancellationToken ct)
	{
		_shuttingDown = true;

		// Snapshot keys — ConcurrentDictionary enumeration is safe under concurrent modification
		// but we want deterministic teardown ordering (and to avoid re-entering the enumerator
		// once TryRemove starts modifying the map).
		List<string> keys = new();
		foreach (string k in _channels.Keys)
		{
			keys.Add(k);
		}

		foreach (string channel in keys)
		{
			if (_channels.TryRemove(channel, out ChannelRuntime? runtime))
			{
				await DisposeRuntimeSafelyAsync(runtime, ct).ConfigureAwait(false);
			}
		}
	}

	/// <summary>
	/// Persist all pending bookmarks to the <see cref="BookmarkStore"/>. Idempotent: bookmarks
	/// whose XML has not changed since the last successful flush are skipped. Safe to call from
	/// a periodic timer and from shutdown code back-to-back.
	/// </summary>
	public async Task FlushBookmarksAsync(CancellationToken ct)
	{
		Dictionary<string, string> snapshot = CreateBookmarkFlushSnapshot();
		if (snapshot.Count == 0)
		{
			return;
		}

		foreach (KeyValuePair<string, string> entry in snapshot)
		{
			try
			{
				await _bookmarks.SaveBookmarkAsync(entry.Key, entry.Value, ct).ConfigureAwait(false);

				lock (_bookmarkGate)
				{
					_flushedBookmarks[entry.Key] = entry.Value;
					_pendingBookmarkEventCounts[entry.Key] = 0;
				}
			}
			catch (OperationCanceledException) when (ct.IsCancellationRequested)
			{
				break;
			}
			catch (Exception ex)
			{
				_logger.LogDebug(ex, "Bookmark flush failed for {Channel}", entry.Key);
			}
		}
	}

	// ── Core Logic ───────────────────────────────────────────────────────────────

	private void TrackBookmark(string channel, string bookmarkXml)
	{
		int eventCount;
		bool shouldFlush;

		lock (_bookmarkGate)
		{
			_pendingBookmarks[channel] = bookmarkXml;

			_pendingBookmarkEventCounts.TryGetValue(channel, out eventCount);
			eventCount++;
			_pendingBookmarkEventCounts[channel] = eventCount;

			shouldFlush = eventCount >= PendingFlushEventThreshold;
			if (shouldFlush)
			{
				_pendingBookmarkEventCounts[channel] = 0;
			}
		}

		if (shouldFlush)
		{
			// Fire-and-forget: the periodic caller and shutdown path both cover missed flushes;
			// we just kick a background task when the per-channel event threshold trips so the
			// bookmark does not lag more than PendingFlushEventThreshold events behind reality.
			_ = FlushBookmarksAsync(CancellationToken.None);
		}
	}

	private async Task HandleFaultAsync(string channel, string xpathQuery, Exception ex, bool isCallback)
	{
		if (_shuttingDown)
		{
			return;
		}

		bool invalidHandleLike =
			ex is System.Diagnostics.Eventing.Reader.EventLogException ||
			ex is UnauthorizedAccessException ||
			ex.HResult == unchecked((int)0x80070006);

		ChannelHealthOutcome outcome = _health.ReportFailure(channel, invalidHandleLike);

		await DisposeChannelSourceAsync(channel).ConfigureAwait(false);

		switch (outcome.Decision)
		{
			case ChannelDecision.ResetBookmarkAndRestart:
				_statusSink?.SetChannelStatus(channel, "BookmarkReset");
				_logger.LogWarning(
					ex,
					"Watcher fault on {Channel} ({Source}); {Reason}. Resetting bookmark and restarting.",
					channel,
					isCallback ? "callback" : "arm",
					outcome.Reason);
				QueueRestart(channel, xpathQuery, resetBookmark: true);
				break;

			case ChannelDecision.Cooldown:
				_statusSink?.SetChannelStatus(channel, "RestartScheduled");
				_logger.LogDebug(
					ex,
					"Watcher fault on {Channel}; {Reason} (consecutiveFailures={ConsecutiveFailures})",
					channel,
					outcome.Reason,
					_health.ConsecutiveFailures(channel));
				QueueRestart(channel, xpathQuery, resetBookmark: false);
				break;

			case ChannelDecision.DisablePermanently:
				_statusSink?.SetChannelStatus(channel, "DisabledAfterFailures");
				if (_health.ClassifyChannel(channel) == ChannelImportance.Optional)
				{
					_logger.LogWarning(
						"Optional channel {Channel} disabled until service restart. {Reason}",
						channel,
						outcome.Reason);
				}
				else
				{
					_logger.LogError(
						ex,
						"Critical channel {Channel} disabled until service restart. {Reason}",
						channel,
						outcome.Reason);
				}
				break;

			default:
				_statusSink?.SetChannelStatus(channel, "RestartScheduled");
				QueueRestart(channel, xpathQuery, resetBookmark: false);
				break;
		}
	}

	private void QueueRestart(string channel, string xpathQuery, bool resetBookmark)
	{
		if (_shuttingDown)
		{
			return;
		}

		if (!_restartInFlight.TryAdd(channel, 0))
		{
			return; // another restart already in flight for this channel
		}

		_ = Task.Run(async () =>
		{
			bool arming = false;
			try
			{
				if (resetBookmark)
				{
					await ResetBookmarkStateAsync(channel, CancellationToken.None).ConfigureAwait(false);
				}
				else
				{
					await WaitForRestartGateAsync(channel, CancellationToken.None).ConfigureAwait(false);
				}

				if (_shuttingDown || _health.IsDisabled(channel))
				{
					return;
				}

				// Release the in-flight flag BEFORE arming so a fault during arm can queue a
				// fresh restart via HandleFaultAsync → QueueRestart without deadlocking against
				// the flag we still hold.
				arming = true;
				_restartInFlight.TryRemove(channel, out _);

				await StartChannelAsync(channel, xpathQuery, CancellationToken.None).ConfigureAwait(false);

				if (!_health.IsDisabled(channel))
				{
					_statusSink?.SetChannelStatus(channel, "RestartSucceeded");
				}
			}
			catch (Exception ex)
			{
				_logger.LogError(ex, "Restart loop for {Channel} threw", channel);
			}
			finally
			{
				if (!arming)
				{
					_restartInFlight.TryRemove(channel, out _);
				}
			}
		});
	}

	private async Task WaitForRestartGateAsync(string channel, CancellationToken ct)
	{
		DateTime? nextAllowedUtc = _health.NextAllowedRestartUtc(channel);
		if (nextAllowedUtc is null)
		{
			return;
		}

		TimeSpan delay = nextAllowedUtc.Value - DateTime.UtcNow;
		if (delay > TimeSpan.Zero)
		{
			await Task.Delay(delay, ct).ConfigureAwait(false);
		}
	}

	private async Task ResetBookmarkStateAsync(string channel, CancellationToken ct)
	{
		lock (_bookmarkGate)
		{
			_pendingBookmarks.Remove(channel);
			_flushedBookmarks.Remove(channel);
			_pendingBookmarkEventCounts.Remove(channel);
		}

		try
		{
			await _bookmarks.DeleteBookmarkAsync(channel, ct).ConfigureAwait(false);
			_logger.LogInformation("Bookmark reset for {Channel}", channel);
		}
		catch (OperationCanceledException) when (ct.IsCancellationRequested)
		{
			throw;
		}
		catch (Exception ex)
		{
			_logger.LogWarning(
				ex,
				"Bookmark delete failed for {Channel}; watcher rearm will continue without persisted bookmark cleanup",
				channel);
		}
	}

	// ── Error Handling & Retry ───────────────────────────────────────────────────

	private Dictionary<string, string> CreateBookmarkFlushSnapshot()
	{
		lock (_bookmarkGate)
		{
			Dictionary<string, string> snapshot = new(StringComparer.OrdinalIgnoreCase);

			foreach (KeyValuePair<string, string> entry in _pendingBookmarks)
			{
				if (_flushedBookmarks.TryGetValue(entry.Key, out string? previous) &&
					string.Equals(previous, entry.Value, StringComparison.Ordinal))
				{
					continue;
				}

				snapshot[entry.Key] = entry.Value;
			}

			return snapshot;
		}
	}

	private async Task DisposeChannelSourceAsync(string channel)
	{
		if (_channels.TryRemove(channel, out ChannelRuntime? runtime))
		{
			await DisposeRuntimeSafelyAsync(runtime).ConfigureAwait(false);
		}
	}

	private async Task DisposeRuntimeSafelyAsync(ChannelRuntime runtime, CancellationToken ct = default)
	{
		try
		{
			await runtime.Source.StopAsync(ct).ConfigureAwait(false);
		}
		catch (Exception ex)
		{
			_logger.LogDebug(ex, "StopAsync threw for {Channel}", runtime.Channel);
		}

		if (runtime.Source is IDisposable disposable)
		{
			try
			{
				disposable.Dispose();
			}
			catch (Exception ex)
			{
				_logger.LogDebug(ex, "Dispose threw for {Channel}", runtime.Channel);
			}
		}
		else if (runtime.Source is IAsyncDisposable asyncDisposable)
		{
			try
			{
				await asyncDisposable.DisposeAsync().ConfigureAwait(false);
			}
			catch (Exception ex)
			{
				_logger.LogDebug(ex, "DisposeAsync threw for {Channel}", runtime.Channel);
			}
		}
	}

	// ── Disposal & Pool Returns ──────────────────────────────────────────────────

	/// <inheritdoc />
	public async ValueTask DisposeAsync()
	{
		_shuttingDown = true;
		await StopAllAsync(CancellationToken.None).ConfigureAwait(false);
	}

	// ── Nested types ─────────────────────────────────────────────────────────────

	private sealed record ChannelRuntime(string Channel, string XpathQuery, IEventSource Source);
}
