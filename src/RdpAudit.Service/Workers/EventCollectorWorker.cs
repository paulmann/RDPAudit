/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 2.1.0
// File   : EventCollectorWorker.cs
// Project: RdpAudit.Service (RdpAudit.Service)
// Purpose: Collects Windows event records, manages watcher lifecycle, persists bookmarks, and recovers from stale Security bookmarks and channel faults without taking down the service.
// Depends: EventChannel, BookmarkStore, ServiceMetrics, IOptionsMonitor<RdpAuditOptions>, ChannelHealthPolicy, AuditDbContext, IOperationLogWriter, EventLogWatcher
// Extends: Adjust SecurityBookmarkStalenessThreshold, watcher query policy, and channel recovery behavior when adding a new event channel or ETW-backed source

using System.Collections.Concurrent;
using System.Diagnostics.Eventing.Reader;
using System.Runtime.Versioning;
using System.Text;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using RdpAudit.Core.Config;
using RdpAudit.Core.Data;
using RdpAudit.Core.Events;
using RdpAudit.Core.Models;
using RdpAudit.Service.Collectors;

namespace RdpAudit.Service.Workers;

/// <summary>
/// Collects configured Windows Event Log channels via <see cref="EventLogWatcher"/>, writes
/// normalised payload DTOs into the in-memory pipeline, persists per-channel bookmarks, and
/// performs bounded self-healing when a watcher or bookmark becomes stale.
/// </summary>
public sealed class EventCollectorWorker : BackgroundService
{
	// ── Fields & DI ──────────────────────────────────────────────────────────────

	private const int FlushEventThreshold = 100;
	private const int MaxEventXmlLength = 65_536;

	internal const int SkippedUnavailableReasonMaxLength = 120;
	internal static readonly TimeSpan FlushTimerPeriod = TimeSpan.FromSeconds(30);
	internal static readonly TimeSpan SecurityBookmarkStalenessThreshold = TimeSpan.FromMinutes(15);

	private readonly EventChannel _channel;
	private readonly BookmarkStore _bookmarks;
	private readonly ServiceMetrics _metrics;
	private readonly ILogger<EventCollectorWorker> _logger;
	private readonly IOptionsMonitor<RdpAuditOptions> _options;
	private readonly ChannelHealthPolicy _health;
	private readonly IDbContextFactory<AuditDbContext>? _factory;
	private readonly IOperationLogWriter? _opLog;

	private readonly ConcurrentDictionary<string, WatcherRegistration> _watchers = new(StringComparer.OrdinalIgnoreCase);
	private readonly ConcurrentDictionary<string, byte> _restartInFlight = new(StringComparer.OrdinalIgnoreCase);

	private readonly object _bookmarkGate = new();
	private readonly Dictionary<string, string> _pendingBookmarks = new(StringComparer.OrdinalIgnoreCase);
	private readonly Dictionary<string, string> _flushedBookmarks = new(StringComparer.OrdinalIgnoreCase);
	private readonly Dictionary<string, int> _pendingBookmarkEventCounts = new(StringComparer.OrdinalIgnoreCase);

	private CancellationTokenSource? _shutdownCts;
	private CancellationToken _serviceToken;
	private Task? _bookmarkFlushLoopTask;

	private int _bookmarkFlushScheduled;
	private volatile bool _shuttingDown;

	// ── Construction ─────────────────────────────────────────────────────────────

	public EventCollectorWorker(
		EventChannel channel,
		BookmarkStore bookmarks,
		ServiceMetrics metrics,
		ILogger<EventCollectorWorker> logger,
		IOptionsMonitor<RdpAuditOptions> options,
		IDbContextFactory<AuditDbContext> factory,
		IOperationLogWriter opLog)
		: this(channel, bookmarks, metrics, logger, options, new ChannelHealthPolicy(), factory, opLog)
	{
	}

	internal EventCollectorWorker(
		EventChannel channel,
		BookmarkStore bookmarks,
		ServiceMetrics metrics,
		ILogger<EventCollectorWorker> logger,
		IOptionsMonitor<RdpAuditOptions> options,
		ChannelHealthPolicy health,
		IDbContextFactory<AuditDbContext>? factory = null,
		IOperationLogWriter? opLog = null)
	{
		ArgumentNullException.ThrowIfNull(channel);
		ArgumentNullException.ThrowIfNull(bookmarks);
		ArgumentNullException.ThrowIfNull(metrics);
		ArgumentNullException.ThrowIfNull(logger);
		ArgumentNullException.ThrowIfNull(options);
		ArgumentNullException.ThrowIfNull(health);

		_channel = channel;
		_bookmarks = bookmarks;
		_metrics = metrics;
		_logger = logger;
		_options = options;
		_health = health;
		_factory = factory;
		_opLog = opLog;
	}

	// ── Public API ───────────────────────────────────────────────────────────────

	protected override async Task ExecuteAsync(CancellationToken stoppingToken)
	{
		_shutdownCts = CancellationTokenSource.CreateLinkedTokenSource(stoppingToken);
		_serviceToken = _shutdownCts.Token;

		_logger.LogInformation("{Worker} starting", nameof(EventCollectorWorker));

		if (!OperatingSystem.IsWindows())
		{
			_logger.LogWarning("EventLogWatcher requires Windows; collector will idle on this host");
			await Task.Delay(Timeout.InfiniteTimeSpan, _serviceToken).ConfigureAwait(false);
			return;
		}

		try
		{
			await ReconcileStartupStateAsync(_serviceToken).ConfigureAwait(false);

			ArmConfiguredChannels();

			_bookmarkFlushLoopTask = RunBookmarkFlushLoopAsync(_serviceToken);

			await Task.Delay(Timeout.InfiniteTimeSpan, _serviceToken).ConfigureAwait(false);
		}
		catch (OperationCanceledException) when (_serviceToken.IsCancellationRequested)
		{
		}
		catch (Exception ex)
		{
			_logger.LogCritical(ex, "{Worker} faulted; collection is degraded but the host will stay up", nameof(EventCollectorWorker));

			if (_opLog is not null)
			{
				await _opLog.ErrorAsync(
					"EventCollector",
					"WatcherFault",
					"Event collector faulted; collection is degraded but the service host remains available.",
					ex,
					OperationLogSeverity.Critical,
					_serviceToken).ConfigureAwait(false);
			}

			try
			{
				await Task.Delay(Timeout.InfiniteTimeSpan, _serviceToken).ConfigureAwait(false);
			}
			catch (OperationCanceledException)
			{
			}
		}
		finally
		{
			await ShutdownAsync().ConfigureAwait(false);
		}
	}

	public override async Task StopAsync(CancellationToken cancellationToken)
	{
		_shuttingDown = true;

		try
		{
			_shutdownCts?.Cancel();
		}
		catch (ObjectDisposedException)
		{
		}

		await base.StopAsync(cancellationToken).ConfigureAwait(false);
	}

	internal static (string Xpath, IReadOnlyList<int> Ids) BuildWatcherQuery(
		string channel,
		IReadOnlyCollection<int> globalFilter)
	{
		ArgumentNullException.ThrowIfNull(channel);
		ArgumentNullException.ThrowIfNull(globalFilter);

		bool isSecurity = string.Equals(channel, EventCatalog.ChannelSecurity, StringComparison.OrdinalIgnoreCase);
		List<int> channelIds = CollectChannelEventIds(channel, globalFilter);

		if (isSecurity)
		{
			List<int> securityIds = CollectSecurityAuthEventIds(channelIds, globalFilter.Count > 0);
			if (securityIds.Count == 0)
			{
				for (int i = 0; i < SecurityAuthQuery.AuthEventIds.Count; i++)
				{
					securityIds.Add(SecurityAuthQuery.AuthEventIds[i]);
				}
			}

			return (SecurityAuthQuery.BuildXPath(securityIds), securityIds);
		}

		if (channelIds.Count == 0)
		{
			return ("*", channelIds);
		}

		StringBuilder xpath = new(64 + (channelIds.Count * 16));
		xpath.Append("*[System[(");

		for (int i = 0; i < channelIds.Count; i++)
		{
			if (i > 0)
			{
				xpath.Append(" or ");
			}

			xpath.Append("EventID=");
			xpath.Append(channelIds[i]);
		}

		xpath.Append(")]]");
		return (xpath.ToString(), channelIds);
	}

	internal static string BuildSkippedUnavailableStatus(string reason)
	{
		const string statusToken = "SkippedUnavailable";

		if (string.IsNullOrEmpty(reason))
		{
			return statusToken;
		}

		string trimmed = reason.Length > SkippedUnavailableReasonMaxLength
			? reason[..SkippedUnavailableReasonMaxLength] + "..."
			: reason;

		return statusToken + ": " + trimmed;
	}

	// ── Core Logic ───────────────────────────────────────────────────────────────

	private async Task ReconcileStartupStateAsync(CancellationToken ct)
	{
		if (_factory is null)
		{
			return;
		}

		string? existingSecurityBookmark = _bookmarks.GetBookmarkXml(EventCatalog.ChannelSecurity);
		if (existingSecurityBookmark is null)
		{
			return;
		}

		try
		{
			(bool shouldReset, string reason, DateTime? lastSecurityAuthUtc, DateTime? lastRdpSignalUtc) =
				await EvaluateStartupSecurityBookmarkAsync(ct).ConfigureAwait(false);

			if (!shouldReset)
			{
				return;
			}

			await ResetBookmarkStateAsync(EventCatalog.ChannelSecurity, ct).ConfigureAwait(false);

			_logger.LogInformation(
				"Reset stale Security bookmark before arming watcher. Reason={Reason}; LastSecurityAuthUtc={LastSecurityAuthUtc}; LastRdpSignalUtc={LastRdpSignalUtc}",
				reason,
				lastSecurityAuthUtc,
				lastRdpSignalUtc);
		}
		catch (OperationCanceledException) when (ct.IsCancellationRequested)
		{
		}
		catch (Exception ex)
		{
			_logger.LogDebug(ex, "Startup Security bookmark reconciliation failed; continuing with current bookmark");
		}
	}

	private async Task<(bool ShouldReset, string Reason, DateTime? LastSecurityAuthUtc, DateTime? LastRdpSignalUtc)> EvaluateStartupSecurityBookmarkAsync(CancellationToken ct)
	{
		await using AuditDbContext db = await _factory!.CreateDbContextAsync(ct).ConfigureAwait(false);

		bool anyAuthAttemptFact = await db.AuthAttemptFacts
			.AsNoTracking()
			.AnyAsync(ct)
			.ConfigureAwait(false);

		if (!anyAuthAttemptFact)
		{
			return (true, "NoAuthAttemptFactsPersisted", null, null);
		}

		DateTime? lastSecurityAuthUtc = await db.RawEvents
			.AsNoTracking()
			.Where(e =>
				e.Channel == EventCatalog.ChannelSecurity &&
				(e.EventId == 4624 || e.EventId == 4625 || e.EventId == 4648))
			.OrderByDescending(e => e.TimeUtc)
			.Select(e => (DateTime?)e.TimeUtc)
			.FirstOrDefaultAsync(ct)
			.ConfigureAwait(false);

		DateTime? lastRdpSignalUtc = await db.RawEvents
			.AsNoTracking()
			.Where(e =>
				(e.Channel == EventCatalog.ChannelTsRemote && (e.EventId == 1149 || e.EventId == 261)) ||
				(e.Channel == EventCatalog.ChannelRdpCore && (e.EventId == 131 || e.EventId == 140)) ||
				(e.Channel == EventCatalog.ChannelTsLocal && (e.EventId == 21 || e.EventId == 24 || e.EventId == 25 || e.EventId == 39 || e.EventId == 40)))
			.OrderByDescending(e => e.TimeUtc)
			.Select(e => (DateTime?)e.TimeUtc)
			.FirstOrDefaultAsync(ct)
			.ConfigureAwait(false);

		if (lastRdpSignalUtc is null)
		{
			return (false, "NoRecentRdpSignalObserved", lastSecurityAuthUtc, null);
		}

		if (lastSecurityAuthUtc is null)
		{
			return (true, "NoPersistedSecurityAuthEvent", null, lastRdpSignalUtc);
		}

		TimeSpan lag = lastRdpSignalUtc.Value - lastSecurityAuthUtc.Value;
		if (lag > SecurityBookmarkStalenessThreshold)
		{
			return (true, "SecurityAuthLagExceededThreshold", lastSecurityAuthUtc, lastRdpSignalUtc);
		}

		return (false, "SecurityAuthStreamHealthy", lastSecurityAuthUtc, lastRdpSignalUtc);
	}

	[SupportedOSPlatform("windows")]
	private void ArmConfiguredChannels()
	{
		RdpAuditOptions options = _options.CurrentValue;
		HashSet<string> seen = new(StringComparer.OrdinalIgnoreCase);

		if (options.Monitoring.EnabledChannels.Count > 0)
		{
			for (int i = 0; i < options.Monitoring.EnabledChannels.Count; i++)
			{
				string channel = options.Monitoring.EnabledChannels[i];
				if (seen.Add(channel))
				{
					ArmChannel(channel);
				}
			}

			return;
		}

		foreach (string channel in EventCatalog.AllChannels())
		{
			if (seen.Add(channel))
			{
				ArmChannel(channel);
			}
		}
	}

	[SupportedOSPlatform("windows")]
	private void ArmChannel(string channel)
	{
		if (_shuttingDown || _serviceToken.IsCancellationRequested)
		{
			return;
		}

		ChannelProbeResult probe = ChannelCapability.Probe(channel);
		if (!probe.IsAvailable)
		{
			ChannelImportance importance = _health.ClassifyChannel(channel);
			if (importance == ChannelImportance.Optional)
			{
				_health.ReportUnavailable(channel, probe.Reason);
				_metrics.SetChannelStatus(channel, BuildSkippedUnavailableStatus(probe.Reason));

				_logger.LogWarning(
					"Skipping optional channel {Channel}: {Reason}",
					channel,
					probe.Reason);

				return;
			}

			_logger.LogError(
				"Critical channel {Channel} failed capability probe: {Reason}. Will attempt to arm anyway.",
				channel,
				probe.Reason);
		}

		try
		{
			WatcherRegistration registration = CreateWatcherRegistration(channel);
			ReplaceWatcherRegistration(channel, registration);

			_health.ReportSuccess(channel);
			_metrics.SetChannelStatus(channel, "Armed");

			if (string.Equals(channel, EventCatalog.ChannelSecurity, StringComparison.OrdinalIgnoreCase))
			{
				_metrics.SetSecurityWatcherEnabled(true);
			}

			_logger.LogInformation("Watcher armed for channel {Channel}", channel);
		}
		catch (Exception ex)
		{
			HandleWatcherFailure(channel, ex, isCallback: false);
		}
	}

	[SupportedOSPlatform("windows")]
	private WatcherRegistration CreateWatcherRegistration(string channel)
	{
		EventLogWatcher watcher = CreateWatcher(channel);
		EventRecordWrittenEventHandler handler = (_, args) => OnEventRecordWritten(channel, args);

		watcher.EventRecordWritten += handler;
		watcher.Enabled = true;

		return new WatcherRegistration(channel, watcher, handler);
	}

	[SupportedOSPlatform("windows")]
	private EventLogWatcher CreateWatcher(string channel)
	{
		IReadOnlyCollection<int> filterSet = _options.CurrentValue.Monitoring.EnabledEventIds;
		(string xpath, _) = BuildWatcherQuery(channel, filterSet);

		EventLogQuery query = new(channel, PathType.LogName, xpath)
		{
			ReverseDirection = false,
		};

		string? bookmarkXml = _bookmarks.GetBookmarkXml(channel);

		if (bookmarkXml is null)
		{
			return new EventLogWatcher(query);
		}

		try
		{
			return new EventLogWatcher(query, BookmarkSerializer.Deserialize(bookmarkXml));
		}
		catch (EventLogException ex)
		{
			_logger.LogWarning(
				ex,
				"Watcher constructor rejected bookmark for {Channel}; rearming without bookmark and scheduling bookmark deletion",
				channel);

			QueueBackgroundOperation(
				"DeleteRejectedBookmark",
				async token => await ResetBookmarkStateAsync(channel, token).ConfigureAwait(false));

			return new EventLogWatcher(query);
		}
	}

	[SupportedOSPlatform("windows")]
	private void OnEventRecordWritten(string channel, EventRecordWrittenEventArgs args)
	{
		if (args.EventException is not null)
		{
			HandleWatcherFailure(channel, args.EventException, isCallback: true);
			return;
		}

		if (args.EventRecord is null)
		{
			_metrics.SetChannelStatus(channel, "Stalled");
			QueueRestart(channel, RestartMode.RestartOnly);
			return;
		}

		if (!TryCaptureDto(channel, args.EventRecord, out RawEventDto? dto, out string? bookmarkXml))
		{
			return;
		}

		if (!_channel.Channel.TryWrite(dto))
		{
			_metrics.IncrementDropped();
			_metrics.IncrementRingBufferOverflow();

			if (_options.CurrentValue.Diagnostics.LogChannelDrops)
			{
				_logger.LogWarning(
					"Event channel full; dropped EventID {EventId} from {Channel}",
					dto.EventId,
					dto.Channel);
			}
		}
		else
		{
			_metrics.IncrementCaptured();
		}

		if (bookmarkXml is null)
		{
			return;
		}

		bool flushImmediately = TrackPendingBookmark(channel, bookmarkXml);
		if (flushImmediately)
		{
			QueueBookmarkFlush();
		}
	}

	[SupportedOSPlatform("windows")]
	private bool TryCaptureDto(string channel, EventRecord record, out RawEventDto dto, out string? bookmarkXml)
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
						channel,
						record.Id,
						xml.Length,
						MaxEventXmlLength);

					xml = xml[..MaxEventXmlLength];
				}

				dto = new RawEventDto
				{
					EventId = record.Id,
					Channel = record.LogName ?? channel,
					TimeUtc = record.TimeCreated?.ToUniversalTime() ?? DateTime.UtcNow,
					XmlPayload = xml,
				};

				try
				{
					bookmarkXml = BookmarkSerializer.Serialize(record.Bookmark);
				}
				catch (Exception ex)
				{
					_logger.LogDebug(ex, "Bookmark capture failed for {Channel}", channel);
				}

				return true;
			}
		}
		catch (EventLogException ex)
		{
			_logger.LogError(ex, "Failed reading EventRecord for {Channel}", channel);
			return false;
		}
	}

	[SupportedOSPlatform("windows")]
	private void HandleWatcherFailure(string channel, Exception ex, bool isCallback)
	{
		if (_shuttingDown)
		{
			return;
		}

		bool invalidHandleLike =
			ex is EventLogException ||
			ex is UnauthorizedAccessException ||
			ex.HResult == unchecked((int)0x80070006);

		ChannelHealthOutcome outcome = _health.ReportFailure(channel, invalidHandleLike);

		DisposeWatcher(channel);

		switch (outcome.Decision)
		{
			case ChannelDecision.ResetBookmarkAndRestart:
				_metrics.SetChannelStatus(channel, "BookmarkReset");
				_logger.LogWarning(
					ex,
					"Watcher fault on {Channel} ({Source}); {Reason}. Resetting bookmark and restarting watcher.",
					channel,
					isCallback ? "callback" : "arm",
					outcome.Reason);
				QueueRestart(channel, RestartMode.ResetBookmarkThenRestart);
				break;

			case ChannelDecision.Cooldown:
				_metrics.SetChannelStatus(channel, "RestartScheduled");
				_logger.LogDebug(
					ex,
					"Watcher fault on {Channel}; {Reason} (consecutiveFailures={ConsecutiveFailures})",
					channel,
					outcome.Reason,
					_health.ConsecutiveFailures(channel));
				QueueRestart(channel, RestartMode.RestartOnly);
				break;

			case ChannelDecision.DisablePermanently:
				_metrics.SetChannelStatus(channel, "DisabledAfterFailures");

				if (string.Equals(channel, EventCatalog.ChannelSecurity, StringComparison.OrdinalIgnoreCase))
				{
					_metrics.SetSecurityWatcherEnabled(false);
					_metrics.SetLastSecurityChannelError("DisabledAfterFailures: " + outcome.Reason);
				}

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
				_metrics.SetChannelStatus(channel, "RestartScheduled");
				QueueRestart(channel, RestartMode.RestartOnly);
				break;
		}
	}

	[SupportedOSPlatform("windows")]
	private void QueueRestart(string channel, RestartMode mode)
	{
		if (_shuttingDown || _serviceToken.IsCancellationRequested)
		{
			return;
		}

		if (!_restartInFlight.TryAdd(channel, 0))
		{
			return;
		}

		QueueBackgroundOperation(
			"RestartWatcher:" + channel,
			async token =>
			{
				try
				{
					if (mode == RestartMode.RestartOnly)
					{
						await WaitForRestartGateAsync(channel, token).ConfigureAwait(false);
					}
					else
					{
						await ResetBookmarkStateAsync(channel, token).ConfigureAwait(false);
					}

					if (_shuttingDown || token.IsCancellationRequested || _health.IsDisabled(channel))
					{
						return;
					}

					ArmChannel(channel);

					if (!_health.IsDisabled(channel))
					{
						_metrics.SetChannelStatus(channel, "RestartSucceeded");
					}
				}
				finally
				{
					_restartInFlight.TryRemove(channel, out _);
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

	private bool TrackPendingBookmark(string channel, string bookmarkXml)
	{
		lock (_bookmarkGate)
		{
			_pendingBookmarks[channel] = bookmarkXml;

			_pendingBookmarkEventCounts.TryGetValue(channel, out int eventCount);
			eventCount++;
			_pendingBookmarkEventCounts[channel] = eventCount;

			if (eventCount < FlushEventThreshold)
			{
				return false;
			}

			_pendingBookmarkEventCounts[channel] = 0;
			return true;
		}
	}

	private void QueueBookmarkFlush()
	{
		if (_shuttingDown || _serviceToken.IsCancellationRequested)
		{
			return;
		}

		if (Interlocked.Exchange(ref _bookmarkFlushScheduled, 1) != 0)
		{
			return;
		}

		QueueBackgroundOperation(
			"FlushBookmarks",
			async token =>
			{
				try
				{
					await FlushPendingBookmarksAsync(token).ConfigureAwait(false);
				}
				finally
				{
					Interlocked.Exchange(ref _bookmarkFlushScheduled, 0);

					if (HasUnflushedBookmarks())
					{
						QueueBookmarkFlush();
					}
				}
			});
	}

	private async Task RunBookmarkFlushLoopAsync(CancellationToken ct)
	{
		try
		{
			using PeriodicTimer timer = new(FlushTimerPeriod);

			while (await timer.WaitForNextTickAsync(ct).ConfigureAwait(false))
			{
				await FlushPendingBookmarksAsync(ct).ConfigureAwait(false);
			}
		}
		catch (OperationCanceledException) when (ct.IsCancellationRequested)
		{
		}
		catch (Exception ex)
		{
			_logger.LogError(ex, "Bookmark flush loop faulted");
		}
	}

	private async Task FlushPendingBookmarksAsync(CancellationToken ct)
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

	private bool HasUnflushedBookmarks()
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

	private async Task ResetBookmarkStateAsync(string channel, CancellationToken ct)
	{
		ForgetBookmarkState(channel);

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

	private void ForgetBookmarkState(string channel)
	{
		lock (_bookmarkGate)
		{
			_pendingBookmarks.Remove(channel);
			_flushedBookmarks.Remove(channel);
			_pendingBookmarkEventCounts.Remove(channel);
		}
	}

	private void QueueBackgroundOperation(string name, Func<CancellationToken, Task> operation)
	{
		if (_shuttingDown || _serviceToken.IsCancellationRequested)
		{
			return;
		}

		_ = Task.Run(
			async () =>
			{
				try
				{
					await operation(_serviceToken).ConfigureAwait(false);
				}
				catch (OperationCanceledException) when (_serviceToken.IsCancellationRequested)
				{
				}
				catch (Exception ex)
				{
					_logger.LogDebug(ex, "Background operation {OperationName} faulted", name);
				}
			},
			_serviceToken);
	}

	// ── Error Handling & Retry ───────────────────────────────────────────────────

	[SupportedOSPlatform("windows")]
	private void ReplaceWatcherRegistration(string channel, WatcherRegistration registration)
	{
		if (_watchers.TryRemove(channel, out WatcherRegistration? existing))
		{
			SafeDisposeWatcher(existing);
		}

		_watchers[channel] = registration;
	}

	[SupportedOSPlatform("windows")]
	private void DisposeWatcher(string channel)
	{
		if (_watchers.TryRemove(channel, out WatcherRegistration? registration))
		{
			SafeDisposeWatcher(registration);
		}
	}

	// ── Disposal & Pool Returns ──────────────────────────────────────────────────

	private async Task ShutdownAsync()
	{
		_shuttingDown = true;

		try
		{
			_shutdownCts?.Cancel();
		}
		catch (ObjectDisposedException)
		{
		}

		DisposeAllWatchers();

		if (_bookmarkFlushLoopTask is not null)
		{
			try
			{
				await _bookmarkFlushLoopTask.ConfigureAwait(false);
			}
			catch (OperationCanceledException)
			{
			}
		}

		try
		{
			await FlushPendingBookmarksAsync(CancellationToken.None).ConfigureAwait(false);
		}
		catch (Exception ex)
		{
			_logger.LogDebug(ex, "Final bookmark flush failed");
		}

		_shutdownCts?.Dispose();
		_shutdownCts = null;

		_logger.LogInformation("{Worker} stopped", nameof(EventCollectorWorker));
	}

	[SupportedOSPlatform("windows")]
	private static void SafeDisposeWatcher(WatcherRegistration? registration)
	{
		if (registration is null)
		{
			return;
		}

		try
		{
			registration.Watcher.EventRecordWritten -= registration.Handler;
		}
		catch
		{
		}

		try
		{
			registration.Watcher.Enabled = false;
		}
		catch
		{
		}

		try
		{
			registration.Watcher.Dispose();
		}
		catch
		{
		}
	}

	private void DisposeAllWatchers()
	{
		if (!OperatingSystem.IsWindows())
		{
			return;
		}

		foreach (KeyValuePair<string, WatcherRegistration> entry in _watchers)
		{
			if (_watchers.TryRemove(entry.Key, out WatcherRegistration? registration))
			{
				SafeDisposeWatcher(registration);
			}
		}
	}

	private static List<int> CollectChannelEventIds(string channel, IReadOnlyCollection<int> globalFilter)
	{
		List<int> ids = new();

		if (globalFilter.Count == 0)
		{
			foreach (int eventId in EventCatalog.EventIdsForChannel(channel))
			{
				ids.Add(eventId);
			}

			return ids;
		}

		HashSet<int> filter = new(globalFilter);
		foreach (int eventId in EventCatalog.EventIdsForChannel(channel))
		{
			if (filter.Contains(eventId))
			{
				ids.Add(eventId);
			}
		}

		return ids;
	}

	private static List<int> CollectSecurityAuthEventIds(List<int> channelIds, bool useFilteredChannelIds)
	{
		HashSet<int> authIds = new(SecurityAuthQuery.AuthEventIds);
		List<int> result = new();

		if (!useFilteredChannelIds)
		{
			for (int i = 0; i < SecurityAuthQuery.AuthEventIds.Count; i++)
			{
				result.Add(SecurityAuthQuery.AuthEventIds[i]);
			}

			return result;
		}

		for (int i = 0; i < channelIds.Count; i++)
		{
			int candidate = channelIds[i];
			if (authIds.Contains(candidate))
			{
				result.Add(candidate);
			}
		}

		return result;
	}

	private enum RestartMode : byte
	{
		RestartOnly = 0,
		ResetBookmarkThenRestart = 1,
	}

	private sealed class WatcherRegistration
	{
		public WatcherRegistration(string channel, EventLogWatcher watcher, EventRecordWrittenEventHandler handler)
		{
			Channel = channel;
			Watcher = watcher;
			Handler = handler;
		}

		public string Channel { get; }

		public EventLogWatcher Watcher { get; }

		public EventRecordWrittenEventHandler Handler { get; }
	}
}
