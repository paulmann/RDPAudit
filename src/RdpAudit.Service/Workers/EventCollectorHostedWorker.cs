/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 2.0.2
// File   : EventCollectorHostedWorker.cs
// Project: RdpAudit.Service (RdpAudit.Service.Workers)
// Purpose: Thin BackgroundService shim over EventCollectorHost. Owns three orchestration
//          responsibilities the Host does NOT: startup Security-bookmark reconciliation (which
//          needs a live AuditDbContext), building each channel's XPath and probing its capability
//          before arming, and a periodic bookmark-flush cadence. Everything else — real-time
//          arming, watcher fault dispatch, cooldown restarts, bookmark aggregation, shutdown —
//          is delegated to the injected EventCollectorHost.
//          Replaces the legacy EventCollectorWorker (retired in v2.3.x); this is now the sole
//          rewriting existing tests. Once Program.cs is switched to register this class, the
//          legacy monolith can be retired.
// Depends: EventCollectorHost, ChannelCapability, ChannelHealthPolicy, BookmarkStore,
//          ServiceMetrics, EventCatalog, SecurityAuthQuery, AuditDbContext, IOperationLogWriter,
//          IOptionsMonitor<RdpAuditOptions>
// Extends: When a channel needs a bespoke XPath, extend BuildWatcherQuery — do NOT hand-roll the
//          arm loop here. When shutdown needs an extra flush pass, put it in StopAsync and rely
//          on EventCollectorHost.FlushBookmarksAsync being idempotent.

using System.Diagnostics.Eventing.Reader;
using System.Globalization;
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
using RdpAudit.Service.EventSources;

namespace RdpAudit.Service.Workers;

/// <summary>
/// Thin BackgroundService that composes <see cref="EventCollectorHost"/>. It probes and arms the
/// configured channels once at startup, kicks a periodic bookmark-flush timer, then idles until
/// stop is requested.
/// </summary>
public sealed class EventCollectorHostedWorker : BackgroundService
{
	// ── Fields & DI ──────────────────────────────────────────────────────────────

	internal const int SkippedUnavailableReasonMaxLength = 120;
	internal static readonly TimeSpan FlushTimerPeriod = TimeSpan.FromSeconds(30);
	internal static readonly TimeSpan SecurityBookmarkStalenessThreshold = TimeSpan.FromMinutes(15);

	private readonly EventCollectorHost _host;
	private readonly BookmarkStore _bookmarks;
	private readonly ChannelHealthPolicy _health;
	private readonly ServiceMetrics _metrics;
	private readonly IOptionsMonitor<RdpAuditOptions> _options;
	private readonly IDbContextFactory<AuditDbContext>? _factory;
	private readonly IOperationLogWriter? _opLog;
	private readonly ILogger<EventCollectorHostedWorker> _logger;

	private CancellationTokenSource? _linkedCts;

	// ── Construction ─────────────────────────────────────────────────────────────

	public EventCollectorHostedWorker(
		EventCollectorHost host,
		BookmarkStore bookmarks,
		ChannelHealthPolicy health,
		ServiceMetrics metrics,
		IOptionsMonitor<RdpAuditOptions> options,
		ILogger<EventCollectorHostedWorker> logger,
		IDbContextFactory<AuditDbContext>? factory = null,
		IOperationLogWriter? opLog = null)
	{
		ArgumentNullException.ThrowIfNull(host);
		ArgumentNullException.ThrowIfNull(bookmarks);
		ArgumentNullException.ThrowIfNull(health);
		ArgumentNullException.ThrowIfNull(metrics);
		ArgumentNullException.ThrowIfNull(options);
		ArgumentNullException.ThrowIfNull(logger);

		_host = host;
		_bookmarks = bookmarks;
		_health = health;
		_metrics = metrics;
		_options = options;
		_logger = logger;
		_factory = factory;
		_opLog = opLog;
	}

	// ── Public API ───────────────────────────────────────────────────────────────

	protected override async Task ExecuteAsync(CancellationToken stoppingToken)
	{
		_linkedCts = CancellationTokenSource.CreateLinkedTokenSource(stoppingToken);
		CancellationToken serviceToken = _linkedCts.Token;

		_logger.LogInformation("{Worker} starting", nameof(EventCollectorHostedWorker));

		if (!OperatingSystem.IsWindows())
		{
			_logger.LogWarning("EventLogWatcher requires Windows; hosted collector will idle on this host");
			try
			{
				await Task.Delay(Timeout.InfiniteTimeSpan, serviceToken).ConfigureAwait(false);
			}
			catch (OperationCanceledException)
			{
			}

			return;
		}

		try
		{
			await ReconcileStartupStateAsync(serviceToken).ConfigureAwait(false);

			await ArmConfiguredChannelsAsync(serviceToken).ConfigureAwait(false);

			await RunFlushLoopAsync(serviceToken).ConfigureAwait(false);
		}
		catch (OperationCanceledException) when (serviceToken.IsCancellationRequested)
		{
		}
		catch (Exception ex)
		{
			_logger.LogCritical(ex, "{Worker} faulted; collection is degraded but the host will stay up", nameof(EventCollectorHostedWorker));

			if (_opLog is not null)
			{
				try
				{
					await _opLog.ErrorAsync(
						"EventCollector",
						"WatcherFault",
						"Hosted event collector faulted; collection is degraded but the service host remains available.",
						ex,
						OperationLogSeverity.Critical,
						serviceToken).ConfigureAwait(false);
				}
				catch (Exception logEx)
				{
					_logger.LogDebug(logEx, "Operation log write for hosted collector fault failed");
				}
			}

			try
			{
				await Task.Delay(Timeout.InfiniteTimeSpan, serviceToken).ConfigureAwait(false);
			}
			catch (OperationCanceledException)
			{
			}
		}
	}

	public override async Task StopAsync(CancellationToken cancellationToken)
	{
		_logger.LogInformation("{Worker} stop requested", nameof(EventCollectorHostedWorker));

		try
		{
			_linkedCts?.Cancel();
		}
		catch (ObjectDisposedException)
		{
		}

		// Final bookmark flush — Host guarantees idempotency, safe to call even if the flush
		// loop already ran a moment ago.
		try
		{
			await _host.FlushBookmarksAsync(cancellationToken).ConfigureAwait(false);
		}
		catch (Exception ex)
		{
			_logger.LogDebug(ex, "Final bookmark flush during shutdown failed");
		}

		try
		{
			await _host.StopAllAsync(cancellationToken).ConfigureAwait(false);
		}
		catch (Exception ex)
		{
			_logger.LogDebug(ex, "Host StopAllAsync during shutdown reported an error");
		}

		await base.StopAsync(cancellationToken).ConfigureAwait(false);
	}

	// ── SIMD & Zero-Alloc Parsers ────────────────────────────────────────────────

	/// <summary>
	/// Builds the XPath query and returns the effective event-id list for <paramref name="channel"/>.
	/// Kept as a public static so future hosts (ETW replay, EVTX offline) can share the same
	/// filter logic without depending on this worker's lifecycle. When
	/// <paramref name="firstReadFloorUtc"/> is supplied the query gains a TimeCreated lower
	/// bound so a bookmark-less arm does not replay unbounded channel history.
	/// </summary>
	public static (string Xpath, IReadOnlyList<int> Ids) BuildWatcherQuery(
		string channel,
		IReadOnlyCollection<int> globalFilter,
		DateTime? firstReadFloorUtc = null)
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

			return firstReadFloorUtc is { } floor
				? (SecurityAuthQuery.BuildXPath(securityIds, floor), securityIds)
				: (SecurityAuthQuery.BuildXPath(securityIds), securityIds);
		}

		if (channelIds.Count == 0)
		{
			if (firstReadFloorUtc is { } wildcardFloor)
			{
				string isoFloor = wildcardFloor.ToString("yyyy-MM-ddTHH:mm:ss.fffZ", CultureInfo.InvariantCulture);
				return ("*[System[TimeCreated[@SystemTime >= '" + isoFloor + "']]]", channelIds);
			}

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

		xpath.Append(')');
		if (firstReadFloorUtc is { } floorUtc)
		{
			xpath.Append(" and TimeCreated[@SystemTime >= '");
			xpath.Append(floorUtc.ToString("yyyy-MM-ddTHH:mm:ss.fffZ", CultureInfo.InvariantCulture));
			xpath.Append("']");
		}

		xpath.Append("]]");
		return (xpath.ToString(), channelIds);
	}

	/// <summary>
	/// Formats an "unavailable" reason string for <see cref="ServiceMetrics.SetChannelStatus"/>.
	/// Bounded length prevents pathological probe errors from bloating diagnostics.
	/// </summary>
	public static string BuildSkippedUnavailableStatus(string reason)
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

			await _bookmarks.DeleteBookmarkAsync(EventCatalog.ChannelSecurity, ct).ConfigureAwait(false);

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
	private async Task ArmConfiguredChannelsAsync(CancellationToken ct)
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
					await ArmChannelAsync(channel, options.Monitoring.EnabledEventIds, ct).ConfigureAwait(false);
				}
			}

			return;
		}

		foreach (string channel in EventCatalog.AllChannels())
		{
			if (seen.Add(channel))
			{
				await ArmChannelAsync(channel, options.Monitoring.EnabledEventIds, ct).ConfigureAwait(false);
			}
		}
	}

	[SupportedOSPlatform("windows")]
	private async Task ArmChannelAsync(string channel, IReadOnlyCollection<int> filterSet, CancellationToken ct)
	{
		if (ct.IsCancellationRequested)
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

				if (probe.Reason.StartsWith("Access denied", StringComparison.OrdinalIgnoreCase))
				{
					// Channel exists but this account cannot read it - a real audit-coverage gap.
					_logger.LogWarning(
						"Optional channel {Channel} exists but is not readable: {Reason}",
						channel,
						probe.Reason);
				}
				else
				{
					_logger.LogInformation(
						"Skipping optional channel {Channel}: {Reason}",
						channel,
						probe.Reason);
				}

				return;
			}

			_logger.LogError(
				"Critical channel {Channel} failed capability probe: {Reason}. Will attempt to arm anyway.",
				channel,
				probe.Reason);
		}

		// Per-channel startup position diagnostics BEFORE arming/replay: operators can see,
		// for every enabled channel, whether ingestion resumes from a persisted bookmark or
		// reads a bounded first-read window. This closes the gap where the only observable
		// startup signal was the global "Loaded N bookmarks" line followed by silence.
		string? persistedBookmark = _bookmarks.GetBookmarkXml(channel);
		DateTime? firstReadFloorUtc = null;

		if (persistedBookmark is null)
		{
			int lookbackHours = Math.Max(0, _options.CurrentValue.Monitoring.FirstReadLookbackHours);
			if (lookbackHours > 0)
			{
				firstReadFloorUtc = DateTime.UtcNow - TimeSpan.FromHours(lookbackHours);
				_logger.LogInformation(
					"Channel {Channel}: no persisted bookmark - arming with first-read window {LookbackHours}h (FirstReadLookbackHours).",
					channel,
					lookbackHours);
			}
			else
			{
				_logger.LogWarning(
					"Channel {Channel}: no persisted bookmark and FirstReadLookbackHours=0 - replaying the full matching channel history.",
					channel);
			}
		}
		else
		{
			// D1 resume diagnostic. Restart idempotency is delivered by the persisted event
			// bookmark: EventLogWatcher resumes strictly after RecordId=N, so already-processed
			// records are never re-delivered. (Channel, EventRecordId) is deliberately NOT used
			// as an additional dedup key - EventRecordId is not persisted, is absent on
			// ETW-transport channels, and can repeat across channel-rotation instances. The
			// DB-level exactly-once backstop is the unique partial index on the watermark-assigned
			// RawEvents.IngestionSequence (filter: "IngestionSequence" > 0). This line reports
			// the resumed position (RecordId extracted from the cached bookmark XML) plus the
			// bookmark's last-persisted UpdatedUtc, satisfying the acceptance criterion
			// "resuming from bookmark RecordId=N, UpdatedUtc=...".
			long resumeRecordId = -1;
			DateTime resumeUpdatedUtc = DateTime.MinValue;
			if (_bookmarks.TryGetBookmark(channel, out _, out DateTime cachedUpdatedUtc))
			{
				if (!BookmarkRecordIdParser.TryParseRecordId(persistedBookmark, out resumeRecordId))
				{
					resumeRecordId = -1;
				}

				resumeUpdatedUtc = cachedUpdatedUtc;
			}

			_logger.LogInformation(
				"Channel {Channel}: resuming from persisted bookmark RecordId={RecordId}, UpdatedUtc={UpdatedUtc}",
				channel,
				resumeRecordId,
				resumeUpdatedUtc);
		}

		(string xpath, _) = BuildWatcherQuery(channel, filterSet, firstReadFloorUtc);

		try
		{
			await _host.StartChannelAsync(channel, xpath, ct).ConfigureAwait(false);

			if (string.Equals(channel, EventCatalog.ChannelSecurity, StringComparison.OrdinalIgnoreCase))
			{
				_metrics.SetSecurityWatcherEnabled(true);
			}
		}
		catch (EventLogException ex)
		{
			// StartChannelAsync internally routes exceptions through HandleFaultAsync; an escape
			// here means arm-time construction blew up before the source's event loop began.
			// Health policy already saw the failure via the Host — we just log and move on.
			_logger.LogWarning(ex, "Host arm returned with EventLogException for {Channel}; policy will schedule recovery", channel);
		}
	}

	private async Task RunFlushLoopAsync(CancellationToken ct)
	{
		using PeriodicTimer timer = new(FlushTimerPeriod);
		try
		{
			while (await timer.WaitForNextTickAsync(ct).ConfigureAwait(false))
			{
				await _host.FlushBookmarksAsync(ct).ConfigureAwait(false);
			}
		}
		catch (OperationCanceledException) when (ct.IsCancellationRequested)
		{
		}
	}

	// ── Error Handling & Retry ───────────────────────────────────────────────────

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

	// ── Disposal & Pool Returns ──────────────────────────────────────────────────

	public override void Dispose()
	{
		_linkedCts?.Dispose();
		base.Dispose();
	}
}
