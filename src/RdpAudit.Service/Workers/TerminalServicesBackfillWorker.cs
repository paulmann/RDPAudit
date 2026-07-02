/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 1.0.0
// File   : TerminalServicesBackfillWorker.cs
// Project: RdpAudit.Service (RdpAudit.Service.Workers)
// Purpose: Bounded, idempotent backfill for TS-LocalSessionManager, TS-RemoteConnectionManager,
//          and RdpCoreTS operational channels. SecurityBackfillWorker only covers the Security
//          channel; without this worker, historical 261/1149/21/24/25/131/140 events are lost
//          forever on service restart or database reset, and RDP Activity can never be
//          reconstructed for hosts where identity/IP correlation relies on these channels.
// Depends: EventChannel, ServiceMetrics, IOptionsMonitor<RdpAuditOptions>, EventCatalog
// Extends: Add a new (Channel, EventIds) entry to ChannelBackfillTargets when a new
//          non-Security channel needs historical recovery.

using System.Diagnostics.Eventing.Reader;
using System.Runtime.Versioning;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using RdpAudit.Core.Config;
using RdpAudit.Core.Events;

namespace RdpAudit.Service.Workers;

/// <summary>
/// Polls TS-LSM, TS-RCM, and RdpCoreTS operational channels for historical events on a fixed
/// cadence, forwarding unseen records into the same in-memory <see cref="EventChannel"/> the
/// realtime watcher uses. Mirrors <see cref="SecurityBackfillWorker"/>'s per-channel isolation
/// so a slow or unavailable channel cannot starve the others.
/// </summary>
public sealed class TerminalServicesBackfillWorker : BackgroundService
{
	private static readonly TimeSpan PollInterval = TimeSpan.FromMinutes(2);
	private static readonly TimeSpan DefaultLookback = TimeSpan.FromHours(24);
	private static readonly TimeSpan PerRecordReadTimeout = TimeSpan.FromMilliseconds(50);
	private const int MaxRowsPerChannel = 1000;

	private static readonly IReadOnlyDictionary<string, int[]> ChannelBackfillTargets =
		new Dictionary<string, int[]>(StringComparer.OrdinalIgnoreCase)
		{
			[EventCatalog.ChannelTsLocal] = new[] { 21, 22, 23, 24, 25, 39, 40 },
			[EventCatalog.ChannelTsRemote] = new[] { 261, 1148, 1149 },
			[EventCatalog.ChannelRdpCore] = new[] { 65, 82, 131, 140, 141 },
		};

	private readonly EventChannel _channel;
	private readonly ServiceMetrics _metrics;
	private readonly ILogger<TerminalServicesBackfillWorker> _logger;
	private readonly IOptionsMonitor<RdpAuditOptions> _options;
	private readonly HashSet<string> _seen = new(StringComparer.Ordinal);
	private readonly Queue<string> _seenOrder = new();
	private const int SeenRingCapacity = 16_384;

	public TerminalServicesBackfillWorker(
		EventChannel channel,
		ServiceMetrics metrics,
		ILogger<TerminalServicesBackfillWorker> logger,
		IOptionsMonitor<RdpAuditOptions> options)
	{
		_channel = channel;
		_metrics = metrics;
		_logger = logger;
		_options = options;
	}

	protected override async Task ExecuteAsync(CancellationToken stoppingToken)
	{
		_logger.LogInformation("{Worker} starting", nameof(TerminalServicesBackfillWorker));

		if (!OperatingSystem.IsWindows())
		{
			await Task.Delay(Timeout.InfiniteTimeSpan, stoppingToken).ConfigureAwait(false);
			return;
		}

		await Task.Delay(TimeSpan.FromSeconds(20), stoppingToken).ConfigureAwait(false);

		while (!stoppingToken.IsCancellationRequested)
		{
			foreach (KeyValuePair<string, int[]> target in ChannelBackfillTargets)
			{
				try
				{
					await PollChannelAsync(target.Key, target.Value, stoppingToken).ConfigureAwait(false);
				}
				catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
				{
					break;
				}
				catch (Exception ex)
				{
					_logger.LogDebug(ex, "TS backfill poll failed for channel {Channel}", target.Key);
				}
			}

			try
			{
				await Task.Delay(PollInterval, stoppingToken).ConfigureAwait(false);
			}
			catch (OperationCanceledException)
			{
				break;
			}
		}

		_logger.LogInformation("{Worker} stopped", nameof(TerminalServicesBackfillWorker));
	}

	[SupportedOSPlatform("windows")]
	private Task PollChannelAsync(string channel, int[] eventIds, CancellationToken ct)
	{
		bool debugEnabled = _options.CurrentValue.Diagnostics.DebugMode;
		DateTime sinceUtc = DateTime.UtcNow - DefaultLookback;

		string idFilter = string.Join(" or ", Array.ConvertAll(eventIds, id => "EventID=" + id));
		string timeFilter = "TimeCreated[@SystemTime>='" + sinceUtc.ToString("o") + "']";
		string xpath = $"*[System[({idFilter}) and {timeFilter}]]";

		int read = 0;
		int forwarded = 0;
		int duplicate = 0;

		try
		{
			EventLogQuery query = new(channel, PathType.LogName, xpath) { ReverseDirection = true };
			using EventLogReader reader = new(query);

			while (read < MaxRowsPerChannel && !ct.IsCancellationRequested)
			{
				using EventRecord? record = reader.ReadEvent(PerRecordReadTimeout);
				if (record is null)
				{
					break;
				}

				read++;
				string dedupKey = channel + ":" + (record.RecordId ?? unchecked((long)record.GetHashCode()));

				if (!TryMarkSeen(dedupKey))
				{
					duplicate++;
					continue;
				}

				string xml = record.ToXml();
				if (xml.Length > 65_536)
				{
					xml = xml[..65_536];
				}

				RawEventDto dto = new()
				{
					EventId = record.Id,
					Channel = record.LogName ?? channel,
					TimeUtc = record.TimeCreated?.ToUniversalTime() ?? DateTime.UtcNow,
					XmlPayload = xml,
				};

				bool writtenWithoutOverflow = _channel.Channel.TryWrite(dto);
				forwarded++;
				_metrics.IncrementCaptured();

				if (!writtenWithoutOverflow)
				{
					_metrics.IncrementDropped();
					_metrics.IncrementRingBufferOverflow();
				}
			}

			_metrics.SetChannelStatus(
				channel + "::Backfill",
				$"Forwarded:{forwarded}, Duplicate:{duplicate}, Read:{read}");

			if (debugEnabled)
			{
				_logger.LogDebug(
					"TS backfill tick: Channel={Channel} Read={Read} Forwarded={Forwarded} Duplicate={Duplicate} SinceUtc={SinceUtc}",
					channel, read, forwarded, duplicate, sinceUtc);
			}
		}
		catch (EventLogNotFoundException ex)
		{
			_metrics.SetChannelStatus(channel + "::Backfill", "ChannelNotFound");
			_logger.LogDebug(ex, "TS backfill: channel {Channel} not found", channel);
		}
		catch (UnauthorizedAccessException ex)
		{
			_metrics.SetChannelStatus(channel + "::Backfill", "AccessDenied");
			_logger.LogWarning(ex, "TS backfill: access denied on channel {Channel}", channel);
		}
		catch (EventLogException ex)
		{
			if (debugEnabled)
			{
				_logger.LogDebug(ex, "TS backfill: EventLogException on channel {Channel}", channel);
			}
		}

		return Task.CompletedTask;
	}

	private bool TryMarkSeen(string key)
	{
		lock (_seen)
		{
			if (!_seen.Add(key))
			{
				return false;
			}

			_seenOrder.Enqueue(key);
			while (_seenOrder.Count > SeenRingCapacity)
			{
				_seen.Remove(_seenOrder.Dequeue());
			}

			return true;
		}
	}
}
