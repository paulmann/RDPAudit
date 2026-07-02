/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 2.0.0

// File:    src/RdpAudit.Service/Workers/EventProcessorWorker.cs
// Module:  RdpAudit.Service.Workers
// Purpose: Drains the event channel in batches, normalises payloads, and persists to SQLite.
//          Uses a single transaction with prefetched address map and a bulk AddRange/SaveChanges
//          to avoid the original per-IP / per-event N+1 round-trips.
// Extends: Microsoft.Extensions.Hosting.BackgroundService

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using RdpAudit.Core.Config;
using RdpAudit.Core.Data;
using RdpAudit.Core.Events;
using RdpAudit.Core.Models;
using RdpAudit.Core.Util;
using RdpAudit.Service.Infrastructure;
using RdpAudit.Service.Processors;

namespace RdpAudit.Service.Workers;

/// <summary>Drains the event channel in batches, normalises payloads, and persists to SQLite.</summary>
public sealed class EventProcessorWorker : BackgroundService
{
	private static readonly TimeSpan[] Backoffs =
	{
		TimeSpan.FromMilliseconds(100),
		TimeSpan.FromMilliseconds(200),
		TimeSpan.FromMilliseconds(400),
		TimeSpan.FromMilliseconds(800),
		TimeSpan.FromMilliseconds(2000),
	};

	private const int MaxConsecutiveFailures = 5;

	private readonly EventChannel _channel;
	private readonly IDbContextFactory<AuditDbContext> _factory;
	private readonly EventNormalizer _normalizer;
	private readonly SessionIpCorrelationUpserter _correlationUpserter;
	private readonly RdpConnectionFactUpserter _connectionFactUpserter;
	private readonly AuthAttemptFactUpserter _authAttemptFactUpserter;
	private readonly SecurityCorrelationWatchdog _securityWatchdog;
	private readonly ServiceMetrics _metrics;
	private readonly ILogger<EventProcessorWorker> _logger;
	private readonly IOptionsMonitor<RdpAuditOptions> _options;
	private readonly IOperationLogWriter _opLog;
	private int _consecutiveFailures;

	public EventProcessorWorker(
		EventChannel channel,
		IDbContextFactory<AuditDbContext> factory,
		EventNormalizer normalizer,
		SessionIpCorrelationUpserter correlationUpserter,
		RdpConnectionFactUpserter connectionFactUpserter,
		AuthAttemptFactUpserter authAttemptFactUpserter,
		SecurityCorrelationWatchdog securityWatchdog,
		ServiceMetrics metrics,
		ILogger<EventProcessorWorker> logger,
		IOptionsMonitor<RdpAuditOptions> options,
		IOperationLogWriter opLog)
	{
		_channel = channel;
		_factory = factory;
		_normalizer = normalizer;
		_correlationUpserter = correlationUpserter;
		_connectionFactUpserter = connectionFactUpserter;
		_authAttemptFactUpserter = authAttemptFactUpserter;
		_securityWatchdog = securityWatchdog;
		_metrics = metrics;
		_logger = logger;
		_options = options;
		_opLog = opLog;
	}

	protected override async Task ExecuteAsync(CancellationToken stoppingToken)
	{
		_logger.LogInformation("{Worker} starting", nameof(EventProcessorWorker));
		try
		{
			while (!stoppingToken.IsCancellationRequested)
			{
				try
				{
					List<RawEventDto> batch = await DrainBatchAsync(stoppingToken).ConfigureAwait(false);
					if (batch.Count == 0)
					{
						continue;
					}

					try
					{
						await WithRetryAsync(ct => PersistBatchAsync(batch, ct), stoppingToken).ConfigureAwait(false);
						_consecutiveFailures = 0;
					}
					catch (Exception ex)
					{
						_consecutiveFailures++;
						_logger.LogError(ex, "Persist batch of {Count} failed (consecutiveFailures={ConsecutiveFailures})",
							batch.Count, _consecutiveFailures);
						if (_consecutiveFailures >= MaxConsecutiveFailures)
						{
							_logger.LogCritical(
								"DB persistence has failed {ConsecutiveFailures} batches in a row — pausing 30s before retry",
								_consecutiveFailures);
							await _opLog.ErrorAsync("EventProcessor", "PersistBatch",
								$"DB persistence failed {_consecutiveFailures} batches in a row; pausing 30s.",
								ex, OperationLogSeverity.Critical, stoppingToken).ConfigureAwait(false);
							await Task.Delay(TimeSpan.FromSeconds(30), stoppingToken).ConfigureAwait(false);
						}
					}
				}
				catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
				{
					break;
				}
				catch (Exception ex)
				{
					// A worker must never take the whole service down. Record the fault as Critical and
					// continue the loop after a short backoff so a transient or unexpected error in one
					// iteration cannot kill the host (the original `throw` here was a crash root cause).
					_logger.LogCritical(ex, "{Worker} loop iteration faulted — continuing", nameof(EventProcessorWorker));
					await _opLog.ErrorAsync("EventProcessor", "LoopFault",
						"Unhandled loop-iteration fault; worker continuing.", ex,
						OperationLogSeverity.Critical, stoppingToken).ConfigureAwait(false);
					try
					{
						await Task.Delay(TimeSpan.FromSeconds(5), stoppingToken).ConfigureAwait(false);
					}
					catch (OperationCanceledException)
					{
						break;
					}
				}
			}
		}
		catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
		{
		}
		finally
		{
			_logger.LogInformation("{Worker} stopped", nameof(EventProcessorWorker));
		}
	}

	/// <summary>
	/// v2.0.0: Rewired to drain the lock-free SPSC Ring Buffer.
	/// Uses SpinWait to achieve sub-microsecond latency when events are flowing, 
	/// while automatically yielding to the OS scheduler during idle periods to prevent 100% CPU burn.
	/// </summary>
	private Task<List<RawEventDto>> DrainBatchAsync(CancellationToken stoppingToken)
	{
		MonitoringOptions monitoring = _options.CurrentValue.Monitoring;
		int max = Math.Max(1, monitoring.BatchSize);
		TimeSpan timeout = TimeSpan.FromMilliseconds(Math.Max(50, monitoring.BatchTimeoutMilliseconds));

		List<RawEventDto> batch = new(max);
		
		SpinWait spinner = new();
		long startTimestamp = Stopwatch.GetTimestamp();
		long timeoutTicks = (long)(timeout.TotalSeconds * Stopwatch.Frequency);

// 1. Wait for the first event
while (!stoppingToken.IsCancellationRequested)
{
    // ИСПРАВЛЕНИЕ: Читаем сразу RawEventDto, а не RawEventSlot!
    if (_channel.Channel.TryRead(out RawEventDto dto))
    {
        _metrics.IncrementRingBufferRead();
        batch.Add(dto);
        spinner.Reset();
        break;
    }

    if (Stopwatch.GetTimestamp() - startTimestamp >= timeoutTicks)
    {
        return Task.FromResult(batch); 
    }

    spinner.SpinOnce();
}

// 2. Continue draining up to batch size
while (batch.Count < max && _channel.Channel.TryRead(out RawEventDto nextDto))
{
    _metrics.IncrementRingBufferRead();
    batch.Add(nextDto);
}

		return Task.FromResult(batch);
	}

	private async Task PersistBatchAsync(List<RawEventDto> dtos, CancellationToken ct)
	{
		List<RawEvent> entities = new(dtos.Count);
		foreach (RawEventDto dto in dtos)
		{
			try
			{
				entities.Add(_normalizer.Normalize(dto));
				if (IsSecurityChannel(dto.Channel))
				{
					_metrics.IncrementSecurityEventRead();
					_metrics.IncrementSecurityEventNormalized();
				}
			}
			catch (Exception ex)
			{
				if (IsSecurityChannel(dto.Channel))
				{
					_metrics.IncrementSecurityEventRead();
					_metrics.IncrementSecurityEventRejected("NormalizeFailed: " + ex.GetType().Name);
				}

				_logger.LogWarning(ex, "Normalize failed for event {EventId} channel {Channel}", dto.EventId, dto.Channel);
			}
		}

		await using AuditDbContext db = await _factory.CreateDbContextAsync(ct).ConfigureAwait(false);
		await using var tx = await db.Database.BeginTransactionAsync(ct).ConfigureAwait(false);
		DateTime now = DateTime.UtcNow;

		try
		{
			HashSet<string> ips = new(StringComparer.OrdinalIgnoreCase);
			foreach (RawEvent entity in entities)
			{
				// Stage 6: do NOT materialise an Address row for an event whose IP slot was
				// legitimately unresolvable (Security 4625 without parseable IpAddress). The
				// failure is preserved in RdpConnectionFacts via the sentinel route; creating
				// an Address row for it here would either fail (no IP value) or pollute the
				// table with bogus "0.0.0.0" reputation entries.
				if (entity.SourceIpUnresolved)
				{
					continue;
				}

				if (!string.IsNullOrEmpty(entity.SourceIp))
				{
					ips.Add(entity.SourceIp);
				}
			}

			Dictionary<string, Address> existingMap = new(StringComparer.OrdinalIgnoreCase);
			if (ips.Count > 0)
			{
				List<Address> existing = await db.Addresses
					.Where(a => ips.Contains(a.Ip))
					.ToListAsync(ct)
					.ConfigureAwait(false);
				foreach (Address a in existing)
				{
					existingMap[a.Ip] = a;
				}
			}

			List<Address> toAdd = new();
			foreach (string ip in ips)
			{
				if (!existingMap.ContainsKey(ip))
				{
					Address fresh = new()
					{
						Ip = ip,
						FirstSeen = now,
						LastSeen = now,
						IsPublicIp = IpClassifier.IsPublicIp(ip),
					};
					existingMap[ip] = fresh;
					toAdd.Add(fresh);
				}
			}

			if (toAdd.Count > 0)
			{
				db.Addresses.AddRange(toAdd);
				await db.SaveChangesAsync(ct).ConfigureAwait(false); // assigns Ids in one round-trip
			}

			foreach (RawEvent entity in entities)
			{
				// Stage 6: unresolved-IP failures must not produce or update Address rows. They are
				// already preserved as failed-logon evidence under the sentinel "0.0.0.0" connection
				// fact.
				if (entity.SourceIpUnresolved || string.IsNullOrEmpty(entity.SourceIp))
				{
					continue;
				}

				if (!existingMap.TryGetValue(entity.SourceIp, out Address? addr))
				{
					continue;
				}

				entity.AddressId = addr.Id;
				addr.LastSeen = now;
				if (entity.EventId == 4625 || entity.EventId == 4771 || entity.EventId == 140)
				{
					addr.FailCount++;
				}
				else if (entity.EventId == 4624 || entity.EventId == 4768 || entity.EventId == 4769 || entity.EventId == 4648)
				{
					// Cameyo rdpmon (RdpMon/RdpMon.cs Addrs.Aggregate) counts 4648 — explicit-credentials
					// use such as RunAs / "Connect as a different user" / scheduled-task launch — as a
					// successful authentication on the per-IP reputation row. The connection-fact layer
					// still classifies 4648 as ExplicitCreds (not a session-establishing logon), so this
					// only affects the IP-keyed Attack Statistics view.
					addr.SuccessCount++;
				}
				else if (IsTsLsm21(entity) || IsTsRcm1149(entity))
				{
					// Stage 6: NLA hosts rarely emit Security 4624 for an RDP logon; the TS-RCM 1149
					// (NLA authenticated) and TS-LSM 21 (session logon) events are the authoritative
					// success evidence and must increment the per-IP success counter so the Attack
					// Statistics view stops reporting zero successes on real workloads.
					addr.SuccessCount++;
				}

				addr.UserNames = AppendAddressUserName(addr.UserNames, entity.UserName);
			}

			db.RawEvents.AddRange(entities);

			List<SessionIpCorrelationCandidate> candidates = new(entities.Count);
			foreach (RawEvent entity in entities)
			{
				if (entity.SourceIpDerived || string.IsNullOrEmpty(entity.SourceIp))
				{
					continue;
				}

				candidates.Add(new SessionIpCorrelationCandidate(
					LogonId: entity.LogonId,
					WtsSessionId: entity.SessionId,
					UserName: entity.UserName,
					Domain: entity.Domain,
					Ip: entity.SourceIp!,
					ObservedUtc: entity.TimeUtc,
					EventId: entity.EventId,
					IsDirectObservation: true));
			}

			await _correlationUpserter.ApplyAsync(db, candidates, ct).ConfigureAwait(false);
			await _connectionFactUpserter.ApplyAsync(db, entities, ct).ConfigureAwait(false);

			// v3 atomic-fact pass: persist one AuthAttemptFact per authoritative outcome event so
			// IpFact / UserIpFact / Attack Statistics counters can be derived from a single source
			// of truth (Detect_Attack_Strategy_v3.md §8.1, §17.14). Runs AFTER the RawEvents have
			// been Add()'d so EvidenceRawEventId can reference the actual row id; we run a
			// SaveChanges first to materialise those ids inside the same transaction.
			await db.SaveChangesAsync(ct).ConfigureAwait(false);

			AuthAttemptFactBatchResult authResult = await _authAttemptFactUpserter
				.ApplyAsync(db, entities, ct)
				.ConfigureAwait(false);

			await db.SaveChangesAsync(ct).ConfigureAwait(false);
			await tx.CommitAsync(ct).ConfigureAwait(false);

			if (authResult.FailedCreated > 0 || authResult.SucceededCreated > 0)
			{
				_metrics.RecordAuthAttemptFacts(
					authResult.FailedCreated,
					authResult.SucceededCreated,
					authResult.LastFactUtc == default ? now : authResult.LastFactUtc);
			}
		}
		catch
		{
			await tx.RollbackAsync(ct).ConfigureAwait(false);
			throw;
		}

		// Feed the security-correlation watchdog after the transaction commits so the diagnostic
		// is anchored to events that actually landed in the audit DB. The watchdog updates
		// ServiceMetrics in place — no DB writes here.
		_securityWatchdog.Apply(entities);
	}

	/// <summary>
	/// Maximum width of <see cref="Address.UserNames"/>. Mirrors the
	/// <see cref="RdpConnectionFactUpserter.UserNamesAttemptedMaxLength"/> contract so attempted
	/// usernames are capped consistently across both tables.
	/// </summary>
	internal const int AddressUserNamesMaxLength = 1024;

	private const string TsLsmChannelName = "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational";
	private const string TsRcmChannelName = "Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational";

	private static bool IsSecurityChannel(string? channel)
		=> !string.IsNullOrWhiteSpace(channel)
			&& channel.Equals("Security", StringComparison.OrdinalIgnoreCase);

	private static bool IsTsLsm21(RawEvent e)
		=> e.EventId == 21
			&& string.Equals(e.Channel, TsLsmChannelName, StringComparison.OrdinalIgnoreCase);

	private static bool IsTsRcm1149(RawEvent e)
		=> e.EventId == 1149
			&& string.Equals(e.Channel, TsRcmChannelName, StringComparison.OrdinalIgnoreCase);

	/// <summary>
	/// Append <paramref name="userName"/> to a comma-separated <see cref="Address.UserNames"/>
	/// list, de-duplicating case-insensitively and honouring the column width cap. Returns the
	/// original list when the username is null/blank.
	/// </summary>
	internal static string? AppendAddressUserName(string? current, string? userName)
	{
		if (string.IsNullOrWhiteSpace(userName))
		{
			return current;
		}

		string token = userName.Trim();
		if (string.IsNullOrEmpty(current))
		{
			return token.Length <= AddressUserNamesMaxLength ? token : token[..AddressUserNamesMaxLength];
		}

		string[] parts = current.Split(',', StringSplitOptions.RemoveEmptyEntries);
		List<string> kept = new(parts.Length + 1);
		foreach (string part in parts)
		{
			if (!string.Equals(part, token, StringComparison.OrdinalIgnoreCase))
			{
				kept.Add(part);
			}
		}

		kept.Add(token);
		string joined = string.Join(',', kept);
		while (joined.Length > AddressUserNamesMaxLength && kept.Count > 1)
		{
			kept.RemoveAt(0);
			joined = string.Join(',', kept);
		}

		return joined.Length <= AddressUserNamesMaxLength
			? joined
			: joined[..AddressUserNamesMaxLength];
	}

	private async Task WithRetryAsync(Func<CancellationToken, Task> action, CancellationToken ct)
	{
		for (int i = 0; i < Backoffs.Length; i++)
		{
			try
			{
				await action(ct).ConfigureAwait(false);
				return;
			}
			catch (SqliteException ex) when (ex.SqliteErrorCode is 5 or 6)
			{
				if (i == Backoffs.Length - 1)
				{
					throw;
				}

				_logger.LogWarning(
					"DB busy (attempt {Attempt}) — retrying in {Ms}ms",
					i + 1,
					Backoffs[i].TotalMilliseconds);
				await Task.Delay(Backoffs[i], ct).ConfigureAwait(false);
			}
		}
	}
}