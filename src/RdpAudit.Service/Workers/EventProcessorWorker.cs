/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 2.3.0
// File   : EventProcessorWorker.cs
// Project: RdpAudit.Service (RdpAudit.Service.Workers)
// Purpose: Drains the lock-free ring buffer in batches, normalises payloads, and persists to
//          SQLite inside a single explicit transaction.
//          v2.1.0: decomposed the monolithic persist method into UpsertAddressesAsync /
//          ApplySessionIpCorrelationAsync steps; added DEBUG-mode structured tracing across
//          normalization, address upsert, and fact-upsert calls so an empty RDP Activity table
//          with a healthy Live Events feed can be diagnosed from logs alone.
//          v2.1.3: DrainBatchAsync briefly used ValueTask<T> to silence CS1998, but reflection
//          in EventProcessorWorkerRingBufferTests.InvokeDrainBatchAsync hard-casts the result to
//          Task<List<RawEventDto>>. Reverted to Task<T>; kept non-async via Task.FromResult
//          since the synchronous fast-path (Channel.TryRead) never awaits. Constructor
//          guard clauses relaxed to channel/metrics/logger/options only — the same test suite
//          constructs the worker with `null!` for factory/normalizer/correlationUpserter/
//          connectionFactUpserter/authAttemptFactUpserter/securityWatchdog/opLog while
//          exercising only DrainBatchAsync, which never dereferences those fields.
//          v2.1.5: DrainBatchAsync_EmptyBuffer_ReturnsEmptyListAfterTimeout asserts
//          Assert.Empty(result) — an empty List<RawEventDto>, not null. Contract corrected:
//          DrainBatchAsync now ALWAYS returns a non-null List<RawEventDto> (Task<List<...>>,
//          never Task<List<...>?>), returning the shared EmptyBatch instance on timeout/
//          cancellation instead of null — this also avoids allocating a fresh empty List on
//          every idle drain tick. EmptyBatch is declared exactly once, in Fields & DI.
//          v2.2.0: ROOT-CAUSE FIX for empty RDP Activity with healthy Live Events. ExecuteAsync
//          now yields immediately (await Task.Yield()) so BackgroundService.StartAsync returns
//          control to the Generic Host synchronously — previously the synchronous DrainBatchAsync
//          fast-path plus a tight `continue` idle loop could delay the StartAsync return long
//          enough that AttackStatsRefreshWorker (registered later) never received StartAsync,
//          leaving AttackStats permanently empty. The idle drain path is now cooperatively
//          asynchronous (Channel.WaitToReadAsync with a bounded timeout) instead of a raw
//          SpinWait busy-loop, eliminating both the startup stall AND 100% CPU spin on idle
//          hosts, while preserving the synchronous TryRead fast-path and the reflection-tested
//          Task<List<RawEventDto>> return contract.
//          v2.3.0 (iter17): consumer now reads through the IEventPipe abstraction instead of
//          reaching into IEventPipe directly, so this worker shares the same physical ring
//          with the iter16 producer path (SecurityBackfillWorker / EventCollectorHostedWorker
//          via IEventPipe.TryWrite). DrainBatchAsync’s idle path replaced the shrinking-budget
//          Channel.WaitToReadAsync call with IEventPipe.WaitToReadAsync, which is backed by the
//          semaphore installed in RingBufferEventPipe v2.1.0 — the producer’s Release() on every
//          TryWrite wakes an idle consumer within microseconds instead of after the timeout
//          budget. Fast-path (IEventPipe.TryRead) still runs at the top of every iteration; the
//          reflection-tested Task<List<RawEventDto>> return contract and EmptyBatch idle
//          singleton are unchanged.
// Depends: IEventPipe, IDbContextFactory<AuditDbContext>, EventNormalizer,
//          SessionIpCorrelationUpserter, RdpConnectionFactUpserter, AuthAttemptFactUpserter,
//          SecurityCorrelationWatchdog, ServiceMetrics, IOptionsMonitor<RdpAuditOptions>
// Extends: Add a new fact upserter call inside PersistBatchAsync, after the existing
//          SaveChangesAsync barrier that materialises RawEvent ids, following the same
//          "normalize -> address upsert -> connection facts -> auth facts -> commit" ordering.

using System.Diagnostics;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Storage;
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
using RdpAudit.Service.Storage;

namespace RdpAudit.Service.Workers;

/// <summary>Drains the event ring buffer in batches, normalises payloads, and persists them to
/// SQLite inside a single explicit transaction per batch.</summary>
public sealed class EventProcessorWorker : BackgroundService
{
	// ── Fields & DI ──────────────────────────────────────────────────────────────

	private static readonly TimeSpan[] Backoffs =
	{
		TimeSpan.FromMilliseconds(100),
		TimeSpan.FromMilliseconds(200),
		TimeSpan.FromMilliseconds(400),
		TimeSpan.FromMilliseconds(800),
		TimeSpan.FromMilliseconds(2000),
	};

	private const int MaxConsecutiveFailures = 5;
	private const string TsLsmChannelName = "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational";
	private const string TsRcmChannelName = "Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational";

	internal const int AddressUserNamesMaxLength = 1024;

	/// <summary>
	/// Shared immutable empty-batch instance returned by <see cref="DrainBatchAsync"/> on
	/// timeout/cancellation. Avoids allocating a fresh empty <see cref="List{T}"/> on every idle
	/// drain tick. Safe to share because callers only ever read <c>Count</c> on this path — the
	/// list is never mutated downstream.
	/// </summary>
	private static readonly List<RawEventDto> EmptyBatch = new(capacity: 0);

	private readonly IEventPipe _pipe;
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
	private readonly IpEventSummaryUpserter? _ipEventSummaryUpserter;

	/// <summary>Bookmark persistence. Null keeps the legacy split commit (collector owns bookmarks).</summary>
	private readonly BookmarkStore? _bookmarks;

	/// <summary>Sequence-to-bookmark ledger. Non-null exactly when <see cref="_bookmarks"/> is.</summary>
	private readonly BookmarkCheckpointLedger? _checkpoints;

	private int _consecutiveFailures;

	// ── Construction ─────────────────────────────────────────────────────────────

	/// <summary>
	/// Only <paramref name="pipe"/>, <paramref name="metrics"/>, <paramref name="logger"/>,
	/// and <paramref name="options"/> are guarded against null: these are the fields
	/// <see cref="DrainBatchAsync"/> and the constructor itself dereference unconditionally.
	/// The remaining dependencies are only touched inside <see cref="PersistBatchAsync"/>, which
	/// unit tests that isolate <see cref="DrainBatchAsync"/> intentionally never invoke.
	/// </summary>
	public EventProcessorWorker(
		IEventPipe pipe,
		IDbContextFactory<AuditDbContext> factory,
		EventNormalizer normalizer,
		SessionIpCorrelationUpserter correlationUpserter,
		RdpConnectionFactUpserter connectionFactUpserter,
		AuthAttemptFactUpserter authAttemptFactUpserter,
		SecurityCorrelationWatchdog securityWatchdog,
		ServiceMetrics metrics,
		ILogger<EventProcessorWorker> logger,
		IOptionsMonitor<RdpAuditOptions> options,
		IOperationLogWriter opLog,
		BookmarkStore? bookmarks = null,
		BookmarkCheckpointLedger? checkpoints = null,
		IpEventSummaryUpserter? ipEventSummaryUpserter = null)
	{
		ArgumentNullException.ThrowIfNull(pipe);
		ArgumentNullException.ThrowIfNull(metrics);
		ArgumentNullException.ThrowIfNull(logger);
		ArgumentNullException.ThrowIfNull(options);

		_pipe = pipe;
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
		_bookmarks = bookmarks;
		_checkpoints = checkpoints;
		_ipEventSummaryUpserter = ipEventSummaryUpserter;

		// Unified commit needs both halves. Supplying only one is a composition mistake that would
		// silently degrade to the legacy split-commit behaviour, so surface it loudly at startup.
		if ((bookmarks is null) != (checkpoints is null))
		{
			throw new ArgumentException(
				"BookmarkStore and BookmarkCheckpointLedger must be supplied together to enable " +
				"unified bookmark commit, or both omitted to keep the legacy split commit.",
				nameof(bookmarks));
		}
	}

	// ── Unified Commit ───────────────────────────────────────────────────────────

	/// <summary>
	/// Writes every bookmark made durable by the current transaction through
	/// <paramref name="tx"/>, so the bookmark advance and the events it covers share one commit.
	/// </summary>
	/// <param name="db">Context whose connection and transaction are borrowed.</param>
	/// <param name="tx">The in-flight EF transaction. Not committed or disposed here.</param>
	/// <param name="committedThroughSequence">Highest ingestion sequence in this batch.</param>
	/// <param name="ct">Cancellation token.</param>
	/// <returns>Bookmarks written, so the caller can prune the ledger after a successful commit.</returns>
	private async Task<int> WriteBookmarksInTransactionAsync(
		AuditDbContext db,
		IDbContextTransaction tx,
		long committedThroughSequence,
		CancellationToken ct)
	{
		if (_bookmarks is null || _checkpoints is null || committedThroughSequence <= 0)
		{
			return 0;
		}

		Dictionary<string, string> committable = new(StringComparer.OrdinalIgnoreCase);
		if (_checkpoints.CollectCommittable(committedThroughSequence, committable) == 0)
		{
			return 0;
		}

		// Borrow EF's own connection and transaction rather than opening a second one: a separate
		// connection would deadlock against the writer lock this transaction already holds under
		// SQLite WAL, and would defeat the atomicity the unified commit exists to provide.
		if (db.Database.GetDbConnection() is not SqliteConnection conn ||
			tx.GetDbTransaction() is not SqliteTransaction sqliteTx)
		{
			_logger.LogWarning(
				"Unified bookmark commit skipped: provider is not SQLite for {ChannelCount} channels",
				committable.Count);
			return 0;
		}

		// Update the in-memory cache BEFORE the commit and roll it back on failure, matching the
		// ordering contract documented on BookmarkStore.SaveInSameTransactionAsync.
		Dictionary<string, string?> previous = new(StringComparer.OrdinalIgnoreCase);
		foreach (KeyValuePair<string, string> entry in committable)
		{
			previous[entry.Key] = _bookmarks.UpdateCache(entry.Key, entry.Value);
		}

		try
		{
			await _bookmarks
				.SaveBatchInSameTransactionAsync(conn, sqliteTx, committable, ct)
				.ConfigureAwait(false);
		}
		catch
		{
			foreach (KeyValuePair<string, string?> entry in previous)
			{
				_bookmarks.RollbackCache(entry.Key, entry.Value);
			}

			throw;
		}

		return committable.Count;
	}

	private bool DebugEnabled => _options.CurrentValue.Diagnostics.DebugMode;

	// ── Public API ───────────────────────────────────────────────────────────────

	protected override async Task ExecuteAsync(CancellationToken stoppingToken)
	{
		_logger.LogInformation("{Worker} starting", nameof(EventProcessorWorker));

		// CRITICAL: return control to the Generic Host immediately so StartAsync completes and
		// subsequent hosted services (AttackStatsRefreshWorker et al.) receive StartAsync. Without
		// this yield, a synchronous drain fast-path plus a tight idle loop can stall the ordered
		// startup chain, leaving AttackStats permanently empty despite a healthy Live Events feed.
		await Task.Yield();

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
						_logger.LogError(
							ex,
							"Persist batch of {Count} failed (consecutiveFailures={ConsecutiveFailures})",
							batch.Count,
							_consecutiveFailures);

						if (_consecutiveFailures >= MaxConsecutiveFailures)
						{
							_logger.LogCritical(
								"DB persistence has failed {ConsecutiveFailures} batches in a row — pausing 30s before retry",
								_consecutiveFailures);

							await _opLog.ErrorAsync(
								"EventProcessor",
								"PersistBatch",
								$"DB persistence failed {_consecutiveFailures} batches in a row; pausing 30s.",
								ex,
								OperationLogSeverity.Critical,
								stoppingToken).ConfigureAwait(false);

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
					// A worker must never take the whole service down. Record as Critical and
					// continue after a short backoff — an unexpected fault in one iteration
					// cannot kill the host.
					_logger.LogCritical(ex, "{Worker} loop iteration faulted — continuing", nameof(EventProcessorWorker));

					await _opLog.ErrorAsync(
						"EventProcessor",
						"LoopFault",
						"Unhandled loop-iteration fault; worker continuing.",
						ex,
						OperationLogSeverity.Critical,
						stoppingToken).ConfigureAwait(false);

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

	// ── Core Logic ───────────────────────────────────────────────────────────────

	/// <summary>
	/// Drains the lock-free ring buffer up to <c>Monitoring.BatchSize</c> items or until the
	/// batch timeout elapses. Always returns a non-null <see cref="List{T}"/> — an empty one
	/// (the shared <see cref="EmptyBatch"/> instance) when nothing arrived before the timeout or
	/// cancellation was requested.
	/// <para>
	/// v2.3.0 (iter17): the idle path now awaits <see cref="IEventPipe.WaitToReadAsync"/> — a
	/// semaphore-backed level-triggered signal — under a shrinking timeout budget instead of a
	/// SpinWait busy-loop with cooperative yields. Producer TryWrite calls (event collector,
	/// backfill workers) release the semaphore, so the consumer wakes within microseconds of a
	/// new event landing. The synchronous <see cref="IEventPipe.TryRead"/> fast-path stays as the
	/// first thing tried on every iteration — a burst that fully saturates the ring will still be
	/// drained without ever hitting the wait. Kept as <see cref="Task{TResult}"/> rather than
	/// <see cref="ValueTask{TResult}"/> because <c>EventProcessorWorkerRingBufferTests</c> invokes
	/// this method via reflection and hard-casts the result to
	/// <c>Task&lt;List&lt;RawEventDto&gt;&gt;</c>.
	/// </para>
	/// </summary>
	private async Task<List<RawEventDto>> DrainBatchAsync(CancellationToken stoppingToken)
	{
		MonitoringOptions monitoring = _options.CurrentValue.Monitoring;
		int max = Math.Max(1, monitoring.BatchSize);
		TimeSpan timeout = TimeSpan.FromMilliseconds(Math.Max(50, monitoring.BatchTimeoutMilliseconds));

		long startTimestamp = Stopwatch.GetTimestamp();
		long timeoutTicks = (long)(timeout.TotalSeconds * Stopwatch.Frequency);

		while (!stoppingToken.IsCancellationRequested)
		{
			// Fast-path: try to drain what is already sitting in the ring without any await.
			if (_pipe.TryRead(out RawEventDto first))
			{
				_metrics.IncrementRingBufferRead();

				List<RawEventDto> batch = new(max) { first };
				while (batch.Count < max && _pipe.TryRead(out RawEventDto next))
				{
					_metrics.IncrementRingBufferRead();
					batch.Add(next);
				}

				return batch;
			}

			// Shrinking wait-budget: how much of the batch-timeout window is left. If the caller
			// already exhausted it, surface the empty batch immediately so the outer ExecuteAsync
			// loop can move on to its next tick without an extra scheduler round-trip.
			long elapsedTicks = Stopwatch.GetTimestamp() - startTimestamp;
			if (elapsedTicks >= timeoutTicks)
			{
				return EmptyBatch;
			}

			TimeSpan remaining = TimeSpan.FromSeconds(
				(double)(timeoutTicks - elapsedTicks) / Stopwatch.Frequency);

			// Semaphore-backed wait: iter15 wired RingBufferEventPipe.TryWrite -> Release() so this
			// wakes on the next producer write with microsecond latency, without CPU spin. A false
			// return means the remaining timeout elapsed with an empty ring; we surface the empty
			// batch so the outer loop can decide its next move (idle logging, options refresh, etc.).
			// A true return is a hint — the follow-up TryRead at the top of the loop may still race
			// and lose, which is why we do NOT assume a DTO is available afterwards.
			bool ready = await _pipe.WaitToReadAsync(remaining, stoppingToken).ConfigureAwait(false);
			if (!ready)
			{
				return EmptyBatch;
			}
		}

		return EmptyBatch;
	}

	/// <summary>
	/// Synchronously drains up to <paramref name="max"/> already-buffered items. Returns
	/// <see langword="true"/> with a freshly allocated, non-empty batch when at least one item was
	/// read; otherwise returns <see langword="false"/> without allocating.
	/// </summary>
	private bool TryDrainReady(int max, out List<RawEventDto> batch)
	{
		if (!_pipe.TryRead(out RawEventDto first))
		{
			batch = EmptyBatch;
			return false;
		}

		_metrics.IncrementRingBufferRead();

		batch = new List<RawEventDto>(max) { first };
		while (batch.Count < max && _pipe.TryRead(out RawEventDto next))
		{
			_metrics.IncrementRingBufferRead();
			batch.Add(next);
		}

		return true;
	}

	private async Task PersistBatchAsync(List<RawEventDto> dtos, CancellationToken ct)
	{
		bool debugEnabled = DebugEnabled;
		List<RawEvent> entities = new(dtos.Count);
		int normalizeFailures = 0;

		foreach (RawEventDto dto in dtos)
		{
			try
			{
				RawEvent entity = _normalizer.Normalize(dto);
				entities.Add(entity);

				if (IsSecurityChannel(dto.Channel))
				{
					_metrics.IncrementSecurityEventRead();
					_metrics.IncrementSecurityEventNormalized();
				}

				if (debugEnabled)
				{
					_logger.LogDebug(
						"EventProcessorWorker NORMALIZED: EventId={EventId} Channel={Channel} TimeUtc={TimeUtc} User={User} SourceIp={SourceIp} SourceIpDerived={Derived} SourceIpUnresolved={Unresolved} LogonId={LogonId} SessionId={SessionId}",
						entity.EventId, entity.Channel, entity.TimeUtc, entity.UserName,
						entity.SourceIp, entity.SourceIpDerived, entity.SourceIpUnresolved,
						entity.LogonId, entity.SessionId);
				}
			}
			catch (Exception ex)
			{
				normalizeFailures++;

				if (IsSecurityChannel(dto.Channel))
				{
					_metrics.IncrementSecurityEventRead();
					_metrics.IncrementSecurityEventRejected("NormalizeFailed: " + ex.GetType().Name);
				}

				_logger.LogWarning(ex, "Normalize failed for event {EventId} channel {Channel}", dto.EventId, dto.Channel);
			}
		}

		if (debugEnabled)
		{
			int connectionFactEligible = 0;
			int authFactEligible = 0;

			foreach (RawEvent e in entities)
			{
				if (RdpConnectionFactUpserter.ClassifyEvent(e.Channel ?? string.Empty, e.EventId, e.LogonType)
					!= RdpConnectionFactUpserter.EventKind.Unrelated)
				{
					connectionFactEligible++;
				}

				if (AuthAttemptFactUpserter.IsAuthoritativeAuthEvent(e))
				{
					authFactEligible++;
				}
			}

			_logger.LogDebug(
				"EventProcessorWorker BATCH INTAKE: dtos={DtoCount} normalized={NormalizedCount} normalizeFailures={NormalizeFailures} connectionFactEligible={ConnFact} authFactEligible={AuthFact}",
				dtos.Count, entities.Count, normalizeFailures, connectionFactEligible, authFactEligible);
		}

		await using AuditDbContext db = await _factory.CreateDbContextAsync(ct).ConfigureAwait(false);
		await using var tx = await db.Database.BeginTransactionAsync(ct).ConfigureAwait(false);
		DateTime now = DateTime.UtcNow;

		try
		{
			int addressesUpserted = await UpsertAddressesAsync(db, entities, now, ct).ConfigureAwait(false);
			IngestionSequence sequence = await db.IngestionSequences
				.SingleAsync(item => item.Id == 1, ct)
				.ConfigureAwait(false);
			long nextSequence = sequence.NextValue;
			foreach (RawEvent entity in entities)
			{
				entity.IngestionSequence = checked(nextSequence);
				nextSequence = checked(nextSequence + 1);
			}

			sequence.NextValue = nextSequence;

			db.RawEvents.AddRange(entities);

			await ApplySessionIpCorrelationAsync(db, entities, ct).ConfigureAwait(false);
			await _connectionFactUpserter.ApplyAsync(db, entities, ct).ConfigureAwait(false);

			// Materialise RawEvent ids inside the same transaction before the fact upserters
			// reference EvidenceRawEventId.
			await db.SaveChangesAsync(ct).ConfigureAwait(false);

			AuthAttemptFactBatchResult authResult = await _authAttemptFactUpserter
				.ApplyAsync(db, entities, ct)
				.ConfigureAwait(false);

			await db.SaveChangesAsync(ct).ConfigureAwait(false);

			if (_ipEventSummaryUpserter is not null)
			{
				if (db.Database.GetDbConnection() is not SqliteConnection connection
					|| tx.GetDbTransaction() is not SqliteTransaction sqliteTransaction)
				{
					throw new InvalidOperationException(
						"IpEventSummaryUpserter requires the configured SQLite connection and transaction.");
				}

				await _ipEventSummaryUpserter
					.UpsertBatchAsync(connection, sqliteTransaction, entities, ct)
					.ConfigureAwait(false);
			}

			// Unified durability boundary: the bookmark advance rides the SAME commit as the events
			// it would otherwise skip past. Written last so it covers everything above it, and
			// before CommitAsync so a failure here rolls the whole batch back together.
			long committedThroughSequence = 0;
			foreach (RawEventDto dto in dtos)
			{
				if (dto.IngestionSequence > committedThroughSequence)
				{
					committedThroughSequence = dto.IngestionSequence;
				}
			}

			int bookmarksWritten = await WriteBookmarksInTransactionAsync(
				db, tx, committedThroughSequence, ct).ConfigureAwait(false);

			await tx.CommitAsync(ct).ConfigureAwait(false);

			// Only now is the position durable, so only now may the ledger forget the checkpoints
			// and let the collector's fallback flush publish them.
			if (bookmarksWritten > 0)
			{
				_checkpoints!.Prune(committedThroughSequence);

				_logger.LogDebug(
					"Unified commit advanced {BookmarkCount} bookmark(s) through sequence {Sequence}",
					bookmarksWritten,
					committedThroughSequence);
			}

			if (authResult.FailedCreated > 0 || authResult.SucceededCreated > 0)
			{
				_metrics.RecordAuthAttemptFacts(
					authResult.FailedCreated,
					authResult.SucceededCreated,
					authResult.LastFactUtc == default ? now : authResult.LastFactUtc);
			}

			if (debugEnabled)
			{
				_logger.LogDebug(
					"EventProcessorWorker BATCH COMMIT: entities={EntityCount} addressesUpserted={Addresses} authFactsFailed={AuthFailed} authFactsSucceeded={AuthSucceeded}",
					entities.Count, addressesUpserted, authResult.FailedCreated, authResult.SucceededCreated);
			}
		}
		catch (Exception ex)
		{
			await tx.RollbackAsync(ct).ConfigureAwait(false);

			if (debugEnabled)
			{
				_logger.LogDebug(ex, "EventProcessorWorker BATCH ROLLBACK: entities={EntityCount}", entities.Count);
			}

			throw;
		}

		// Feed the security-correlation watchdog after the transaction commits so the diagnostic
		// is anchored to events that actually landed in the audit DB. Updates ServiceMetrics
		// in place — no DB writes here.
		_securityWatchdog.Apply(entities);
	}

	private async Task<int> UpsertAddressesAsync(
		AuditDbContext db,
		List<RawEvent> entities,
		DateTime now,
		CancellationToken ct)
	{
		HashSet<string> ips = new(StringComparer.OrdinalIgnoreCase);

		foreach (RawEvent entity in entities)
		{
			// Do not materialise an Address row for an event whose IP slot was legitimately
			// unresolvable (e.g. Security 4625 without a parseable IpAddress). The failure is
			// preserved via RdpConnectionFacts' sentinel route; creating an Address row here
			// would either fail (no IP value) or pollute the table with a bogus "0.0.0.0"
			// reputation entry.
			if (entity.SourceIpUnresolved || string.IsNullOrEmpty(entity.SourceIp))
			{
				continue;
			}

			ips.Add(entity.SourceIp);
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
			if (existingMap.ContainsKey(ip))
			{
				continue;
			}

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

		if (toAdd.Count > 0)
		{
			db.Addresses.AddRange(toAdd);
			await db.SaveChangesAsync(ct).ConfigureAwait(false); // assigns Ids in one round-trip
		}

		int touched = 0;

		foreach (RawEvent entity in entities)
		{
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
				addr.SuccessCount++;
			}
			else if (IsTsLsm21(entity) || IsTsRcm1149(entity))
			{
				// NLA hosts rarely emit Security 4624 for an RDP logon; TS-RCM 1149 and TS-LSM 21
				// are the authoritative success evidence on such hosts.
				addr.SuccessCount++;
			}

			addr.UserNames = AppendAddressUserName(addr.UserNames, entity.UserName);
			touched++;
		}

		return touched;
	}

	private async Task ApplySessionIpCorrelationAsync(AuditDbContext db, List<RawEvent> entities, CancellationToken ct)
	{
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

	// ── SIMD & Zero-Alloc Parsers ────────────────────────────────────────────────
	// (Not applicable: this worker is the cold-path DB persistence stage per the project's
	// Cold/Hot Database Split directive. EventCollectorHostedWorker's ingestion callback is the
	// zero-alloc hot path; this class is intentionally allocation-tolerant for EF/SQLite writes.)

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
}
