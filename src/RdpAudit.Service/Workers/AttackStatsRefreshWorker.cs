/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 1.4.1
// File   : AttackStatsRefreshWorker.cs
// Project: RdpAudit.Service (RdpAudit.Service.Workers)
// Purpose: Stage 6 background worker that materialises per-IP AttackStat rows from AuthAttemptFacts +
//          ActiveBlocks on a 60-second cadence (and once at startup). Honours CancellationToken,
//          guards against concurrent re-entry, and bounds each pass by a fixed look-back window so
//          full table scans never grow without bound.
//
//          v1.3.6 fix (stale RDP Activity): each pass now orders AuthAttemptFacts by TimeUtc DESC so
//          the bounded MaxRawEventsPerPass slice is always the NEWEST facts. The previous OrderBy(Id)
//          ascending slice silently dropped fresh facts once the look-back window held more than
//          MaxRawEventsPerPass rows (a brute-forced host crosses that threshold quickly), which froze
//          AttackStat.LastSeenUtc while RawEvents / AuthAttemptFacts kept advancing. RefreshOnceAsync
//          also exposes a full-rebuild mode used by the DEBUG "Rebuild RDP Activity statistics" IPC
//          action: it pages through every in-window fact (no MaxRawEventsPerPass truncation) so a
//          single manual rebuild always re-derives current-day LastSeenUtc from current facts.
//
//          v1.4.0 fix (empty RDP Activity, "Stats worker last run = never"): ExecuteAsync now yields
//          (await Task.Yield()) before the startup refresh so BackgroundService.StartAsync returns to
//          the Generic Host immediately — the startup pass no longer runs inline on the host-start
//          thread, so this worker (and every worker registered after it) can no longer be starved by
//          a slow first projection.
//
//          v1.4.1: RecordStatsWorkerSkipped does not exist on ServiceMetrics — reverted the
//          re-entrancy-skip diagnostic to the existing RecordStatsWorkerRun(rows=0,
//          error="Skipped: gate held") call so a held gate is still distinguishable from "never ran"
//          in the Diagnostic tab, without introducing a new ServiceMetrics API surface. SafeRefreshAsync
//          now branches on AttackStatsRefreshResult.WasSkipped so a skipped pass is never logged as a
//          successful "0 rows materialised" projection.
// Depends: IDbContextFactory<AuditDbContext>, AttackStatsAggregator, ServiceMetrics, IpNormalizer
// Extends: Microsoft.Extensions.Hosting.BackgroundService — add a new projection input by extending
//          the sample-building loop in RunRefreshAsync, keeping AuthAttemptFact as the sole counter
//          source of truth (v3 §6.3 rule 3).

using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using RdpAudit.Core.Data;
using RdpAudit.Core.Models;
using RdpAudit.Core.Util;

namespace RdpAudit.Service.Workers;

/// <summary>Stage 6 background worker that materialises per-IP <see cref="AttackStat"/> rows.</summary>
public sealed class AttackStatsRefreshWorker : BackgroundService
{
	// ── Fields & DI ──────────────────────────────────────────────────────────────

	/// <summary>Refresh cadence. Operator-facing dashboards happily tolerate 60-second lag.</summary>
	internal static readonly TimeSpan Period = TimeSpan.FromSeconds(60);

	/// <summary>Bounded look-back window. Older rows decay via <c>MaintenanceWorker</c>.</summary>
	internal static readonly TimeSpan LookBackWindow = TimeSpan.FromDays(30);

	/// <summary>Upper bound on facts fetched from <c>AuthAttemptFacts</c> per incremental pass. The
	/// slice is taken NEWEST-first (TimeUtc DESC) so fresh activity always wins when the look-back
	/// window holds more facts than this cap.</summary>
	internal const int MaxRawEventsPerPass = 50_000;

	/// <summary>Page size used by the full-rebuild path so a host with hundreds of thousands of
	/// in-window facts can be re-projected without loading them all into memory at once.</summary>
	internal const int FullRebuildPageSize = 50_000;

	/// <summary>Diagnostic marker written via <see cref="ServiceMetrics.RecordStatsWorkerRun"/>'s
	/// error slot when a pass is rejected by the re-entrancy gate. Not an exception — this is a
	/// deliberate, expected outcome — but it must be visibly distinct from <c>null</c> (a clean run)
	/// so an operator reading the Diagnostic tab can tell "gate held" apart from "genuinely failed".</summary>
	private const string GateHeldMarker = "Skipped: gate held";

	private readonly IDbContextFactory<AuditDbContext> _factory;
	private readonly ILogger<AttackStatsRefreshWorker> _logger;
	private readonly ServiceMetrics? _metrics;
	private readonly SemaphoreSlim _gate = new(1, 1);
	private int _disposed;

	// ── Construction ─────────────────────────────────────────────────────────────

	public AttackStatsRefreshWorker(
		IDbContextFactory<AuditDbContext> factory,
		ILogger<AttackStatsRefreshWorker> logger,
		ServiceMetrics? metrics = null)
	{
		_factory = factory ?? throw new ArgumentNullException(nameof(factory));
		_logger = logger ?? throw new ArgumentNullException(nameof(logger));
		_metrics = metrics;
	}

	// ── Public API ───────────────────────────────────────────────────────────────

	protected override async Task ExecuteAsync(CancellationToken stoppingToken)
	{
		_logger.LogInformation("{Worker} starting", nameof(AttackStatsRefreshWorker));
		_metrics?.SetStatsWorkerEnabled(true);

		// CRITICAL: yield before the startup refresh so BackgroundService.StartAsync returns control
		// to the Generic Host synchronously. Otherwise the first projection pass (CreateDbContext +
		// several sequential EF queries over a 30-day window) runs inline on the host-start thread and
		// can stall the ordered startup chain — the exact failure behind an empty AttackStats table
		// with "Stats worker last run = never" while Live Events was healthy.
		await Task.Yield();

		try
		{
			// Startup refresh: kick the first pass without waiting for the cadence.
			await SafeRefreshAsync(stoppingToken).ConfigureAwait(false);

			using PeriodicTimer timer = new(Period);
			while (await WaitForNextTickAsync(timer, stoppingToken).ConfigureAwait(false))
			{
				await SafeRefreshAsync(stoppingToken).ConfigureAwait(false);
			}
		}
		catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
		{
			// Service shutdown — quiet return.
		}
		finally
		{
			_metrics?.SetStatsWorkerEnabled(false);
			_logger.LogInformation("{Worker} stopped", nameof(AttackStatsRefreshWorker));
		}
	}

	/// <summary>Awaits the next timer tick, translating a shutdown cancellation into a clean
	/// loop-exit (<see langword="false"/>) instead of a propagated exception.</summary>
	private static async Task<bool> WaitForNextTickAsync(PeriodicTimer timer, CancellationToken ct)
	{
		try
		{
			return await timer.WaitForNextTickAsync(ct).ConfigureAwait(false);
		}
		catch (OperationCanceledException) when (ct.IsCancellationRequested)
		{
			return false;
		}
	}

	/// <summary>Public for tests and the IPC RebuildAttackStats action: runs a single deterministic
	/// refresh pass. Records the run outcome (timestamp, rows upserted, error) into
	/// <see cref="ServiceMetrics"/> so the Diagnostic tab can prove the projection job is alive.
	/// When <paramref name="fullRebuild"/> is true the pass pages through every in-window fact rather
	/// than the bounded newest-first slice, forcing every AttackStat row's LastSeenUtc to be
	/// re-derived from current facts (the DEBUG "Rebuild RDP Activity statistics" action).</summary>
	public async Task<AttackStatsRefreshResult> RefreshOnceDetailedAsync(bool fullRebuild, CancellationToken ct)
	{
		if (!await _gate.WaitAsync(0, ct).ConfigureAwait(false))
		{
			_logger.LogInformation(
				"{Worker} refresh skipped: previous pass still running (fullRebuild={FullRebuild})",
				nameof(AttackStatsRefreshWorker),
				fullRebuild);

			// ServiceMetrics has no dedicated "skipped" counter (RecordStatsWorkerSkipped does not
			// exist). Reuse RecordStatsWorkerRun with rows=0 and a distinct, non-null error marker so
			// the Diagnostic tab can tell "gate held" apart from both a clean run and a genuine
			// exception, without adding a new ServiceMetrics API surface.
			_metrics?.RecordStatsWorkerRun(DateTime.UtcNow, 0, GateHeldMarker);
			return AttackStatsRefreshResult.Skipped;
		}

		DateTime startedUtc = DateTime.UtcNow;
		_metrics?.RecordStatsWorkerStarted(startedUtc, fullRebuild);
		try
		{
			AttackStatsRefreshResult result = await RunRefreshAsync(fullRebuild, ct).ConfigureAwait(false);
			_metrics?.RecordStatsWorkerRun(DateTime.UtcNow, result.RowsUpserted, null);
			return result;
		}
		catch (OperationCanceledException) when (ct.IsCancellationRequested)
		{
			throw;
		}
		catch (Exception ex)
		{
			_metrics?.RecordStatsWorkerRun(DateTime.UtcNow, 0, ex.GetType().Name + ": " + ex.Message);
			throw;
		}
		finally
		{
			_gate.Release();
		}
	}

	/// <summary>Backwards-compatible incremental refresh entry point. Returns rows upserted.</summary>
	public async Task<int> RefreshOnceAsync(CancellationToken ct)
	{
		AttackStatsRefreshResult result = await RefreshOnceDetailedAsync(false, ct).ConfigureAwait(false);
		return result.RowsUpserted;
	}

	// ── Core Logic ───────────────────────────────────────────────────────────────

	private async Task SafeRefreshAsync(CancellationToken ct)
	{
		try
		{
			AttackStatsRefreshResult result = await RefreshOnceDetailedAsync(false, ct).ConfigureAwait(false);

			if (result.WasSkipped)
			{
				// Never conflate a gate-held skip with a genuine "0 rows materialised" pass — the
				// metric was already recorded via GateHeldMarker inside RefreshOnceDetailedAsync.
				_logger.LogDebug(
					"{Worker} pass skipped (re-entrancy gate held)",
					nameof(AttackStatsRefreshWorker));
				return;
			}

			_logger.LogDebug(
				"{Worker} pass complete, rows materialised: {Rows} (before={Before} after={After} latestFact={LatestFact})",
				nameof(AttackStatsRefreshWorker),
				result.RowsUpserted,
				result.RowsBefore,
				result.RowsAfter,
				result.LatestSourceFactUtc);
		}
		catch (OperationCanceledException) when (ct.IsCancellationRequested)
		{
			// Service shutdown — quiet return.
		}
		catch (Exception ex)
		{
			_logger.LogError(ex, "{Worker} pass failed", nameof(AttackStatsRefreshWorker));
		}
	}

	private async Task<AttackStatsRefreshResult> RunRefreshAsync(bool fullRebuild, CancellationToken ct)
	{
		DateTime nowUtc = DateTime.UtcNow;
		DateTime sinceUtc = nowUtc - LookBackWindow;

		await using AuditDbContext db = await _factory.CreateDbContextAsync(ct).ConfigureAwait(false);

		long rowsBefore = await db.AttackStats.LongCountAsync(ct).ConfigureAwait(false);

		// v3 invariant (Detect_Attack_Strategy_v3.md §8.1, §17.14): Total / Successful / Failed
		// counters MUST derive exclusively from AuthAttemptFact — the atomic source of truth.
		// We pull facts from AuthAttemptFacts, then synthesize AttackEventSample rows keyed by the
		// fact's authoritative SourceIp (or the unresolved-IP sentinel when NLA stripped the address
		// and no transport-IP correlation could supply one).
		//
		// v1.3.6: incremental passes order by TimeUtc DESC and take the newest MaxRawEventsPerPass so
		// fresh activity is never starved by a backlog of older in-window facts. The full-rebuild path
		// pages through EVERY in-window fact so a manual rebuild re-derives current-day LastSeenUtc for
		// every IP regardless of how many facts the look-back window holds.
		List<AuthAttemptFact> facts = fullRebuild
			? await LoadAllInWindowAsync(db, sinceUtc, ct).ConfigureAwait(false)
			: await db.AuthAttemptFacts.AsNoTracking()
				.Where(f => f.TimeUtc >= sinceUtc)
				.OrderByDescending(f => f.TimeUtc)
				.ThenByDescending(f => f.Id)
				.Take(MaxRawEventsPerPass)
				.ToListAsync(ct)
				.ConfigureAwait(false);

		DateTime? latestSourceFactUtc = facts.Count > 0
			? facts.Max(f => f.TimeUtc)
			: await db.AuthAttemptFacts.AsNoTracking().MaxAsync(f => (DateTime?)f.TimeUtc, ct).ConfigureAwait(false);

		HashSet<string> blockedIps = (await db.ActiveBlocks.AsNoTracking()
			.Where(b => b.Status == ActiveBlockStatus.Active || b.Status == ActiveBlockStatus.Pending)
			.Select(b => b.Ip)
			.ToListAsync(ct)
			.ConfigureAwait(false))
			.ToHashSet(StringComparer.OrdinalIgnoreCase);

		int unresolvedCount = 0;
		List<AttackEventSample> samples = new(facts.Count);
		foreach (AuthAttemptFact fact in facts)
		{
			// v1.2.1: re-normalise at the aggregation boundary as a final defence against
			// punctuation-wrapped legacy values (".77.37.192.246", " 77.37.192.246",
			// "::ffff:77.37.192.246") landing under a different aggregation key than the
			// canonical "77.37.192.246". Invalid values collapse to the unresolved sentinel.
			string? canonicalIp = IpNormalizer.Normalize(fact.SourceIp);
			string? sourceIp;
			if (!string.IsNullOrEmpty(canonicalIp))
			{
				sourceIp = canonicalIp;
			}
			else if (fact.Outcome == AuthAttemptOutcome.Failed || fact.Outcome == AuthAttemptOutcome.Denied)
			{
				// Preserve the failure under the unresolved-IP sentinel so Attack Statistics
				// reflects brute-force pressure even when Windows stripped the IpAddress field.
				sourceIp = AttackStatsAggregator.SentinelUnresolvedIp;
				unresolvedCount++;
			}
			else
			{
				continue;
			}

			samples.Add(new AttackEventSample(
				sourceIp,
				MapFactOutcomeToSyntheticEventId(fact.Outcome, fact.EvidenceEventId),
				fact.TimeUtc,
				fact.TargetUser,
				fact.LogonType,
				"Security"));
		}

		if (unresolvedCount > 0)
		{
			_logger.LogInformation(
				"{Worker} included {Count} unresolved-IP AuthAttemptFacts under sentinel {Sentinel}",
				nameof(AttackStatsRefreshWorker),
				unresolvedCount,
				AttackStatsAggregator.SentinelUnresolvedIp);
		}

		IReadOnlyList<AttackStat> projected = AttackStatsAggregator.Aggregate(samples, blockedIps, nowUtc);

		// Upsert into AttackStats. AttackStat.Ip is the primary key (Stage 2 schema).
		Dictionary<string, AttackStat> existing = await db.AttackStats
			.ToDictionaryAsync(s => s.Ip, ct)
			.ConfigureAwait(false);

		HashSet<string> projectedIps = new(StringComparer.OrdinalIgnoreCase);
		int upserts = 0;
		foreach (AttackStat row in projected)
		{
			projectedIps.Add(row.Ip);
			if (existing.TryGetValue(row.Ip, out AttackStat? current))
			{
				current.TotalAttempts = row.TotalAttempts;
				current.Successful = row.Successful;
				current.Failed = row.Failed;
				current.FirstSeenUtc = row.FirstSeenUtc;
				current.LastSeenUtc = row.LastSeenUtc;
				current.DurationSeconds = row.DurationSeconds;
				current.Top10AttemptedLogins = row.Top10AttemptedLogins;
				current.LastLoginType = row.LastLoginType;
				current.ThreatScore = row.ThreatScore;
				current.IsBlocked = row.IsBlocked;
				current.LastUpdatedUtc = row.LastUpdatedUtc;
			}
			else
			{
				db.AttackStats.Add(row);
			}
			upserts++;
		}

		// Rows whose IPs are no longer in the look-back window get a refreshed IsBlocked flag (the
		// firewall state may have changed) but are otherwise left alone so the dashboard keeps
		// historical context. Stale rows are removed by MaintenanceWorker on its retention pass.
		foreach (KeyValuePair<string, AttackStat> kvp in existing)
		{
			if (projectedIps.Contains(kvp.Key))
			{
				continue;
			}

			bool nowBlocked = blockedIps.Contains(kvp.Key);
			if (kvp.Value.IsBlocked != nowBlocked)
			{
				kvp.Value.IsBlocked = nowBlocked;
				kvp.Value.LastUpdatedUtc = nowUtc;
			}
		}

		await db.SaveChangesAsync(ct).ConfigureAwait(false);

		long rowsAfter = await db.AttackStats.AsNoTracking().LongCountAsync(ct).ConfigureAwait(false);
		DateTime? latestStatLastSeenUtc = await db.AttackStats.AsNoTracking()
			.MaxAsync(s => (DateTime?)s.LastSeenUtc, ct)
			.ConfigureAwait(false);

		return new AttackStatsRefreshResult(
			upserts,
			rowsBefore,
			rowsAfter,
			latestSourceFactUtc,
			latestStatLastSeenUtc,
			fullRebuild,
			false);
	}

	/// <summary>Full-rebuild loader: pages through every in-window fact (oldest first by Id so paging
	/// is stable) so the projection can re-derive every IP's current LastSeenUtc without the
	/// incremental MaxRawEventsPerPass truncation. Bounded only by available rows in the window.</summary>
	private static async Task<List<AuthAttemptFact>> LoadAllInWindowAsync(
		AuditDbContext db,
		DateTime sinceUtc,
		CancellationToken ct)
	{
		List<AuthAttemptFact> all = new();
		long lastId = 0;
		while (true)
		{
			List<AuthAttemptFact> page = await db.AuthAttemptFacts.AsNoTracking()
				.Where(f => f.TimeUtc >= sinceUtc && f.Id > lastId)
				.OrderBy(f => f.Id)
				.Take(FullRebuildPageSize)
				.ToListAsync(ct)
				.ConfigureAwait(false);

			if (page.Count == 0)
			{
				break;
			}

			all.AddRange(page);
			lastId = page[^1].Id;

			if (page.Count < FullRebuildPageSize)
			{
				break;
			}
		}

		return all;
	}

	/// <summary>
	/// Bridge between the AuthAttemptFact-derived facts and the existing
	/// <see cref="AttackStatsAggregator"/> contract, which classifies samples by raw Windows event id.
	/// We keep using the same aggregator (one source of truth for scoring) by mapping each fact
	/// outcome to the canonical Security event id (4624 success / 4625 failure). The original
	/// EvidenceEventId is preserved for diagnostic logs but never drives counter classification —
	/// per v3 §6.3 rule 3, only AuthAttemptFact's Outcome field is authoritative.
	/// </summary>
	internal static int MapFactOutcomeToSyntheticEventId(AuthAttemptOutcome outcome, int evidenceEventId)
	{
		_ = evidenceEventId;
		return outcome switch
		{
			AuthAttemptOutcome.Succeeded => AttackStatsAggregator.EventIdLogonSuccess,
			AuthAttemptOutcome.Failed => AttackStatsAggregator.EventIdLogonFailure,
			AuthAttemptOutcome.Denied => AttackStatsAggregator.EventIdLogonFailure,
			_ => 0,
		};
	}

	// ── Disposal & Pool Returns ──────────────────────────────────────────────────

	public override void Dispose()
	{
		if (Interlocked.Exchange(ref _disposed, 1) == 0)
		{
			_gate.Dispose();
		}

		base.Dispose();
	}
}

/// <summary>Outcome of a single <see cref="AttackStatsRefreshWorker"/> projection pass. Surfaced to the
/// DEBUG "Rebuild RDP Activity statistics" IPC action so an operator can confirm the rebuild advanced
/// the projection (RowsBefore/After) and that LastSeenUtc now tracks the freshest source fact.</summary>
/// <param name="RowsUpserted">AttackStat rows projected and written this pass.</param>
/// <param name="RowsBefore">AttackStats table row count before the pass.</param>
/// <param name="RowsAfter">AttackStats table row count after the pass.</param>
/// <param name="LatestSourceFactUtc">Newest AuthAttemptFact.TimeUtc considered (the projection input watermark).</param>
/// <param name="LatestAttackStatLastSeenUtc">Newest AttackStat.LastSeenUtc after the pass (the projection output watermark).</param>
/// <param name="FullRebuild">True when this pass paged through every in-window fact (DEBUG rebuild).</param>
/// <param name="WasSkipped">True when the re-entrancy gate rejected the pass (another pass was running).</param>
public readonly record struct AttackStatsRefreshResult(
	int RowsUpserted,
	long RowsBefore,
	long RowsAfter,
	DateTime? LatestSourceFactUtc,
	DateTime? LatestAttackStatLastSeenUtc,
	bool FullRebuild,
	bool WasSkipped)
{
	/// <summary>A pass that did not run because the re-entrancy gate was held.</summary>
	public static AttackStatsRefreshResult Skipped { get; } =
		new(0, 0, 0, null, null, false, true);
}
