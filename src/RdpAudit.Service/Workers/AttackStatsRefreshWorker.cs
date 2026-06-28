// File:    src/RdpAudit.Service/Workers/AttackStatsRefreshWorker.cs
// Module:  RdpAudit.Service.Workers
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
// Extends: Microsoft.Extensions.Hosting.BackgroundService
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

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

	private readonly IDbContextFactory<AuditDbContext> _factory;
	private readonly ILogger<AttackStatsRefreshWorker> _logger;
	private readonly ServiceMetrics? _metrics;
	private readonly SemaphoreSlim _gate = new(1, 1);

	public AttackStatsRefreshWorker(
		IDbContextFactory<AuditDbContext> factory,
		ILogger<AttackStatsRefreshWorker> logger,
		ServiceMetrics? metrics = null)
	{
		_factory = factory;
		_logger = logger;
		_metrics = metrics;
	}

	protected override async Task ExecuteAsync(CancellationToken stoppingToken)
	{
		_logger.LogInformation("{Worker} starting", nameof(AttackStatsRefreshWorker));
		_metrics?.SetStatsWorkerEnabled(true);
		try
		{
			// Startup refresh: kick the first pass without waiting for the cadence.
			await SafeRefreshAsync(stoppingToken).ConfigureAwait(false);

			while (!stoppingToken.IsCancellationRequested)
			{
				try
				{
					await Task.Delay(Period, stoppingToken).ConfigureAwait(false);
				}
				catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
				{
					break;
				}

				await SafeRefreshAsync(stoppingToken).ConfigureAwait(false);
			}
		}
		finally
		{
			_logger.LogInformation("{Worker} stopped", nameof(AttackStatsRefreshWorker));
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
			_logger.LogDebug("{Worker} refresh skipped: previous pass still running", nameof(AttackStatsRefreshWorker));
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

	private async Task SafeRefreshAsync(CancellationToken ct)
	{
		try
		{
			AttackStatsRefreshResult result = await RefreshOnceDetailedAsync(false, ct).ConfigureAwait(false);
			_logger.LogDebug("{Worker} pass complete, rows materialised: {Rows}", nameof(AttackStatsRefreshWorker), result.RowsUpserted);
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

	public override void Dispose()
	{
		_gate.Dispose();
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
