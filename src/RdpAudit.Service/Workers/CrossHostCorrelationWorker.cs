/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// File   : CrossHostCorrelationWorker.cs
// Project: RdpAudit.Service (RdpAudit.Service.Workers)
// Purpose: P4-18 pull-model cross-host correlation loop. Polls every configured agent host
//          through the IHostFactSource abstraction, persists bounded fact projections
//          (deduplicated by their stable DedupKey), feeds the pure CrossHostCorrelationEngine
//          with persisted facts plus a fail-closed per-host availability view, and stores newly
//          emitted attack chains and per-host health states. Every host is polled sequentially
//          so a vanished agent is bounded by its connect/round-trip deadline instead of
//          starving the other hosts; transient SQLITE_BUSY / SQLITE_LOCKED errors are retried
//          with a short exponential backoff.
// Depends: IDbContextFactory<AuditDbContext>, RdpAuditOptions (CrossHost section), IHostFactSource,
//          CrossHostCorrelationEngine, EF entities CrossHostFact/Chain/Link/HostState
// Extends: Add new transports by registering another IHostFactSource factory; the worker only
//          sees the source abstraction.

using System.Globalization;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using RdpAudit.Core.Config;
using RdpAudit.Core.CrossHost;
using RdpAudit.Core.Editions;
using RdpAudit.Core.Data;
using RdpAudit.Core.Ipc.Contracts;
using RdpAudit.Core.Models;
using RdpAudit.Service.CrossHost;

namespace RdpAudit.Service.Workers;

/// <summary>Polling correlation worker described in the file Purpose header.</summary>
/// <remarks>
/// Fail-closed semantics: a host that reports anything other than
/// <see cref="IpcResultStatus.Success"/> is recorded as Unavailable and contributes no facts to
/// the engine. Facts are withheld from correlation only when their contributing host is
/// unavailable in the same pass; the availability map is keyed by both the configured host name
/// and the fact-reported host name observed in successful pulls, so re-pulling over an alias
/// (IP vs machine name) never lets a dead host's stale rows back into the engine.
/// </remarks>
public sealed class CrossHostCorrelationWorker : BackgroundService
{
	private static readonly TimeSpan[] BusyBackoffs =
	{
		TimeSpan.FromMilliseconds(25),
		TimeSpan.FromMilliseconds(50),
		TimeSpan.FromMilliseconds(100),
		TimeSpan.FromMilliseconds(200),
		TimeSpan.FromMilliseconds(400),
	};

	private readonly IDbContextFactory<AuditDbContext> _factory;
	private readonly IOptionsMonitor<RdpAuditOptions> _options;
	private readonly ILogger<CrossHostCorrelationWorker> _logger;
	private readonly CrossHostCorrelationEngine _engine;
	private readonly Func<CrossHostHostOptions, IHostFactSource> _sourceFactory;
	private readonly TimeProvider _timeProvider;

	public CrossHostCorrelationWorker(
		IDbContextFactory<AuditDbContext> factory,
		IOptionsMonitor<RdpAuditOptions> options,
		ILogger<CrossHostCorrelationWorker> logger,
		CrossHostCorrelationEngine? engine = null,
		Func<CrossHostHostOptions, IHostFactSource>? sourceFactory = null,
		TimeProvider? timeProvider = null)
	{
		_factory = factory ?? throw new ArgumentNullException(nameof(factory));
		_options = options ?? throw new ArgumentNullException(nameof(options));
		_logger = logger ?? throw new ArgumentNullException(nameof(logger));
		_engine = engine ?? new CrossHostCorrelationEngine();
		_timeProvider = timeProvider ?? TimeProvider.System;
		_sourceFactory = sourceFactory ?? (host => new RemoteHostFactSource(new NamedPipeCrossHostIpcTransport
		{
			HostName = host.HostName,
			ConnectTimeoutMs = _options.CurrentValue.CrossHost.ResolveConnectTimeoutMs(),
		}));
	}

	protected override async Task ExecuteAsync(CancellationToken stoppingToken)
	{
		_logger.LogInformation("{Worker} starting", nameof(CrossHostCorrelationWorker));
		try
		{
			while (!stoppingToken.IsCancellationRequested)
			{
				CrossHostOptions crossHost = _options.CurrentValue.CrossHost;
				if (crossHost.Enabled)
				{
					try
					{
						await RunOnceAsync(stoppingToken).ConfigureAwait(false);
					}
					catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
					{
						break;
					}
					catch (Exception ex)
					{
						_logger.LogError(ex, "Cross-host correlation iteration failed");
					}
				}

				await Task.Delay(TimeSpan.FromSeconds(crossHost.ResolvePollIntervalSeconds()), stoppingToken).ConfigureAwait(false);
			}
		}
		catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
		{
		}
		finally
		{
			_logger.LogInformation("{Worker} stopped", nameof(CrossHostCorrelationWorker));
		}
	}

	/// <summary>Runs one full correlation pass: poll all configured hosts, persist new facts,
	/// run the engine over the persisted fact window and persist new chains and host states.
	/// Exposed for tests; production callers use <see cref="ExecuteAsync"/>.</summary>
	internal async Task RunOnceAsync(CancellationToken ct)
	{
		ct.ThrowIfCancellationRequested();

		CrossHostOptions crossHost = _options.CurrentValue.CrossHost;
		if (!crossHost.Enabled)
		{
			_logger.LogDebug("Cross-host correlation disabled - poll skipped.");
			return;
		}

		List<CrossHostHostOptions> hosts = crossHost.ResolveHosts();

		// Edition budget (Pro 25 hosts, Enterprise 500). A budget of zero means the capability is
		// absent from THIS build, in which case the worker is not part of the service composition and
		// clamping is meaningless - only the composed worker is bounded. Truncation is loud: an
		// operator must never believe the whole fleet is correlated when only part of it is.
		int hostBudget = EditionContext.MaxCrossHostHosts;
		if (hostBudget > 0 && hosts.Count > hostBudget)
		{
			_logger.LogWarning(
				"Cross-host correlation: {Configured} host(s) are configured but the {Edition} edition correlates at most {Budget}; the remaining {Dropped} host(s) are not polled.",
				hosts.Count,
				EditionContext.DisplayName,
				hostBudget,
				hosts.Count - hostBudget);
			hosts = hosts.GetRange(0, hostBudget);
		}

		if (hosts.Count == 0)
		{
			_logger.LogWarning("Cross-host correlation enabled but no agent hosts are configured - poll skipped.");
			return;
		}

		DateTime nowUtc = _timeProvider.GetUtcNow().UtcDateTime;
		int maxFacts = crossHost.ResolveMaxFactsPerPoll();

		// Phase 1 - poll every host and project accepted facts. Persistence deliberately starts
		// only after ALL pulls finish so a slow agent never blocks the SQLite writer while other
		// hosts are still being pulled.
		List<CrossHostFactProjection> pulled = new();
		Dictionary<string, CrossHostAvailability> availabilityByHost = new(StringComparer.OrdinalIgnoreCase);
		List<(CrossHostHostOptions Host, CrossHostFactsDto Result)> pollResults = new();
		int factsRejected = 0;

		for (int i = 0; i < hosts.Count; i++)
		{
			ct.ThrowIfCancellationRequested();
			CrossHostHostOptions host = hosts[i];

			DateTime? sinceUtc = await ResolveWatermarkAsync(host.HostName, nowUtc, ct).ConfigureAwait(false);
			IHostFactSource source = _sourceFactory(host);
			CrossHostFactsDto dto = await source.PullFactsAsync(
				sinceUtc,
				maxFacts,
				"crosshost-poll-" + i.ToString(CultureInfo.InvariantCulture),
				ct).ConfigureAwait(false);

			bool available = dto.Status == IpcResultStatus.Success;
			availabilityByHost[host.HostName] = available ? CrossHostAvailability.Available : CrossHostAvailability.Unavailable;
			pollResults.Add((host, dto));

			if (!available)
			{
				_logger.LogWarning(
					"Agent host {Host} unavailable for cross-host polling: {Message}",
					host.HostName,
					dto.Message ?? "(no detail)");
				continue;
			}

			foreach (CrossHostFactDto? fact in dto.Facts ?? new List<CrossHostFactDto>())
			{
				if (fact is null)
				{
					factsRejected++;
					continue;
				}

				CrossHostFactProjection projection = MapToProjection(fact);
				if (!projection.IsValid())
				{
					factsRejected++;
					continue;
				}

				pulled.Add(projection);
				// Source-authorized alias: facts that arrived through an authenticated successful
				// pull authorize their reported host name as available for this pass, so an
				// IP-alias configuration cannot let a dead host's facts re-enter correlation.
				availabilityByHost[projection.HostName.Trim()] = CrossHostAvailability.Available;
			}
		}

		// Phase 2 - persist new facts (dedup by stable DedupKey) and correlate.
		int factsPersisted = await PersistPulledFactsAsync(pulled, nowUtc, ct).ConfigureAwait(false);

		List<CrossHostAvailabilityView> views = availabilityByHost
			.Select(pair => new CrossHostAvailabilityView(pair.Key, pair.Value, null, null))
			.ToList();

		List<CrossHostFactProjection> engineFacts = await LoadRecentFactsAsync(nowUtc, ct).ConfigureAwait(false);
		ISet<string> knownChainKeys = await LoadKnownChainKeysAsync(nowUtc, ct).ConfigureAwait(false);
		CrossHostCorrelationResult correlation = _engine.Correlate(engineFacts, views, nowUtc, knownChainKeys);

		int chainsPersisted = await PersistChainsAsync(correlation.Chains, nowUtc, ct).ConfigureAwait(false);
		await PersistHostStatesAsync(pollResults, nowUtc, ct).ConfigureAwait(false);

		int unavailable = pollResults.Count(pair => pair.Result.Status != IpcResultStatus.Success);
		_logger.LogInformation(
			"Cross-host correlation pass complete: hosts={Hosts} unavailable={Unavailable} factsPulled={Pulled} factsRejected={Rejected} factsPersisted={Persisted} factsCorrelated={FactsAccepted} chainsNew={ChainsNew}",
			hosts.Count,
			unavailable,
			pulled.Count,
			factsRejected,
			factsPersisted,
			correlation.FactsAccepted,
			chainsPersisted);
	}

	// ── Poll helpers ───────────────────────────────────────────────────────────

	/// <summary>Resolves the exclusive watermark for the next pull of one host: the persisted
	/// LastSeenUtc when the host was polled successfully before, otherwise a full correlation
	/// window back so the initial pull hydrates the engine's working set.</summary>
	private async Task<DateTime?> ResolveWatermarkAsync(string hostName, DateTime nowUtc, CancellationToken ct)
	{
		await using AuditDbContext db = await _factory.CreateDbContextAsync(ct).ConfigureAwait(false);
		CrossHostHostState? state = await db.CrossHostHostStates
			.AsNoTracking()
			.FirstOrDefaultAsync(s => s.HostName == hostName, ct)
			.ConfigureAwait(false);

		return state?.LastSeenUtc ?? nowUtc.AddHours(-CrossHostChainRule.DefaultMaxFactAgeHours);
	}

	private static CrossHostFactProjection MapToProjection(CrossHostFactDto dto)
	{
		CrossHostFactProjection projection = new()
		{
			HostName = dto.HostName?.Trim() ?? string.Empty,
			TimeUtc = DateTime.SpecifyKind(dto.TimeUtc, DateTimeKind.Utc),
			UserName = dto.UserName,
			NormalizedUserName = dto.NormalizedUserName,
			SourceIp = dto.SourceIp,
			LogonType = dto.LogonType,
			Kind = dto.Kind,
			EventId = dto.EventId,
			DedupKey = dto.DedupKey,
		};

		if (string.IsNullOrWhiteSpace(projection.DedupKey))
		{
			projection.DedupKey = projection.BuildDedupKey();
		}

		return projection;
	}

	// ── Persistence helpers ────────────────────────────────────────────────────

	/// <summary>Inserts fact projections missing from the central database. Idempotent: a
	/// re-pull of the same observation is skipped by DedupKey instead of violating the unique
	/// index. Returns the number of rows inserted.</summary>
	private async Task<int> PersistPulledFactsAsync(List<CrossHostFactProjection> facts, DateTime nowUtc, CancellationToken ct)
	{
		if (facts.Count == 0)
		{
			return 0;
		}

		await using AuditDbContext db = await _factory.CreateDbContextAsync(ct).ConfigureAwait(false);
		HashSet<string> existing = await LoadExistingDedupKeysAsync(db, facts, ct).ConfigureAwait(false);

		int persisted = 0;
		HashSet<string> addedInBatch = new(StringComparer.Ordinal);
		foreach (CrossHostFactProjection fact in facts)
		{
			ct.ThrowIfCancellationRequested();
			string key = fact.DedupKey ?? fact.BuildDedupKey();
			if (existing.Contains(key) || !addedInBatch.Add(key))
			{
				continue;
			}

			db.CrossHostFacts.Add(new CrossHostFact
			{
				HostName = fact.HostName.Trim(),
				TimeUtc = fact.TimeUtc,
				UserName = fact.UserName,
				NormalizedUserName = fact.NormalizedUserName,
				SourceIp = fact.SourceIp,
				LogonType = fact.LogonType,
				Kind = fact.Kind,
				EventId = fact.EventId,
				DedupKey = key,
				IngestedUtc = nowUtc,
			});
			persisted++;
		}

		await WithBusyRetryAsync(token => db.SaveChangesAsync(token), ct).ConfigureAwait(false);
		return persisted;
	}

	/// <summary>Loads the DedupKeys already present in the central database for the supplied
	/// projections, in bounded chunks so the SQLite variable limit is never exceeded.</summary>
	private static async Task<HashSet<string>> LoadExistingDedupKeysAsync(
		AuditDbContext db,
		List<CrossHostFactProjection> facts,
		CancellationToken ct)
	{
		List<string> keys = facts
			.Select(f => f.DedupKey ?? f.BuildDedupKey())
			.Where(k => !string.IsNullOrEmpty(k))
			.Distinct(StringComparer.Ordinal)
			.ToList();

		HashSet<string> existing = new(StringComparer.Ordinal);
		for (int offset = 0; offset < keys.Count; offset += 500)
		{
			List<string> chunk = keys.GetRange(offset, Math.Min(500, keys.Count - offset));
			List<string?> found = await db.CrossHostFacts
				.AsNoTracking()
				.Where(f => f.DedupKey != null && chunk.Contains(f.DedupKey))
				.Select(f => f.DedupKey)
				.ToListAsync(ct)
				.ConfigureAwait(false);

			foreach (string? foundKey in found)
			{
				if (foundKey is not null)
				{
					existing.Add(foundKey);
				}
			}
		}

		return existing;
	}

	/// <summary>Loads the persisted fact window the engine works on. TimeUtc values are
	/// re-specified as UTC because the SQLite round-trip returns Unspecified kinds, which the
	/// engine's trust boundary rejects.</summary>
	private async Task<List<CrossHostFactProjection>> LoadRecentFactsAsync(DateTime nowUtc, CancellationToken ct)
	{
		DateTime cutoff = nowUtc.AddHours(-CrossHostChainRule.DefaultMaxFactAgeHours - 2);
		await using AuditDbContext db = await _factory.CreateDbContextAsync(ct).ConfigureAwait(false);
		List<CrossHostFact> rows = await db.CrossHostFacts
			.AsNoTracking()
			.Where(f => f.TimeUtc >= cutoff)
			.OrderBy(f => f.TimeUtc)
			.ThenBy(f => f.Id)
			.ToListAsync(ct)
			.ConfigureAwait(false);

		List<CrossHostFactProjection> projections = new(rows.Count);
		foreach (CrossHostFact row in rows)
		{
			projections.Add(new CrossHostFactProjection
			{
				HostName = row.HostName,
				TimeUtc = DateTime.SpecifyKind(row.TimeUtc, DateTimeKind.Utc),
				UserName = row.UserName,
				NormalizedUserName = row.NormalizedUserName,
				SourceIp = row.SourceIp,
				LogonType = row.LogonType,
				Kind = row.Kind,
				EventId = row.EventId,
				DedupKey = row.DedupKey,
			});
		}

		return projections;
	}

	/// <summary>Loads the ChainKeys the engine must still deduplicate: those observed inside the
	/// fact window. A chain older than that window cannot be re-derived from the facts the engine
	/// loads, so forgetting its key lets a NEW occurrence of the same route raise a new alert
	/// instead of being suppressed forever by the time-independent key.</summary>
	private async Task<ISet<string>> LoadKnownChainKeysAsync(DateTime nowUtc, CancellationToken ct)
	{
		DateTime cutoff = nowUtc.AddHours(-(CrossHostChainRule.DefaultMaxFactAgeHours + 2));
		await using AuditDbContext db = await _factory.CreateDbContextAsync(ct).ConfigureAwait(false);
		List<string> keys = await db.CrossHostChains
			.AsNoTracking()
			.Where(c => c.LastSeenUtc >= cutoff)
			.Select(c => c.ChainKey)
			.ToListAsync(ct)
			.ConfigureAwait(false);

		return new HashSet<string>(keys, StringComparer.Ordinal);
	}

	/// <summary>Persists engine-emitted chains with their ordered links. An existing
	/// (RuleId, ChainKey) row is REFRESHED rather than duplicated, and its alert gate is cleared so
	/// a re-occurrence outside the dedup window raises a new CROSS_HOST_CHAIN alert. The engine only
	/// emits a candidate whose key is stale/unknown, so a row found here is exactly that re-occurrence.
	/// A (RuleId, ChainKey) collision from a concurrent pass is still caught and skipped.</summary>
	internal async Task<int> PersistChainsAsync(List<CrossHostChainCandidate> candidates, DateTime nowUtc, CancellationToken ct)
	{
		if (candidates.Count == 0)
		{
			return 0;
		}

		await using AuditDbContext db = await _factory.CreateDbContextAsync(ct).ConfigureAwait(false);
		int touched = 0;
		foreach (CrossHostChainCandidate candidate in candidates)
		{
			ct.ThrowIfCancellationRequested();

			CrossHostChain? existing = await db.CrossHostChains
				.FirstOrDefaultAsync(c => c.RuleId == candidate.RuleId && c.ChainKey == candidate.ChainKey, ct)
				.ConfigureAwait(false);
			if (existing is not null)
			{
				// Re-occurrence outside the dedup window: refresh the row and clear the alert gate
				// so the alert processor raises a NEW alert. The stored links are kept: the ChainKey
				// pins the hop path, so a refreshed chain describes the same route.
				existing.NormalizedUserName = candidate.NormalizedUserName;
				existing.FirstSeenUtc = candidate.FirstSeenUtc;
				existing.LastSeenUtc = candidate.LastSeenUtc;
				existing.DetectedUtc = nowUtc;
				existing.Score = candidate.Score;
				existing.FailedAttemptCount = candidate.FailedAttemptCount;
				existing.AlertId = null;
				existing.IsAcknowledged = false;
				touched++;
				continue;
			}

			CrossHostChain chain = new()
			{
				ChainKey = candidate.ChainKey,
				RuleId = candidate.RuleId,
				NormalizedUserName = candidate.NormalizedUserName,
				FirstSeenUtc = candidate.FirstSeenUtc,
				LastSeenUtc = candidate.LastSeenUtc,
				Score = candidate.Score,
				FailedAttemptCount = candidate.FailedAttemptCount,
				DetectedUtc = nowUtc,
			};

			int ordinal = 0;
			foreach (CrossHostChainLinkCandidate link in candidate.Links)
			{
				chain.Links.Add(new CrossHostLink
				{
					Ordinal = ordinal++,
					HostName = link.HostName,
					Kind = link.Kind,
					EventId = link.EventId,
					TimeUtc = DateTime.SpecifyKind(link.TimeUtc, DateTimeKind.Utc),
					SourceIp = link.SourceIp,
					UserName = link.UserName,
				});
			}

			db.CrossHostChains.Add(chain);
			touched++;
		}

		try
		{
			await WithBusyRetryAsync(token => db.SaveChangesAsync(token), ct).ConfigureAwait(false);
			return touched;
		}
		catch (DbUpdateException ex)
		{
			_logger.LogWarning(ex, "Cross-host chain insert collided with an existing row; batch skipped (idempotent on the next pass).");
			return 0;
		}
	}

	/// <summary>Updates one state row per configured host: availability, last successful fact
	/// watermark, last error and last polled timestamp.</summary>
	private async Task PersistHostStatesAsync(
		List<(CrossHostHostOptions Host, CrossHostFactsDto Result)> pollResults,
		DateTime nowUtc,
		CancellationToken ct)
	{
		if (pollResults.Count == 0)
		{
			return;
		}

		await using AuditDbContext db = await _factory.CreateDbContextAsync(ct).ConfigureAwait(false);
		foreach ((CrossHostHostOptions host, CrossHostFactsDto result) in pollResults)
		{
			ct.ThrowIfCancellationRequested();
			CrossHostHostState? state = await db.CrossHostHostStates
				.FirstOrDefaultAsync(s => s.HostName == host.HostName, ct)
				.ConfigureAwait(false);

			if (state is null)
			{
				state = new CrossHostHostState { HostName = host.HostName };
				db.CrossHostHostStates.Add(state);
			}

			if (result.Status == IpcResultStatus.Success)
			{
				state.Availability = CrossHostAvailability.Available;
				state.LastSeenUtc = result.LatestFactUtc ?? state.LastSeenUtc;
				state.LastError = null;
			}
			else
			{
				state.Availability = CrossHostAvailability.Unavailable;
				state.LastSeenUtc = null;
				state.LastError = Truncate(result.Message, 1024);
			}

			state.LastPolledUtc = nowUtc;
		}

		await WithBusyRetryAsync(token => db.SaveChangesAsync(token), ct).ConfigureAwait(false);
	}

	private static string? Truncate(string? value, int maxLength)
	{
		if (string.IsNullOrEmpty(value) || value.Length <= maxLength)
		{
			return value;
		}

		return value[..maxLength];
	}

	// ── SQLite resilience ──────────────────────────────────────────────────────

	/// <summary>Executes <paramref name="action"/>, retrying transient SQLite busy/locked errors
	/// (codes 5 / 6) with a short exponential backoff. Other exceptions propagate immediately.</summary>
	private async Task WithBusyRetryAsync(Func<CancellationToken, Task> action, CancellationToken ct)
	{
		await WithBusyRetryAsync<object?>(async token =>
		{
			await action(token).ConfigureAwait(false);
			return null;
		}, ct).ConfigureAwait(false);
	}

	private async Task<TResult> WithBusyRetryAsync<TResult>(
		Func<CancellationToken, Task<TResult>> action,
		CancellationToken ct)
	{
		for (int i = 0; i < BusyBackoffs.Length; i++)
		{
			try
			{
				return await action(ct).ConfigureAwait(false);
			}
			catch (Exception ex) when (SqliteTransientErrors.IsTransient(ex))
			{
				if (i == BusyBackoffs.Length - 1)
				{
					throw;
				}

				_logger.LogWarning(
					"Cross-host correlation DB busy (attempt {Attempt}) - retrying in {Ms}ms",
					i + 1,
					BusyBackoffs[i].TotalMilliseconds);
				await Task.Delay(BusyBackoffs[i], ct).ConfigureAwait(false);
			}
		}

		// Unreachable: the loop either returns or rethrows.
		throw new InvalidOperationException("Retry loop exited without producing a result.");
	}
}
