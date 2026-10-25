// File:    src/RdpAudit.Service/Workers/ThreatIntelEnrichmentWorker.cs
// Module:  RdpAudit.Service.Workers
// Purpose: Backlog #5 background worker that keeps the persistent threat-intel cache warm. Each
//          pass gathers candidate PUBLIC, non-whitelisted IPs from AttackStats (highest threat
//          first) and recent RdpConnectionFacts, skips IPs that already have a fresh cache row or
//          a provider-imposed NextRetryUtc in the future, and performs at most the configured
//          per-minute / per-day budget of /api/v2/check lookups through IThreatIntelligenceClient.
//          Results are persisted through ThreatIntelLookupStore; the IPC request path reads ONLY
//          cached rows and never performs HTTP. Fail-closed throughout: a lookup failure writes a
//          non-Success row which can never manufacture a High-risk mark. Honours CancellationToken,
//          guards against concurrent re-entry and never logs the API key.
// Extends: Microsoft.Extensions.Hosting.BackgroundService
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using RdpAudit.Core.Config;
using RdpAudit.Core.Data;
using RdpAudit.Core.Models;
using RdpAudit.Core.ThreatIntel;
using RdpAudit.Core.Util;
using RdpAudit.Service.ThreatIntel;

namespace RdpAudit.Service.Workers;

/// <summary>Backlog #5 background worker refreshing the threat-intel reputation cache.</summary>
public sealed class ThreatIntelEnrichmentWorker : BackgroundService
{
	/// <summary>Initial delay before the first pass - let the DB migrations and other workers settle.</summary>
	internal static readonly TimeSpan StartupDelay = TimeSpan.FromMinutes(1);

	/// <summary>Upper bound on rows considered per source per pass. The outbound volume is further
	/// bounded by the per-minute / per-day lookup budget in <see cref="ThreatIntelRateLimiter"/>.</summary>
	internal const int MaxCandidatesPerPass = 50;

	/// <summary>How far back RdpConnectionFacts qualify as "recent" connection candidates.</summary>
	internal static readonly TimeSpan LookBackWindow = TimeSpan.FromDays(30);

	private readonly IDbContextFactory<AuditDbContext> _factory;
	private readonly IOptionsMonitor<RdpAuditOptions> _options;
	private readonly IThreatIntelligenceClient _client;
	private readonly ThreatIntelLookupStore _store;
	private readonly ThreatIntelRateLimiter _rateLimiter;
	private readonly ILogger<ThreatIntelEnrichmentWorker> _logger;
	private readonly TimeProvider _time;
	private readonly SemaphoreSlim _gate = new(1, 1);
	private readonly object _passRecordGate = new();
	private ThreatIntelPassTelemetry _lastPass;

	public ThreatIntelEnrichmentWorker(
		IDbContextFactory<AuditDbContext> factory,
		IOptionsMonitor<RdpAuditOptions> options,
		IThreatIntelligenceClient client,
		ThreatIntelLookupStore store,
		ThreatIntelRateLimiter rateLimiter,
		ILogger<ThreatIntelEnrichmentWorker> logger,
		TimeProvider? time = null)
	{
		ArgumentNullException.ThrowIfNull(factory);
		ArgumentNullException.ThrowIfNull(options);
		ArgumentNullException.ThrowIfNull(client);
		ArgumentNullException.ThrowIfNull(store);
		ArgumentNullException.ThrowIfNull(rateLimiter);
		ArgumentNullException.ThrowIfNull(logger);
		_factory = factory;
		_options = options;
		_client = client;
		_store = store;
		_rateLimiter = rateLimiter;
		_logger = logger;
		_time = time ?? TimeProvider.System;
	}

	protected override async Task ExecuteAsync(CancellationToken stoppingToken)
	{
		_logger.LogInformation("{Worker} starting", nameof(ThreatIntelEnrichmentWorker));
		try
		{
			try
			{
				await Task.Delay(StartupDelay, stoppingToken).ConfigureAwait(false);
			}
			catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
			{
				return;
			}

			while (!stoppingToken.IsCancellationRequested)
			{
				await SafeRunAsync(stoppingToken).ConfigureAwait(false);
				try
				{
					await Task.Delay(GetPeriod(), stoppingToken).ConfigureAwait(false);
				}
				catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
				{
					break;
				}
			}
		}
		finally
		{
			_logger.LogInformation("{Worker} stopped", nameof(ThreatIntelEnrichmentWorker));
		}
	}

	/// <summary>Refresh cadence from configuration, clamped to the canonical 30..86400s band.</summary>
	private TimeSpan GetPeriod()
	{
		AbuseIpDbOptions opts = _options.CurrentValue.AbuseIpDb;
		return TimeSpan.FromSeconds(ThreatIntelLimits.ClampWorkerIntervalSeconds(opts.CheckWorkerIntervalSeconds));
	}

	/// <summary>Runs a single enrichment pass deterministically. Exposed for tests; honours the
	/// concurrency gate. Returns the number of lookups actually performed.</summary>
	public async Task<int> RunOnceAsync(CancellationToken ct)
	{
		if (!await _gate.WaitAsync(0, ct).ConfigureAwait(false))
		{
			_logger.LogDebug("{Worker} skipped: previous pass still running", nameof(ThreatIntelEnrichmentWorker));
			return 0;
		}

		DateTime startedUtc = _time.GetUtcNow().UtcDateTime;
		try
		{
			int performed = await RunPassAsync(ct).ConfigureAwait(false);
			RecordPass(startedUtc, _time.GetUtcNow().UtcDateTime, performed, error: null);
			return performed;
		}
		catch (OperationCanceledException) when (ct.IsCancellationRequested)
		{
			throw;
		}
		catch (Exception ex)
		{
			RecordPass(startedUtc, _time.GetUtcNow().UtcDateTime, 0, SanitizePassError(ex));
			throw;
		}
		finally
		{
			_gate.Release();
		}
	}

	/// <summary>Snapshot of the most recent completed or failed pass; default value when no pass
	/// has run yet. Exposed for the GetThreatIntelStatus IPC handler.</summary>
	public ThreatIntelPassTelemetry LastPass
	{
		get
		{
			lock (_passRecordGate)
			{
				return _lastPass;
			}
		}
	}

	private void RecordPass(DateTime startedUtc, DateTime finishedUtc, int lookups, string? error)
	{
		lock (_passRecordGate)
		{
			_lastPass = new ThreatIntelPassTelemetry(startedUtc, finishedUtc, lookups, error);
		}
	}

	private static string SanitizePassError(Exception ex)
	{
		string message = ex.Message ?? string.Empty;
		if (message.Length > 300)
		{
			message = message.Substring(0, 300);
		}

		return ex.GetType().Name + ": " + message;
	}

	private async Task SafeRunAsync(CancellationToken ct)
	{
		try
		{
			int performed = await RunOnceAsync(ct).ConfigureAwait(false);
			_logger.LogDebug("{Worker} pass complete, lookups={Lookups}", nameof(ThreatIntelEnrichmentWorker), performed);
		}
		catch (OperationCanceledException) when (ct.IsCancellationRequested)
		{
			// Quiet shutdown.
		}
		catch (Exception ex)
		{
			_logger.LogError(ex, "{Worker} pass failed", nameof(ThreatIntelEnrichmentWorker));
		}
	}

	private async Task<int> RunPassAsync(CancellationToken ct)
	{
		AbuseIpDbOptions opts = _options.CurrentValue.AbuseIpDb;
		if (!opts.Enabled || !opts.CheckEnabled || !opts.CacheLookups)
		{
			return 0;
		}

		if (string.IsNullOrWhiteSpace(opts.ApiKey))
		{
			return 0;
		}

		DateTime nowUtc = _time.GetUtcNow().UtcDateTime;
		string todayKey = _rateLimiter.TodayKey();

		await using AuditDbContext db = await _factory.CreateDbContextAsync(ct).ConfigureAwait(false);

		HashSet<string> whitelistDb = (await db.WhitelistEntries.AsNoTracking()
			.Select(w => w.Ip)
			.ToListAsync(ct)
			.ConfigureAwait(false))
			.Where(static s => !string.IsNullOrWhiteSpace(s))
			.ToHashSet(StringComparer.OrdinalIgnoreCase);

		List<string> attackIps = await db.AttackStats.AsNoTracking()
			.Where(s => !string.IsNullOrEmpty(s.Ip))
			.OrderByDescending(s => s.ThreatScore)
			.ThenByDescending(s => s.LastSeenUtc)
			.ThenBy(s => s.Ip)
			.Select(s => s.Ip)
			.Take(MaxCandidatesPerPass)
			.ToListAsync(ct)
			.ConfigureAwait(false);

		DateTime factCutoff = nowUtc - LookBackWindow;
		List<string> factIps = await db.RdpConnectionFacts.AsNoTracking()
			.Where(f => !string.IsNullOrEmpty(f.Ip) && f.LastSeenUtc >= factCutoff)
			.OrderByDescending(f => f.LastSeenUtc)
			.ThenBy(f => f.Ip)
			.Select(f => f.Ip)
			.Take(MaxCandidatesPerPass)
			.ToListAsync(ct)
			.ConfigureAwait(false);

		List<string> candidates = BuildCandidateList(attackIps, factIps);
		if (candidates.Count == 0)
		{
			return 0;
		}

		// Only public, non-whitelisted candidates ever reach a lookup.
		List<string> scope = new(candidates.Count);
		foreach (string ip in candidates)
		{
			if (IpClassifier.IsPublicIp(ip) && !whitelistDb.Contains(ip))
			{
				scope.Add(ip);
			}
		}

		if (scope.Count == 0)
		{
			return 0;
		}

		Dictionary<string, ThreatIntelLookup> existing =
			(await db.ThreatIntelLookups.AsNoTracking()
				.Where(r => scope.Contains(r.Ip))
				.ToListAsync(ct)
				.ConfigureAwait(false))
			.ToDictionary(static r => r.Ip, StringComparer.Ordinal);

		int maxAge = ThreatIntelLimits.ClampMaxAgeInDays(opts.CheckMaxAgeInDays);
		DateTime freshCutoff = nowUtc.AddDays(-maxAge);
		int dailyCount = await _store.GetDailyCountAsync(todayKey, ct).ConfigureAwait(false);
		int performed = 0;

		foreach (string ip in scope)
		{
			ct.ThrowIfCancellationRequested();

			if (existing.TryGetValue(ip, out ThreatIntelLookup? row))
			{
				// Honour the provider back-off, then skip still-fresh Success snapshots.
				if (row.NextRetryUtc is { } retry && retry > nowUtc)
				{
					continue;
				}

				if (row.Outcome == (int)ThreatIntelLookupOutcome.Success && row.LookedUpUtc >= freshCutoff)
				{
					continue;
				}
			}

			if (!_rateLimiter.CanLookup(opts, dailyCount))
			{
				_logger.LogDebug("Threat-intel lookup budget exhausted; stopping pass at {Ip}", ip);
				break;
			}

			_rateLimiter.RecordLookup();
			dailyCount++;

			ThreatIntelLookupResult result;
			try
			{
				result = await _client.LookupAsync(ip, ct).ConfigureAwait(false);
			}
			catch (OperationCanceledException) when (ct.IsCancellationRequested)
			{
				throw;
			}
			catch (Exception ex)
			{
				_logger.LogWarning(ex, "Threat-intel lookup threw for {Ip}", ip);
				result = new ThreatIntelLookupResult
				{
					Outcome = ThreatIntelLookupOutcome.TransportError,
					Ip = ip,
					Message = "Exception performing lookup: " + ex.GetType().Name,
				};
			}

			await _store.UpsertAsync(result, ct: ct).ConfigureAwait(false);
			await _store.IncrementDailyCountAsync(todayKey, ct).ConfigureAwait(false);
			performed++;

			if (result.Outcome == ThreatIntelLookupOutcome.RateLimited)
			{
				_logger.LogWarning("AbuseIPDB rate-limited threat-intel lookups; pausing this pass");
				break;
			}
		}

		return performed;
	}

	/// <summary>Merges the two candidate sources into one de-duplicated, normalized, ordered list:
	/// AttackStats candidates (highest threat first) win over RdpConnectionFact candidates.</summary>
	internal static List<string> BuildCandidateList(List<string> attackIps, List<string> factIps)
	{
		// ReSharper disable once ConditionIsAlwaysTrueOrFalse
		ArgumentNullException.ThrowIfNull(attackIps);
		// ReSharper disable once ConditionIsAlwaysTrueOrFalse
		ArgumentNullException.ThrowIfNull(factIps);

		List<string> merged = new(attackIps.Count + factIps.Count);
		HashSet<string> seen = new(StringComparer.Ordinal);

		foreach (string raw in attackIps)
		{
			string? ip = IpNormalizer.Normalize(raw);
			if (ip is not null && seen.Add(ip))
			{
				merged.Add(ip);
			}
		}

		foreach (string raw in factIps)
		{
			string? ip = IpNormalizer.Normalize(raw);
			if (ip is not null && seen.Add(ip))
			{
				merged.Add(ip);
			}
		}

		return merged;
	}

	public override void Dispose()
	{
		_gate.Dispose();
		base.Dispose();
	}
}
