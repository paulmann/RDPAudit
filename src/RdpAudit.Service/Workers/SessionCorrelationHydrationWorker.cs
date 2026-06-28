// File:    src/RdpAudit.Service/Workers/SessionCorrelationHydrationWorker.cs
// Module:  RdpAudit.Service.Workers
// Purpose: One-shot startup warmup that seeds the in-memory SessionCorrelationCache from the
//          durable SessionIpCorrelations table. Runs off the hot path: a small initial delay
//          ensures other workers initialise first; an EF AsAsyncEnumerable stream keeps memory
//          bounded. The TTL window mirrors the cache's TTL (24h) so we never seed entries that
//          would be expired on first read.
// Extends: Microsoft.Extensions.Hosting.BackgroundService
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using RdpAudit.Core.Data;
using RdpAudit.Service.Processors;

namespace RdpAudit.Service.Workers;

/// <summary>Background warmup that hydrates <see cref="SessionCorrelationCache"/> from
/// <c>SessionIpCorrelations</c> once per process. Always non-blocking with respect to the event
/// hot path; cancellation is honoured immediately.</summary>
public sealed class SessionCorrelationHydrationWorker : BackgroundService
{
	/// <summary>Lookback window for hydration. Matches the cache's TTL so the seed never produces
	/// entries that would be expired on the first read.</summary>
	internal static readonly TimeSpan HydrationLookback = TimeSpan.FromHours(24);

	/// <summary>Hard cap on rows pulled in one hydration pass. The cache itself enforces capacity
	/// per index; this just bounds the EF round trip.</summary>
	internal const int HydrationRowCap = 20_000;

	private static readonly TimeSpan InitialDelay = TimeSpan.FromSeconds(5);

	private readonly IDbContextFactory<AuditDbContext> _factory;
	private readonly SessionCorrelationCache _cache;
	private readonly ILogger<SessionCorrelationHydrationWorker> _logger;

	public SessionCorrelationHydrationWorker(
		IDbContextFactory<AuditDbContext> factory,
		SessionCorrelationCache cache,
		ILogger<SessionCorrelationHydrationWorker> logger)
	{
		_factory = factory;
		_cache = cache;
		_logger = logger;
	}

	protected override async Task ExecuteAsync(CancellationToken stoppingToken)
	{
		try
		{
			await Task.Delay(InitialDelay, stoppingToken).ConfigureAwait(false);
			await HydrateOnceAsync(stoppingToken).ConfigureAwait(false);
		}
		catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
		{
		}
		catch (Exception ex)
		{
			_logger.LogWarning(ex, "SessionCorrelationCache hydration failed — service continues with empty cache");
		}
	}

	/// <summary>Exposed for tests. Runs a single hydration pass against the supplied context
	/// factory and seeds the cache.</summary>
	internal async Task HydrateOnceAsync(CancellationToken ct)
	{
		if (_cache.IsHydrated)
		{
			return;
		}

		DateTime cutoff = DateTime.UtcNow - HydrationLookback;
		await using AuditDbContext db = await _factory.CreateDbContextAsync(ct).ConfigureAwait(false);

		IAsyncEnumerable<SessionCorrelationCache.HydrationRow> stream = db.SessionIpCorrelations
			.AsNoTracking()
			.Where(r => r.LastSeenUtc >= cutoff)
			.OrderByDescending(r => r.LastSeenUtc)
			.Take(HydrationRowCap)
			.Select(r => new SessionCorrelationCache.HydrationRow(
				r.LogonId,
				r.WtsSessionId,
				r.UserName,
				r.Ip,
				r.LastSeenUtc))
			.AsAsyncEnumerable();

		await _cache.HydrateFromAsync(stream, ct).ConfigureAwait(false);
		_logger.LogInformation("SessionCorrelationCache hydration complete (entries={Count})", _cache.Count);
	}
}
