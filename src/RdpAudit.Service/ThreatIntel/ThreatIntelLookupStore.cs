// File:    src/RdpAudit.Service/ThreatIntel/ThreatIntelLookupStore.cs
// Module:  RdpAudit.Service.ThreatIntel
// Purpose: EF Core-backed store for the Backlog #5 threat-intel cache (ThreatIntelLookups) and the
//          persisted daily usage counter (ThreatIntelUsageCounters). The IPC request path reads
//          ONLY fresh cache rows through GetFreshSnapshotAsync - HTTP is never performed there.
//          The background enrichment worker writes rows via UpsertAsync and increments the daily
//          budget via IncrementDailyCountAsync. All freshness decisions are fail-closed: stale,
//          missing or non-Success rows are reported as null so callers can never mark High-risk
//          from unusable provider data.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System.Globalization;
using Microsoft.EntityFrameworkCore;
using RdpAudit.Core.Data;
using RdpAudit.Core.Models;
using RdpAudit.Core.ThreatIntel;

namespace RdpAudit.Service.ThreatIntel;

/// <summary>EF Core-backed store for the threat-intel cache and daily usage counter.</summary>
public sealed class ThreatIntelLookupStore
{
	private readonly IDbContextFactory<AuditDbContext> _factory;
	private readonly TimeProvider _time;

	public ThreatIntelLookupStore(IDbContextFactory<AuditDbContext> factory, TimeProvider time)
	{
		ArgumentNullException.ThrowIfNull(factory);
		ArgumentNullException.ThrowIfNull(time);
		_factory = factory;
		_time = time;
	}

	/// <summary>Reads the raw cache row for one IP. Cache-only: never touches Http clients.</summary>
	public async Task<ThreatIntelLookup?> GetAsync(string ip, CancellationToken ct = default)
	{
		await using AuditDbContext db = await _factory.CreateDbContextAsync(ct).ConfigureAwait(false);
		return await db.ThreatIntelLookups.AsNoTracking()
			.FirstOrDefaultAsync(r => r.Ip == ip, ct)
			.ConfigureAwait(false);
	}

	/// <summary>Reads a FRESH row for one IP: the row must exist, its outcome must be Success and
	/// its snapshot age must be within the configured freshness window. Any other state is reported
	/// as null (fail-closed), so a stale / rejected / rate-limited row can never manufacture a
	/// High-risk mark.</summary>
	/// <param name="ip">Normalized IP literal.</param>
	/// <param name="maxAgeInDays">Freshness window; clamped via ThreatIntelLimits.</param>
	public async Task<ThreatIntelLookup?> GetFreshSnapshotAsync(string ip, int maxAgeInDays, CancellationToken ct = default)
	{
		ThreatIntelLookup? row = await GetAsync(ip, ct).ConfigureAwait(false);
		if (row is null || row.Outcome != (int)ThreatIntelLookupOutcome.Success)
		{
			return null;
		}

		DateTime cutoff = _time.GetUtcNow().UtcDateTime.AddDays(-ThreatIntelLimits.ClampMaxAgeInDays(maxAgeInDays));
		if (row.LookedUpUtc < cutoff)
		{
			return null;
		}

		return row;
	}

	/// <summary>Reads, in ONE batch, all fresh Success cache rows for the supplied IP literals.
	/// Non-Success, stale and missing rows are omitted (fail-closed). Cache-only: never touches HTTP
	/// clients. Used by the IPC stamping pass so a response page costs a single cache query.</summary>
	/// <param name="ips">Distinct IP literals to resolve.</param>
	/// <param name="maxAgeInDays">Freshness window; clamped via ThreatIntelLimits.</param>
	public async Task<Dictionary<string, ThreatIntelLookup>> GetFreshSnapshotMapAsync(
		IEnumerable<string> ips,
		int maxAgeInDays,
		CancellationToken ct = default)
	{
		ArgumentNullException.ThrowIfNull(ips);

		HashSet<string> set = new(ips, StringComparer.OrdinalIgnoreCase);
		if (set.Count == 0)
		{
			return new Dictionary<string, ThreatIntelLookup>(StringComparer.OrdinalIgnoreCase);
		}

		int age = ThreatIntelLimits.ClampMaxAgeInDays(maxAgeInDays);
		DateTime cutoff = _time.GetUtcNow().UtcDateTime.AddDays(-age);

		await using AuditDbContext db = await _factory.CreateDbContextAsync(ct).ConfigureAwait(false);
		List<ThreatIntelLookup> rows = await db.ThreatIntelLookups.AsNoTracking()
			.Where(r => r.Outcome == (int)ThreatIntelLookupOutcome.Success
				&& r.LookedUpUtc >= cutoff
				&& set.Contains(r.Ip))
			.ToListAsync(ct)
			.ConfigureAwait(false);

		Dictionary<string, ThreatIntelLookup> result = new(StringComparer.OrdinalIgnoreCase);
		foreach (ThreatIntelLookup row in rows)
		{
			result[row.Ip] = row;
		}

		return result;
	}

	/// <summary>Upserts the cache row for one lookup result. Success results carry the reputation
	/// fields; every other outcome only records the failure (fail-closed: no stale success fields
	/// remain). A 429 result arms <c>NextRetryUtc</c> from its Retry-After hint so the enrichment
	/// worker can honour the provider back-off; every other outcome clears it.</summary>
	/// <param name="result">Classified lookup result to persist.</param>
	/// <param name="nowUtc">Optional clock override for tests; defaults to the store's TimeProvider.</param>
	public async Task UpsertAsync(ThreatIntelLookupResult result, DateTime? nowUtc = null, CancellationToken ct = default)
	{
		ArgumentNullException.ThrowIfNull(result);

		DateTime now = nowUtc ?? _time.GetUtcNow().UtcDateTime;
		bool success = result.Outcome == ThreatIntelLookupOutcome.Success;

		await using AuditDbContext db = await _factory.CreateDbContextAsync(ct).ConfigureAwait(false);
		ThreatIntelLookup? row = await db.ThreatIntelLookups
			.FirstOrDefaultAsync(r => r.Ip == result.Ip, ct)
			.ConfigureAwait(false);

		if (row is null)
		{
			row = new ThreatIntelLookup { Ip = result.Ip };
			db.ThreatIntelLookups.Add(row);
		}

		row.LookedUpUtc = now;
		row.Outcome = (int)result.Outcome;
		row.Score = success ? result.AbuseConfidenceScore : null;
		row.TotalReports = success ? result.TotalReports : null;
		row.IsWhitelisted = success ? result.IsWhitelisted : null;
		row.IsPublic = success ? result.IsPublic : null;
		row.UsageType = success ? result.UsageType : null;
		row.CountryCode = success ? result.CountryCode : null;
		row.NextRetryUtc = result.Outcome == ThreatIntelLookupOutcome.RateLimited
			? now.Add(result.RetryAfter ?? TimeSpan.FromMinutes(5))
			: null;

		try
		{
			await db.SaveChangesAsync(ct).ConfigureAwait(false);
		}
		catch (DbUpdateException)
		{
			// Lost a race against a concurrent upsert of the same IP: the peer's row wins. The cache
			// is eventually consistent, so swallowing the duplicate-key conflict is safe here.
		}
	}

	/// <summary>Reads the persisted number of lookups performed on the given UTC day key.</summary>
	public async Task<int> GetDailyCountAsync(string dayKey, CancellationToken ct = default)
	{
		await using AuditDbContext db = await _factory.CreateDbContextAsync(ct).ConfigureAwait(false);
		ThreatIntelUsageCounter? row = await db.ThreatIntelUsageCounters.AsNoTracking()
			.FirstOrDefaultAsync(c => c.DayDateUtc == dayKey, ct)
			.ConfigureAwait(false);
		return row?.Count ?? 0;
	}

	/// <summary>Returns the UTC day key (yyyy-MM-dd) for the store's clock. Shared with the persisted
	/// daily-counter rows so callers always key on the same value.</summary>
	public string TodayKey()
	{
		return _time.GetUtcNow().UtcDateTime.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture);
	}

	/// <summary>Cache-only summary for the GetThreatIntelStatus IPC handler: row counts by outcome,
	/// fresh-Success count within the freshness window, plus the persisted daily usage figure.
	/// Never touches HTTP clients and never returns provider payloads.</summary>
	/// <param name="dayKey">UTC day key (yyyy-MM-dd) whose usage counter to read.</param>
	/// <param name="maxAgeInDays">Freshness window; clamped via ThreatIntelLimits.</param>
	public async Task<(int TotalRows, int SuccessRows, int FreshSuccessRows, List<(int Outcome, int Count)> OutcomeCounts, int DailyUsage)> GetStatusCountsAsync(
		string dayKey,
		int maxAgeInDays,
		CancellationToken ct = default)
	{
		await using AuditDbContext db = await _factory.CreateDbContextAsync(ct).ConfigureAwait(false);

		List<ThreatIntelLookup> rows = await db.ThreatIntelLookups.AsNoTracking()
			.Select(r => new ThreatIntelLookup { Ip = r.Ip, Outcome = r.Outcome, LookedUpUtc = r.LookedUpUtc })
			.ToListAsync(ct)
			.ConfigureAwait(false);

		int successRows = 0;
		int freshSuccessRows = 0;
		DateTime cutoff = _time.GetUtcNow().UtcDateTime.AddDays(-ThreatIntelLimits.ClampMaxAgeInDays(maxAgeInDays));
		Dictionary<int, int> byOutcome = new();
		foreach (ThreatIntelLookup row in rows)
		{
			byOutcome.TryGetValue(row.Outcome, out int count);
			byOutcome[row.Outcome] = count + 1;
			if (row.Outcome == (int)ThreatIntelLookupOutcome.Success)
			{
				successRows++;
				if (row.LookedUpUtc >= cutoff)
				{
					freshSuccessRows++;
				}
			}
		}

		List<(int Outcome, int Count)> outcomeCounts = byOutcome
			.OrderBy(kv => kv.Key)
			.Select(kv => (kv.Key, kv.Value))
			.ToList();

		int dailyUsage = await GetDailyCountAsync(dayKey, ct).ConfigureAwait(false);
		return (rows.Count, successRows, freshSuccessRows, outcomeCounts, dailyUsage);
	}

	/// <summary>Increments the persisted daily counter for the given UTC day key by one,
	/// creating the row when the day has not been seen before.</summary>
	public async Task IncrementDailyCountAsync(string dayKey, CancellationToken ct = default)
	{
		await using AuditDbContext db = await _factory.CreateDbContextAsync(ct).ConfigureAwait(false);
		ThreatIntelUsageCounter? row = await db.ThreatIntelUsageCounters
			.FirstOrDefaultAsync(c => c.DayDateUtc == dayKey, ct)
			.ConfigureAwait(false);

		if (row is null)
		{
			db.ThreatIntelUsageCounters.Add(new ThreatIntelUsageCounter { DayDateUtc = dayKey, Count = 1 });
		}
		else
		{
			row.Count++;
		}

		try
		{
			await db.SaveChangesAsync(ct).ConfigureAwait(false);
		}
		catch (DbUpdateException)
		{
			// Race on the same calendar day: a concurrent writer already counted the lookup.
			// The daily budget is a defensive cap, not an accounting ledger, so this is harmless.
		}
	}

	/// <summary>Converts a persisted cache row into the provider-agnostic lookup result used by the
	/// classifier. Non-Success rows yield <c>null</c> so the IPC path never fabricates a
	/// <see cref="ThreatIntelLookupOutcome.Success"/> from a failed attempt.</summary>
	public static ThreatIntelLookupResult? ToLookupResult(ThreatIntelLookup? row)
	{
		if (row is null || row.Outcome != (int)ThreatIntelLookupOutcome.Success)
		{
			return null;
		}

		return new ThreatIntelLookupResult
		{
			Outcome = ThreatIntelLookupOutcome.Success,
			Ip = row.Ip,
			ResponseCode = 200,
			AbuseConfidenceScore = row.Score,
			TotalReports = row.TotalReports,
			IsWhitelisted = row.IsWhitelisted,
			IsPublic = row.IsPublic,
			UsageType = row.UsageType,
			CountryCode = row.CountryCode,
			Message = "Cached reputation snapshot.",
		};
	}
}
