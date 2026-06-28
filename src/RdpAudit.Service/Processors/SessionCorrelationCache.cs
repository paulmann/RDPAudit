// File:    src/RdpAudit.Service/Processors/SessionCorrelationCache.cs
// Module:  RdpAudit.Service.Processors
// Purpose: Thread-safe, RAM-only in-process cache that remembers the IP that was observed for
//          a given LogonId / (SessionId, UserName) / UserName. Subsequent IP-less events
//          (logoff, disconnect, privilege-assignment) can be enriched at normalisation time
//          without touching the database.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System.Collections.Concurrent;
using System.Globalization;

namespace RdpAudit.Service.Processors;

/// <summary>
/// Three-index in-memory correlation cache. Lookups are O(1); writes happen exclusively on
/// direct-IP events; eviction is TTL-based and capacity-bounded. The cache lives for the lifetime
/// of the process and is never persisted to disk.
/// </summary>
public sealed class SessionCorrelationCache
{
	private static readonly TimeSpan DefaultTtl = TimeSpan.FromHours(24);
	private static readonly TimeSpan DefaultSweepInterval = TimeSpan.FromMinutes(5);
	private const int DefaultCapacity = 10_000;

	private readonly ConcurrentDictionary<string, Entry> _byLogonId;
	private readonly ConcurrentDictionary<string, Entry> _bySessionUser;
	private readonly ConcurrentDictionary<string, Entry> _byUser;
	private readonly TimeSpan _ttl;
	private readonly TimeSpan _sweepInterval;
	private readonly int _capacity;
	private readonly Func<DateTime> _utcNow;
	private DateTime _lastSweep;
	private readonly object _sweepGate = new();

	public SessionCorrelationCache()
		: this(DefaultCapacity, DefaultTtl, DefaultSweepInterval, () => DateTime.UtcNow)
	{
	}

	internal SessionCorrelationCache(int capacity, TimeSpan ttl, TimeSpan sweepInterval, Func<DateTime> utcNow)
	{
		_capacity = Math.Max(64, capacity);
		_ttl = ttl;
		_sweepInterval = sweepInterval;
		_utcNow = utcNow;
		_byLogonId = new ConcurrentDictionary<string, Entry>(StringComparer.OrdinalIgnoreCase);
		_bySessionUser = new ConcurrentDictionary<string, Entry>(StringComparer.OrdinalIgnoreCase);
		_byUser = new ConcurrentDictionary<string, Entry>(StringComparer.OrdinalIgnoreCase);
		_lastSweep = _utcNow();
	}

	/// <summary>
	/// Record an observed (key, IP) tuple. Any subset of LogonId / SessionId / UserName may be
	/// supplied; the corresponding indexes are populated independently. Null IP is silently
	/// ignored, as is a missing event timestamp.
	/// </summary>
	public void Seed(string? logonId, int? sessionId, string? userName, string ip, DateTime utc)
	{
		if (string.IsNullOrWhiteSpace(ip))
		{
			return;
		}

		Entry entry = new(ip, utc);
		if (!string.IsNullOrWhiteSpace(logonId))
		{
			_byLogonId[NormalizeLogonId(logonId!)] = entry;
		}

		if (sessionId is int sid && !string.IsNullOrWhiteSpace(userName))
		{
			_bySessionUser[SessionUserKey(sid, userName!)] = entry;
		}

		if (!string.IsNullOrWhiteSpace(userName))
		{
			_byUser[userName!.Trim()] = entry;
		}

		MaybeSweep();
		EnforceCapacityIfNeeded(_byLogonId);
		EnforceCapacityIfNeeded(_bySessionUser);
		EnforceCapacityIfNeeded(_byUser);
	}

	/// <summary>
	/// Resolve the most specific cached IP for the supplied tuple. Order: LogonId →
	/// (SessionId+UserName) → UserName. Entries past the TTL are skipped. The freshness reference
	/// is taken from the configured clock; pass an explicit timestamp via the
	/// <see cref="Lookup(string?, int?, string?, DateTime)"/> overload when the caller is driving
	/// the cache from an event-time stream (e.g. EventLog backfill) where wall-clock comparisons
	/// would falsely classify just-seeded entries as expired.
	/// </summary>
	public string? Lookup(string? logonId, int? sessionId, string? userName)
	{
		return Lookup(logonId, sessionId, userName, _utcNow());
	}

	/// <summary>
	/// Resolve the most specific cached IP for the supplied tuple, measuring TTL against an
	/// externally-supplied reference time. Order: LogonId → (SessionId+UserName) → UserName.
	/// Entries past the TTL relative to <paramref name="nowUtc"/> are skipped. This overload exists
	/// so the pipeline can use the current event's timestamp — TTL is a property of the event
	/// stream being processed, not of the wall clock; mixing the two means backfilled or
	/// replayed events would skip the cache entirely even when seed and lookup are seconds apart
	/// in event time.
	/// </summary>
	public string? Lookup(string? logonId, int? sessionId, string? userName, DateTime nowUtc)
	{
		if (TryReadFresh(_byLogonId, !string.IsNullOrWhiteSpace(logonId) ? NormalizeLogonId(logonId!) : null, nowUtc, out string? ip))
		{
			return ip;
		}

		string? suKey = sessionId is int sid && !string.IsNullOrWhiteSpace(userName)
			? SessionUserKey(sid, userName!)
			: null;
		if (TryReadFresh(_bySessionUser, suKey, nowUtc, out ip))
		{
			return ip;
		}

		string? uKey = !string.IsNullOrWhiteSpace(userName) ? userName!.Trim() : null;
		if (TryReadFresh(_byUser, uKey, nowUtc, out ip))
		{
			return ip;
		}

		return null;
	}

	/// <summary>Total entry count across all indexes. Intended for tests / metrics.</summary>
	internal int Count => _byLogonId.Count + _bySessionUser.Count + _byUser.Count;

	/// <summary>True once <see cref="HydrateFromAsync"/> has populated the cache (whether it loaded
	/// any rows or not). Used by the warmup worker to make hydration a one-shot operation per
	/// process.</summary>
	public bool IsHydrated { get; private set; }

	/// <summary>
	/// Seed the cache from persisted correlation rows. Caller must restrict the query to the
	/// retention window relevant to the active TTL — typically the last 24h. The method is async
	/// so the caller (a background warmup) can stream rows from EF without blocking startup.
	/// Subsequent calls update <see cref="IsHydrated"/> but never overwrite a fresher live
	/// observation already in the indexes.
	/// </summary>
	public async Task HydrateFromAsync(
		IAsyncEnumerable<HydrationRow> rows,
		CancellationToken ct)
	{
		await foreach (HydrationRow row in rows.WithCancellation(ct).ConfigureAwait(false))
		{
			if (string.IsNullOrWhiteSpace(row.Ip))
			{
				continue;
			}

			Entry incoming = new(row.Ip, row.LastSeenUtc);
			if (!string.IsNullOrWhiteSpace(row.LogonId))
			{
				string key = NormalizeLogonId(row.LogonId!);
				_byLogonId.AddOrUpdate(key, incoming, (_, existing) =>
					existing.ObservedUtc >= incoming.ObservedUtc ? existing : incoming);
			}

			if (row.WtsSessionId is int sid && !string.IsNullOrWhiteSpace(row.UserName))
			{
				string key = SessionUserKey(sid, row.UserName!);
				_bySessionUser.AddOrUpdate(key, incoming, (_, existing) =>
					existing.ObservedUtc >= incoming.ObservedUtc ? existing : incoming);
			}

			if (!string.IsNullOrWhiteSpace(row.UserName))
			{
				string key = row.UserName!.Trim();
				_byUser.AddOrUpdate(key, incoming, (_, existing) =>
					existing.ObservedUtc >= incoming.ObservedUtc ? existing : incoming);
			}
		}

		EnforceCapacityIfNeeded(_byLogonId);
		EnforceCapacityIfNeeded(_bySessionUser);
		EnforceCapacityIfNeeded(_byUser);
		IsHydrated = true;
	}

	/// <summary>One row of correlation data shaped for cache hydration.</summary>
	public readonly record struct HydrationRow(
		string? LogonId,
		int? WtsSessionId,
		string? UserName,
		string Ip,
		DateTime LastSeenUtc);

	private bool TryReadFresh(ConcurrentDictionary<string, Entry> map, string? key, DateTime now, out string? ip)
	{
		ip = null;
		if (key is null)
		{
			return false;
		}

		if (!map.TryGetValue(key, out Entry entry))
		{
			return false;
		}

		if (now - entry.ObservedUtc > _ttl)
		{
			map.TryRemove(key, out _);
			return false;
		}

		ip = entry.Ip;
		return true;
	}

	private void MaybeSweep()
	{
		DateTime now = _utcNow();
		if (now - _lastSweep < _sweepInterval)
		{
			return;
		}

		if (!System.Threading.Monitor.TryEnter(_sweepGate))
		{
			return;
		}

		try
		{
			if (now - _lastSweep < _sweepInterval)
			{
				return;
			}

			Sweep(_byLogonId, now);
			Sweep(_bySessionUser, now);
			Sweep(_byUser, now);
			_lastSweep = now;
		}
		finally
		{
			System.Threading.Monitor.Exit(_sweepGate);
		}
	}

	private void Sweep(ConcurrentDictionary<string, Entry> map, DateTime now)
	{
		foreach (KeyValuePair<string, Entry> kv in map)
		{
			if (now - kv.Value.ObservedUtc > _ttl)
			{
				map.TryRemove(kv.Key, out _);
			}
		}
	}

	private void EnforceCapacityIfNeeded(ConcurrentDictionary<string, Entry> map)
	{
		if (map.Count <= _capacity)
		{
			return;
		}

		// Drop the oldest 10% in one pass to amortise the cost; this is O(n) but only runs when
		// the index has already exceeded its high-water mark.
		int target = Math.Max(_capacity * 9 / 10, 1);
		List<KeyValuePair<string, Entry>> snapshot = new(map);
		snapshot.Sort(static (a, b) => a.Value.ObservedUtc.CompareTo(b.Value.ObservedUtc));
		int toDrop = snapshot.Count - target;
		for (int i = 0; i < toDrop; i++)
		{
			map.TryRemove(snapshot[i].Key, out _);
		}
	}

	private static string SessionUserKey(int sessionId, string userName)
	{
		return string.Create(
			CultureInfo.InvariantCulture,
			$"{sessionId}|{userName.Trim()}");
	}

	private static string NormalizeLogonId(string logonId)
	{
		string trimmed = logonId.Trim();
		// LogonId is sometimes "0x12345", sometimes "12345". Normalise to lower-case hex form
		// only when the source string is already hex; otherwise compare verbatim.
		return trimmed.StartsWith("0x", StringComparison.OrdinalIgnoreCase)
			? trimmed.ToLowerInvariant()
			: trimmed;
	}

	private readonly struct Entry
	{
		public Entry(string ip, DateTime observedUtc)
		{
			Ip = ip;
			ObservedUtc = observedUtc;
		}

		public string Ip { get; }

		public DateTime ObservedUtc { get; }
	}
}
