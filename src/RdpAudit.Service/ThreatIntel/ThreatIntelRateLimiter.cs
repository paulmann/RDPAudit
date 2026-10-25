// File:    src/RdpAudit.Service/ThreatIntel/ThreatIntelRateLimiter.cs
// Module:  RdpAudit.Service.ThreatIntel
// Purpose: Concurrency-safe fixed-window rate limiter for the Backlog #5 /api/v2/check lookups.
//          Two independent gates, both consultable without a database round-trip:
//          (1) a per-minute fixed window of N calls and (2) a per-day budget that is persisted in
//          the ThreatIntelUsageCounters table. Time comes exclusively from an injectable
//          TimeProvider so tests can move the clock; all mutable state is guarded by a lock.
//          Never throws for configuration problems - out-of-range values are clamped.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using RdpAudit.Core.Config;
using RdpAudit.Core.ThreatIntel;

namespace RdpAudit.Service.ThreatIntel;

/// <summary>Concurrency-safe fixed-window rate limiter for threat-intel lookups.</summary>
public sealed class ThreatIntelRateLimiter
{
	private readonly object _gate = new();
	private readonly TimeProvider _time;

	private int _windowStartMinute;
	private int _lookupsInWindow;

	/// <summary>Creates the limiter bound to the supplied clock.</summary>
	public ThreatIntelRateLimiter(TimeProvider time)
	{
		ArgumentNullException.ThrowIfNull(time);
		_time = time;
	}

	/// <summary>Tests whether <b>one more</b> lookup may start now given the per-minute cap and the
	/// persisted daily budget. Pure read - does not consume anything. When false, the next lookup
	/// must be skipped for this cycle.</summary>
	/// <param name="options">Current AbuseIPDB configuration; caps are clamped to the canonical
	/// ThreatIntelLimits bands.</param>
	/// <param name="dailyCount">Number of lookups already performed today (from the store).</param>
	public bool CanLookup(AbuseIpDbOptions options, int dailyCount)
	{
		ArgumentNullException.ThrowIfNull(options);

		int perMinute = ThreatIntelLimits.ClampLookupsPerMinute(options.CheckMaxLookupsPerMinute);
		int perDay = ThreatIntelLimits.ClampLookupsPerDay(options.CheckMaxLookupsPerDay);
		if (dailyCount < 0)
		{
			// Defensive: a negative counter is treated as an exhausted budget rather than a free pass.
			dailyCount = perDay;
		}

		lock (_gate)
		{
			DateTimeOffset now = _time.GetUtcNow();
			int currentMinute = (int)(now.ToUnixTimeSeconds() / 60);
			if (currentMinute != _windowStartMinute)
			{
				_windowStartMinute = currentMinute;
				_lookupsInWindow = 0;
			}

			return _lookupsInWindow < perMinute && dailyCount < perDay;
		}
	}

	/// <summary>Consumes one lookup slot for the per-minute window. Must be called only after
	/// <see cref="CanLookup"/> returned true. The daily counter is persisted separately by the
	/// caller through <c>ThreatIntelLookupStore.IncrementDailyCountAsync</c>.</summary>
	public void RecordLookup()
	{
		lock (_gate)
		{
			DateTimeOffset now = _time.GetUtcNow();
			int currentMinute = (int)(now.ToUnixTimeSeconds() / 60);
			if (currentMinute != _windowStartMinute)
			{
				_windowStartMinute = currentMinute;
				_lookupsInWindow = 0;
			}

			_lookupsInWindow++;
		}
	}

	/// <summary>Returns the UTC day key (yyyy-MM-dd) for the clock's current date. Shared with the
	/// daily-counter helper so the limiter and the persisted counter always key on the same value.</summary>
	public string TodayKey()
	{
		return _time.GetUtcNow().UtcDateTime.ToString("yyyy-MM-dd", System.Globalization.CultureInfo.InvariantCulture);
	}
}
