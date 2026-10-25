// File:    src/RdpAudit.Service/Alerts/AlertCooldownTracker.cs
// Module:  RdpAudit.Service.Alerts
// Purpose: De-duplication / cooldown helper. Threshold-based brute-force / Kerberos / NTLM rules
//          can fire one alert per offending event after the threshold; this tracker suppresses
//          subsequent events with the same (RuleId, Key) tuple within a per-rule cooldown window.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System.Collections.Concurrent;
using System.Globalization;

namespace RdpAudit.Service.Alerts;

/// <summary>De-duplication / cooldown helper for alert rules.</summary>
public sealed class AlertCooldownTracker
{
	/// <summary>Entries are pruned only once the map grows past this size, so the common case
	/// pays nothing for the bound while the map can never grow without limit.</summary>
	private const int PruneThreshold = 4096;

	/// <summary>An entry untouched for this long cannot suppress anything (cooldowns are minutes),
	/// so it is dead weight once the map passes <see cref="PruneThreshold"/>.</summary>
	private static readonly TimeSpan RetainAfterFire = TimeSpan.FromHours(24);

	/// <summary>Minimum gap between prune scans, so a flood that keeps the map above the threshold
	/// does not pay an O(n) scan on every single alert.</summary>
	private const long PruneIntervalTicks = TimeSpan.TicksPerMinute;

	private readonly ConcurrentDictionary<string, DateTime> _lastFire = new(StringComparer.Ordinal);

	/// <summary>UTC ticks of the last completed prune scan; 0 until the first scan.</summary>
	private long _lastPruneTicks;

	/// <summary>Returns true if an alert may fire; updates last-fire time when allowed.</summary>
	public bool TryRegister(string ruleId, string key, TimeSpan cooldown)
	{
		ArgumentException.ThrowIfNullOrWhiteSpace(ruleId);
		ArgumentException.ThrowIfNullOrWhiteSpace(key);

		string composite = string.Format(CultureInfo.InvariantCulture, "{0}|{1}", ruleId, key);
		DateTime now = DateTime.UtcNow;

		while (true)
		{
			if (_lastFire.TryGetValue(composite, out DateTime previous))
			{
				if (now - previous < cooldown)
				{
					return false;
				}

				if (_lastFire.TryUpdate(composite, now, previous))
				{
					PruneIfOversized(now);
					return true;
				}
			}
			else if (_lastFire.TryAdd(composite, now))
			{
				PruneIfOversized(now);
				return true;
			}
		}
	}

	/// <summary>Drops entries that can no longer suppress an alert. Bounded by construction: the
	/// tracker used to grow monotonically for the lifetime of the service (one entry per distinct
	/// rule+key ever seen), which is unbounded memory growth on a long-lived host.</summary>
	private void PruneIfOversized(DateTime now)
	{
		if (_lastFire.Count < PruneThreshold)
		{
			return;
		}

		long nowTicks = now.Ticks;
		long lastTicks = System.Threading.Interlocked.Read(ref _lastPruneTicks);
		if (nowTicks - lastTicks < PruneIntervalTicks
			|| System.Threading.Interlocked.CompareExchange(ref _lastPruneTicks, nowTicks, lastTicks) != lastTicks)
		{
			return;
		}

		DateTime cutoff = now - RetainAfterFire;
		foreach (KeyValuePair<string, DateTime> entry in _lastFire)
		{
			if (entry.Value >= cutoff)
			{
				continue;
			}

			// Re-read immediately before removing so a key that a concurrent TryRegister refreshed
			// between the enumeration and the removal is not dropped (which would allow one extra
			// alert through).
			if (_lastFire.TryGetValue(entry.Key, out DateTime current) && current == entry.Value)
			{
				_lastFire.TryRemove(entry.Key, out _);
			}
		}
	}
}
