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
	private readonly ConcurrentDictionary<string, DateTime> _lastFire = new(StringComparer.Ordinal);

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
					return true;
				}
			}
			else if (_lastFire.TryAdd(composite, now))
			{
				return true;
			}
		}
	}
}
