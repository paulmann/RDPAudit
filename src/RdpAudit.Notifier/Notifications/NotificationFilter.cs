// File:    src/RdpAudit.Notifier/Notifications/NotificationFilter.cs
// Module:  RdpAudit.Notifier.Notifications
// Purpose: Pure decision logic for the polling loop: keeps only alerts worth a toast (severity,
//          per-rule visibility) that have not been shown yet (deduplication by alert id).
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using RdpAudit.Core.Models;

namespace RdpAudit.Notifier.Notifications;

/// <summary>Filters and deduplicates alerts for the tray notifier.</summary>
public sealed class NotificationFilter
{
	private readonly HashSet<long> _shownAlertIds = [];
	private readonly object _gate = new();

	/// <summary>Returns alerts that should produce a toast, in newest-first order.
	/// Already-shown alerts are skipped; skipped alerts are marked as shown so they are
	/// never re-shown even if the list is fetched again.</summary>
	public List<Alert> SelectNew(List<Alert> alerts, NotificationPolicy policy)
	{
		if (!policy.Enabled || alerts.Count == 0)
		{
			return [];
		}

		List<Alert> selected = [];
		lock (_gate)
		{
			foreach (Alert alert in alerts.OrderByDescending(a => a.Id))
			{
				if (!_shownAlertIds.Add(alert.Id))
				{
					continue;
				}

				if (!IsVisible(alert, policy))
				{
					continue;
				}

				selected.Add(alert);
			}
		}

		return selected;
	}

	/// <summary>Resets the deduplication memory (used on settings reload / re-enable).</summary>
	public void Reset()
	{
		lock (_gate)
		{
			_shownAlertIds.Clear();
		}
	}

	private static bool IsVisible(Alert alert, NotificationPolicy policy)
	{
		if (alert.Severity < policy.MinimumSeverity)
		{
			return false;
		}

		if (policy.ShowAlerts.TryGetValue(alert.RuleId, out bool visible) && !visible)
		{
			return false;
		}

		return true;
	}
}
