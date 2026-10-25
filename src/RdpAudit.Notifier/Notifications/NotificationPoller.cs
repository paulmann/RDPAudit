// File:    src/RdpAudit.Notifier/Notifications/NotificationPoller.cs
// Module:  RdpAudit.Notifier.Notifications
// Purpose: Polling coordinator for the tray notifier. Each tick: fetch settings, resolve the
//          policy, fetch recent alerts, select new visible alerts subject to the per-minute
//          toast budget, then render them via the sink. Poll failures degrade silently:
//          settings keep the previous policy and alerts are simply not delivered this tick.
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using RdpAudit.Core.Ipc.Contracts;
using RdpAudit.Core.Models;
using RdpAudit.Notifier.Ipc;

namespace RdpAudit.Notifier.Notifications;

/// <summary>Coordinates settings refresh, alert filtering and toast delivery.</summary>
public sealed class NotificationPoller
{
	private readonly IAlertSource _source;
	private readonly INotificationSink _sink;
	private readonly NotificationFilter _filter;
	private readonly TimeProvider _timeProvider;
	private NotificationPolicy _policy = NotificationPolicy.Defaults();
	private ToastBudget? _budget;

	/// <summary>The currently effective poll interval in seconds (clamped to 1..60).
	/// Read by the tray loop to pace the next delay.</summary>
	public int CurrentPollIntervalSeconds => _policy.PollIntervalSeconds;

	/// <summary>True when the last tick received settings from the service;
	/// false when the service was unreachable (null settings).</summary>
	public bool LastTickSucceeded { get; private set; }

	public NotificationPoller(IAlertSource source, INotificationSink sink, TimeProvider? timeProvider = null)
	{
		_source = source;
		_sink = sink;
		_filter = new NotificationFilter();
		_timeProvider = timeProvider ?? TimeProvider.System;
		_budget = new ToastBudget(_timeProvider, _policy.MaximumToastsPerMinute);
	}

	/// <summary>Runs one poll of settings and alerts, rendering due notifications.</summary>
	public async Task TickAsync(CancellationToken ct)
	{
		NotificationSettingsDto? dto = await _source.FetchSettingsAsync(ct).ConfigureAwait(false);
		LastTickSucceeded = dto is not null;
		if (dto is not null)
		{
			NotificationPolicy next = NotificationPolicy.From(dto);
			if (next.MaximumToastsPerMinute != _policy.MaximumToastsPerMinute)
			{
				_budget = new ToastBudget(_timeProvider, next.MaximumToastsPerMinute);
			}

			_policy = next;
			_sink.PreferNativeToasts = next.UseNativeToasts;
		}

		if (!_policy.Enabled)
		{
			return;
		}

		List<Alert>? alerts = await _source.FetchRecentAlertsAsync(ct).ConfigureAwait(false);
		if (alerts is null)
		{
			return;
		}

		List<Alert> selected = _filter.SelectNew(alerts, _policy);
		if (selected.Count == 0)
		{
			return;
		}

		ToastBudget budget = _budget!;
		int firstThrottled = -1;
		for (int i = 0; i < selected.Count; i++)
		{
			if (!budget.TryAdmit())
			{
				firstThrottled = i;
				break;
			}

			_sink.Show(selected[i]);
		}

		if (firstThrottled >= 0)
		{
			int throttled = selected.Count - firstThrottled;
			_sink.ShowAggregate(throttled);
		}
	}
}
