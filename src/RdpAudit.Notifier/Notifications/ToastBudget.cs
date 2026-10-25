// File:    src/RdpAudit.Notifier/Notifications/ToastBudget.cs
// Module:  RdpAudit.Notifier.Notifications
// Purpose: Enforces the per-minute toast cap. A toast is admitted only while fewer than
//          MaximumToastsPerMinute admissions happened in the trailing 60-second window.
//          Surplus callers learn they were throttled so the loop can show one aggregate.
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

namespace RdpAudit.Notifier.Notifications;

/// <summary>Sliding-window rate limiter for toast admissions.</summary>
public sealed class ToastBudget
{
	private readonly TimeProvider _timeProvider;
	private readonly Queue<DateTime> _admissions = new();
	private readonly object _gate = new();

	public ToastBudget(TimeProvider? timeProvider = null, int maximumToastsPerMinute = 10)
	{
		_timeProvider = timeProvider ?? TimeProvider.System;
		MaximumToastsPerMinute = Math.Max(1, maximumToastsPerMinute);
	}

	public int MaximumToastsPerMinute { get; }

	/// <summary>Attempts to admit one toast. When the window is full the toast is
	/// throttled (returns false); the caller tracks the suppressed count.</summary>
	public bool TryAdmit()
	{
		lock (_gate)
		{
			DateTime now = _timeProvider.GetUtcNow().UtcDateTime;
			while (_admissions.Count > 0 && now - _admissions.Peek() >= TimeSpan.FromMinutes(1))
			{
				_admissions.Dequeue();
			}

			if (_admissions.Count >= MaximumToastsPerMinute)
			{
				return false;
			}

			_admissions.Enqueue(now);
			return true;
		}
	}
}
