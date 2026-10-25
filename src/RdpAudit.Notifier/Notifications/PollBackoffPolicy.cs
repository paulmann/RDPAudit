// File:    src/RdpAudit.Notifier/Notifications/PollBackoffPolicy.cs
// Module:  RdpAudit.Notifier.Notifications
// Purpose: Pure backoff policy for the tray poll loop: a healthy tick resets the delay to the
//          (clamped) configured poll interval, consecutive failures double the delay up to
//          MaxBackoffSeconds. Clock-free by design so the curve is unit-testable.
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using RdpAudit.Core.Config;

namespace RdpAudit.Notifier.Notifications;

/// <summary>Backoff policy for the tray poll delay.</summary>
public sealed class PollBackoffPolicy
{
	/// <summary>Upper bound of the degraded retry delay (seconds).</summary>
	public const int MaxBackoffSeconds = NotificationOptions.MaxPollIntervalSeconds;

	private int _healthyIntervalSeconds;

	public PollBackoffPolicy(int healthyIntervalSeconds)
	{
		_healthyIntervalSeconds = Clamp(healthyIntervalSeconds);
		CurrentDelaySeconds = _healthyIntervalSeconds;
	}

	/// <summary>Current delay the loop waits before the next poll (seconds, 1..60).</summary>
	public int CurrentDelaySeconds { get; private set; }

	/// <summary>Records a healthy tick: the delay resets to the (clamped) poll interval.</summary>
	public void OnHealthy(int healthyIntervalSeconds)
	{
		_healthyIntervalSeconds = Clamp(healthyIntervalSeconds);
		CurrentDelaySeconds = _healthyIntervalSeconds;
	}

	/// <summary>Records a failed tick: the delay doubles up to MaxBackoffSeconds.</summary>
	public void OnUnhealthy()
		=> CurrentDelaySeconds = Math.Min(CurrentDelaySeconds * 2, MaxBackoffSeconds);

	private static int Clamp(int seconds)
		=> Math.Clamp(seconds, NotificationOptions.MinPollIntervalSeconds, MaxBackoffSeconds);
}
