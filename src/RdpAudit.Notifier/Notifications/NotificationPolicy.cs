// File:    src/RdpAudit.Notifier/Notifications/NotificationPolicy.cs
// Module:  RdpAudit.Notifier.Notifications
// Purpose: Effective notification policy resolved from the service-provided DTO (IPC 78), with the
//          same clamping and severity fallback the service applies when saving. The polling loop
//          keeps the latest policy and falls back to safe defaults when the service is unreachable.
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using RdpAudit.Core.Config;
using RdpAudit.Core.Ipc.Contracts;
using RdpAudit.Core.Models;

namespace RdpAudit.Notifier.Notifications;

/// <summary>Effective notification policy resolved from the service DTO.</summary>
public sealed record NotificationPolicy
{
	/// <summary>Master switch for the tray notifier.</summary>
	public bool Enabled { get; init; } = true;

	/// <summary>Clamped poll interval in seconds.</summary>
	public int PollIntervalSeconds { get; init; } = 5;

	/// <summary>Prefer native WinRT toasts over balloon tips.</summary>
	public bool UseNativeToasts { get; init; }

	/// <summary>Minimum alert severity that produces a toast.</summary>
	public AlertSeverity MinimumSeverity { get; init; } = AlertSeverity.High;

	/// <summary>Maximum toasts per minute before surplus collapses into an aggregate.</summary>
	public int MaximumToastsPerMinute { get; init; } = 10;

	/// <summary>Per-rule visibility; absent key means shown (subject to severity).</summary>
	public Dictionary<string, bool> ShowAlerts { get; init; } = new(StringComparer.OrdinalIgnoreCase);

	/// <summary>Resolves a policy from the service DTO applying server-side clamps locally.</summary>
	public static NotificationPolicy From(NotificationSettingsDto dto)
	{
		AlertSeverity severity = Enum.TryParse(dto.MinimumSeverity, ignoreCase: true, out AlertSeverity parsed)
			? parsed
			: AlertSeverity.High;

		return new NotificationPolicy
		{
			Enabled = dto.EnableTrayNotifier,
			PollIntervalSeconds = Math.Clamp(dto.PollIntervalSeconds, NotificationOptions.MinPollIntervalSeconds, NotificationOptions.MaxPollIntervalSeconds),
			MinimumSeverity = severity,
			MaximumToastsPerMinute = Math.Clamp(dto.MaxToastsPerMinute, NotificationOptions.MinMaxToastsPerMinute, NotificationOptions.MaxMaxToastsPerMinute),
			UseNativeToasts = dto.UseNativeToasts,
			ShowAlerts = dto.ShowAlerts ?? new Dictionary<string, bool>(StringComparer.OrdinalIgnoreCase),
		};
	}

	/// <summary>Safe defaults used before the first successful settings fetch.</summary>
	public static NotificationPolicy Defaults() => new();
}
