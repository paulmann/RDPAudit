// File:    src/RdpAudit.Core/Config/NotificationOptions.cs
// Module:  RdpAudit.Core.Config
// Purpose: Toast notification configuration bound from appsettings.json.
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using RdpAudit.Core.Models;

namespace RdpAudit.Core.Config;

/// <summary>Configuration for toast notifications delivered by the tray notifier.</summary>
public sealed class NotificationOptions
{
	/// <summary>Master switch. Default true.</summary>
	public bool EnableTrayNotifier { get; set; } = true;

	/// <summary>Register a LogonTrigger scheduled task. Default true.</summary>
	public bool StartWithWindows { get; set; } = true;

	/// <summary>Poll interval seconds, clamped 1..60. Default 5.</summary>
	public int PollIntervalSeconds { get; set; } = 5;

	/// <summary>Minimum alert severity for a toast. Default High.</summary>
	public string MinimumSeverity { get; set; } = "High";

	/// <summary>Maximum toasts shown per minute before surplus items collapse into one
	/// aggregate toast. Clamped to 1..60; default 10.</summary>
	public int MaxToastsPerMinute { get; set; } = 10;

	/// <summary>Phase-2 flag: when true and the platform supports it, render native WinRT
	/// toasts instead of balloon tips. Default false (balloon MVP).</summary>
	public bool UseNativeToasts { get; set; }

	/// <summary>Per-rule visibility map keyed by the stable SCREAMING_SNAKE_CASE
	/// rule id. Absent key means the rule is shown by default (MinimumSeverity applies).
	/// Value false hides the rule.</summary>
	public Dictionary<string, bool> ShowAlerts { get; set; } = new(StringComparer.OrdinalIgnoreCase);

	/// <summary>Per-event visibility map keyed by the catalog event id (stringified in JSON).
	/// Absent key means the event is shown by default when its catalog criticality is High or
	/// Critical. Value false hides the event.</summary>
	public Dictionary<string, bool> ShowEvents { get; set; } = new(StringComparer.Ordinal);

	/// <summary>Minimum allowed poll interval (seconds).</summary>
	public const int MinPollIntervalSeconds = 1;

	/// <summary>Maximum allowed poll interval (seconds).</summary>
	public const int MaxPollIntervalSeconds = 60;

	/// <summary>Minimum allowed toasts-per-minute cap.</summary>
	public const int MinMaxToastsPerMinute = 1;

	/// <summary>Maximum allowed toasts-per-minute cap.</summary>
	public const int MaxMaxToastsPerMinute = 60;

	/// <summary>Resolves the poll interval to a safe [1..60] seconds value.</summary>
	public int ResolvePollIntervalSeconds()
		=> Math.Clamp(PollIntervalSeconds, MinPollIntervalSeconds, MaxPollIntervalSeconds);

	/// <summary>Resolves the per-minute toast cap to a safe [1..60] value.</summary>
	public int ResolveMaxToastsPerMinute()
		=> Math.Clamp(MaxToastsPerMinute, MinMaxToastsPerMinute, MaxMaxToastsPerMinute);

	/// <summary>Parses MinimumSeverity into an AlertSeverity;
	/// unknown or blank values fall back to AlertSeverity.High.</summary>
	public AlertSeverity ResolveMinimumSeverity()
		=> Enum.TryParse(MinimumSeverity, ignoreCase: true, out AlertSeverity severity)
			? severity
			: AlertSeverity.High;
}
