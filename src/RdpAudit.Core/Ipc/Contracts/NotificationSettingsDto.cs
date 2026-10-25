// File:    src/RdpAudit.Core/Ipc/Contracts/NotificationSettingsDto.cs
// Module:  RdpAudit.Core.Ipc.Contracts
// Purpose: Effective tray-notifier settings exchanged over IPC commands 78/79.
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

namespace RdpAudit.Core.Ipc.Contracts;

/// <summary>Effective notification settings returned and saved over IPC 78/79.</summary>
public sealed class NotificationSettingsDto
{
	public bool EnableTrayNotifier { get; set; } = true;
	public bool StartWithWindows { get; set; } = true;
	public int PollIntervalSeconds { get; set; } = 5;
	public string MinimumSeverity { get; set; } = "High";

	/// <summary>Maximum toasts per minute; server-clamped to 1..60. Default 10.</summary>
	public int MaxToastsPerMinute { get; set; } = 10;

	/// <summary>Phase-2 flag: render native WinRT toasts instead of balloon tips.</summary>
	public bool UseNativeToasts { get; set; }

	/// <summary>Per-rule visibility map keyed by the stable rule id. Absent key means shown by default.</summary>
	public Dictionary<string, bool> ShowAlerts { get; set; } = new(StringComparer.OrdinalIgnoreCase);

	/// <summary>Per-event visibility map keyed by the catalog event id. Absent key means shown by default.</summary>
	public Dictionary<string, bool> ShowEvents { get; set; } = new(StringComparer.Ordinal);
}
