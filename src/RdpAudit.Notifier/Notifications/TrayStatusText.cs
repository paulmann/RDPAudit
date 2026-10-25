// Tray tooltip text shaping: healthy base or degraded retry notice.
namespace RdpAudit.Notifier.Notifications;

/// <summary>Shapes the tray icon tooltip text.</summary>
public static class TrayStatusText
{
	/// <summary>Base tooltip when the service is reachable.</summary>
	public const string Healthy = "RdpAudit Notifier";

	/// <summary>Builds the tooltip for the given reachability and retry delay.</summary>
	public static string For(bool serviceReachable, int delaySeconds)
		=> serviceReachable ? Healthy : "RdpAudit Notifier - service unreachable, retry in " + delaySeconds + "s";
}
