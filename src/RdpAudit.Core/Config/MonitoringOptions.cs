// File:    src/RdpAudit.Core/Config/MonitoringOptions.cs
// Module:  RdpAudit.Core.Config
// Purpose: Configures which event channels and event IDs are monitored.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

namespace RdpAudit.Core.Config;

/// <summary>Configures which event channels and event IDs are monitored.</summary>
public sealed class MonitoringOptions
{
	public List<string> EnabledChannels { get; set; } = new()
	{
		"Security",
		"Microsoft-Windows-TerminalServices-LocalSessionManager/Operational",
		"Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational",
		"Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational",
		"Microsoft-Windows-TerminalServices-Gateway/Operational",
		"Microsoft-Windows-TerminalServices-RDPClient/Operational",
		"System",
	};

	public List<int> EnabledEventIds { get; set; } = new();

	public bool FilterLocalAddresses { get; set; } = true;

	public bool TrackProcessCreation { get; set; } = true;

	public bool TrackScheduledTasks { get; set; } = true;

	public bool TrackAccountChanges { get; set; } = true;

	public bool TrackKerberos { get; set; } = true;

	public bool TrackObjectAccess { get; set; } = true;

	public int BatchSize { get; set; } = 100;

	public int BatchTimeoutMilliseconds { get; set; } = 500;

	public int ChannelCapacity { get; set; } = 50_000;
}
