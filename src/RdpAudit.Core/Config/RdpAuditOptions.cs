// File:    src/RdpAudit.Core/Config/RdpAuditOptions.cs
// Module:  RdpAudit.Core.Config
// Purpose: Root configuration object bound from appsettings.json.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

namespace RdpAudit.Core.Config;

/// <summary>Root configuration object bound from appsettings.json.</summary>
public sealed class RdpAuditOptions
{
	public const string SectionName = "RdpAudit";

	public MonitoringOptions Monitoring { get; set; } = new();

	public AlertOptions Alerts { get; set; } = new();

	public FirewallOptions Firewall { get; set; } = new();

	public StorageOptions Storage { get; set; } = new();

	public DiagnosticsOptions Diagnostics { get; set; } = new();

	/// <summary>Operation-log viewing depth and retention settings (Logs tab + retention pass).</summary>
	public LogsOptions Logs { get; set; } = new();

	/// <summary>AbuseIPDB external reputation / reporting provider settings.</summary>
	public AbuseIpDbOptions AbuseIpDb { get; set; } = new();

	/// <summary>MikroTik RouterOS external firewall provider settings.</summary>
	public MikroTikOptions MikroTik { get; set; } = new();

	/// <summary>RDP session control (disconnect, logoff, shadow) policy settings.</summary>
	public SessionControlOptions SessionControl { get; set; } = new();
}
