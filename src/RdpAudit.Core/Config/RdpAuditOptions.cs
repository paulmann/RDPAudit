/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 2.0.1
// File   : RdpAuditOptions.cs
// Project: RdpAudit.Core (RdpAudit.Core.Config)
// Purpose: Binds root service configuration including optional forensic shard storage.
// Depends: MonitoringOptions, ShardingOptions
// Extends: Add a root option property when a new independently bound configuration section is introduced.

namespace RdpAudit.Core.Config;

/// <summary>Root configuration object bound from appsettings.json.</summary>
public sealed class RdpAuditOptions
{
	public const string SectionName = "RdpAudit";
	public MonitoringOptions Monitoring { get; set; } = new();
	public AlertOptions Alerts { get; set; } = new();
	public FirewallOptions Firewall { get; set; } = new();
	public StorageOptions Storage { get; set; } = new();
	public ShardingOptions Sharding { get; set; } = new();
	public DiagnosticsOptions Diagnostics { get; set; } = new();
	public LogsOptions Logs { get; set; } = new();
	public AbuseIpDbOptions AbuseIpDb { get; set; } = new();
	public MikroTikOptions MikroTik { get; set; } = new();
	public SessionControlOptions SessionControl { get; set; } = new();
}
