/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// File   : ZabbixSettingsDto.cs
// Project: RdpAudit.Core (RdpAudit.Core.Ipc.Contracts)
// Purpose: Settings payload of the Zabbix tab (commands GetZabbixSettings 96 / SaveZabbixSettings 97).
//          Secrets are echoed as the mask placeholder, never as their stored envelope.
// Extends: System.Object

using MessagePack;

namespace RdpAudit.Core.Ipc.Contracts;

/// <summary>Zabbix connection settings as the Configurator sees them.</summary>
/// <remarks>MessagePack keys are append-only: add new members at the end with the next free key.</remarks>
[MessagePackObject(keyAsPropertyName: false)]
public sealed class ZabbixSettingsDto
{
	/// <summary>Enables the background push worker.</summary>
	[Key(0)]
	public bool Enabled { get; set; }

	/// <summary>Zabbix server or proxy that accepts the sender protocol.</summary>
	[Key(1)]
	public string ServerHost { get; set; } = string.Empty;

	/// <summary>Trapper port.</summary>
	[Key(2)]
	public int ServerPort { get; set; } = 10051;

	/// <summary>Configured technical host name; blank means "derive from the machine".</summary>
	[Key(3)]
	public string HostName { get; set; } = string.Empty;

	/// <summary>Technical host name that will actually be used, already normalized.</summary>
	[Key(4)]
	public string EffectiveHostName { get; set; } = string.Empty;

	/// <summary>Host group that collects the fleet.</summary>
	[Key(5)]
	public string HostGroup { get; set; } = string.Empty;

	/// <summary>Frontend base URL.</summary>
	[Key(6)]
	public string ApiUrl { get; set; } = string.Empty;

	/// <summary>API token, or the mask placeholder when one is stored.</summary>
	[Key(7)]
	public string ApiToken { get; set; } = string.Empty;

	/// <summary>API user used when no token is configured.</summary>
	[Key(8)]
	public string ApiUser { get; set; } = string.Empty;

	/// <summary>API password, or the mask placeholder when one is stored.</summary>
	[Key(9)]
	public string ApiPassword { get; set; } = string.Empty;

	/// <summary>Validates the server certificate of the API endpoint.</summary>
	[Key(10)]
	public bool ValidateServerCertificate { get; set; } = true;

	/// <summary>Network timeout in seconds.</summary>
	[Key(11)]
	public int TimeoutSeconds { get; set; } = 15;

	/// <summary>Seconds between push cycles.</summary>
	[Key(12)]
	public int PushIntervalSeconds { get; set; } = 60;

	/// <summary>Lowest forwarded severity, as an <c>AlertSeverity</c> name.</summary>
	[Key(13)]
	public string MinimumSeverity { get; set; } = "Medium";

	/// <summary>Upper bound on incidents per push.</summary>
	[Key(14)]
	public int MaxIncidentsPerPush { get; set; } = 20;

	/// <summary>Upper bound on the local backlog.</summary>
	[Key(15)]
	public int MaxBacklogIncidents { get; set; } = 500;

	/// <summary>Creates the trigger set during provisioning.</summary>
	[Key(16)]
	public bool ProvisionTriggers { get; set; } = true;

	/// <summary>Creates the shared dashboard during the first provisioning.</summary>
	[Key(17)]
	public bool CreateDashboard { get; set; } = true;

	/// <summary>Resolved JSON-RPC endpoint, shown so the operator can verify the URL shape.</summary>
	[Key(18)]
	public string ApiEndpoint { get; set; } = string.Empty;

	/// <summary>Resolved "all machines" Problems URL: the single window across the fleet.</summary>
	[Key(19)]
	public string ProblemsUrl { get; set; } = string.Empty;

	/// <summary>Hosts, addresses or CIDRs allowed to write this host's trapper items. Empty means
	/// "use this machine's own addresses".</summary>
	[Key(20)]
	public string TrapperAllowedHosts { get; set; } = string.Empty;
}
