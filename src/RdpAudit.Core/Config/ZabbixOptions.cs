/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// File   : ZabbixOptions.cs
// Project: RdpAudit.Core (RdpAudit.Core.Config)
// Purpose: Configuration for the Zabbix integration: the outbound incident push (Zabbix sender
//          protocol, TCP 10051) and the one-time provisioning call against the Zabbix JSON-RPC API.
//          Both credentials are stored as protected envelopes; no value ever reaches a log, a DTO
//          or an IPC payload.
// Depends: AlertSeverity
// Extends: Bind a new property here only together with the code that reads it, the settings
//          template entry and the Configurator field that writes it.

using RdpAudit.Core.Models;

namespace RdpAudit.Core.Config;

/// <summary>Configuration for the Zabbix integration (incident push plus API provisioning).</summary>
/// <remarks>
/// <para>
/// Delivery uses the native Zabbix sender protocol against trapper items on the machine's own
/// host, because that is the only supported way for an external system to write item values:
/// measured on 2026-10-25 against Zabbix 8.0.0, <c>history.push</c> over HTTPS answers
/// "Client IP is not in item's allowed hosts list" for a trapper item, and <c>allowed_hosts</c>
/// is not an accepted <c>item.create</c> parameter. Provisioning uses the JSON-RPC API and is
/// idempotent: it looks every object up before creating it and never deletes.
/// </para>
/// <para>
/// Fail-closed: <see cref="Enabled"/> is false by default, an unreachable server is recorded as a
/// failure and never as "nothing to report", and a batch is only acknowledged after the server
/// answered with <c>failed: 0</c>.
/// </para>
/// </remarks>
public sealed class ZabbixOptions
{
	/// <summary>Default trapper port.</summary>
	public const int DefaultServerPort = 10051;

	/// <summary>Default host group that collects the whole fleet.</summary>
	public const string DefaultHostGroup = "RDPAudit";

	/// <summary>Default network timeout.</summary>
	public const int DefaultTimeoutSeconds = 15;

	/// <summary>Default push cadence.</summary>
	public const int DefaultPushIntervalSeconds = 60;

	/// <summary>Default per-push incident cap.</summary>
	public const int DefaultMaxIncidentsPerPush = 20;

	/// <summary>Default local backlog cap.</summary>
	public const int DefaultMaxBacklogIncidents = 500;

	/// <summary>Lower bound for <see cref="PushIntervalSeconds"/>.</summary>
	public const int MinPushIntervalSeconds = 15;

	/// <summary>Upper bound for <see cref="PushIntervalSeconds"/>.</summary>
	public const int MaxPushIntervalSeconds = 86_400;

	/// <summary>Lower bound for <see cref="TimeoutSeconds"/>.</summary>
	public const int MinTimeoutSeconds = 3;

	/// <summary>Upper bound for <see cref="TimeoutSeconds"/>.</summary>
	public const int MaxTimeoutSeconds = 120;

	/// <summary>Lower bound for <see cref="MaxIncidentsPerPush"/>.</summary>
	public const int MinIncidentsPerPush = 1;

	/// <summary>Upper bound for <see cref="MaxIncidentsPerPush"/>.</summary>
	public const int MaxIncidentsPerPushCeiling = 200;

	/// <summary>Lower bound for <see cref="MaxBacklogIncidents"/>.</summary>
	public const int MinBacklogIncidents = 1;

	/// <summary>Upper bound for <see cref="MaxBacklogIncidents"/>.</summary>
	public const int MaxBacklogIncidentsCeiling = 100_000;

	/// <summary>Enables the background push worker. When false no connection is ever attempted.</summary>
	public bool Enabled { get; set; }

	/// <summary>Zabbix server (or proxy) that accepts the sender protocol.</summary>
	public string ServerHost { get; set; } = string.Empty;

	/// <summary>Trapper port on <see cref="ServerHost"/>; 10051 is the Zabbix default.</summary>
	public int ServerPort { get; set; } = DefaultServerPort;

	/// <summary>Technical host name in Zabbix. Empty means "use the machine name". Sanitized before
	/// use, because the name is embedded into trigger expressions during provisioning.</summary>
	public string HostName { get; set; } = string.Empty;

	/// <summary>Comma-separated hosts, addresses or CIDRs allowed to write this host's trapper
	/// items. Empty means "use this machine's own addresses", which is what a normal install
	/// needs; set <c>*</c> only when the machine is reached through NAT and its source address
	/// differs from any local address. An item that does not list the sender rejects the value
	/// while the sender protocol still answers "success", so this is not cosmetic.</summary>
	public string TrapperAllowedHosts { get; set; } = string.Empty;

	/// <summary>Host group that collects every machine running this agent.</summary>
	public string HostGroup { get; set; } = DefaultHostGroup;

	/// <summary>Base URL of the web frontend, for example <c>https://22877.ru</c>. The API endpoint is
	/// derived from it unless the value already points at <c>api_jsonrpc.php</c>.</summary>
	public string ApiUrl { get; set; } = string.Empty;

	/// <summary>Protected envelope holding the API token. Preferred over user/password.</summary>
	public string ApiToken { get; set; } = string.Empty;

	/// <summary>API user used when no token is configured.</summary>
	public string ApiUser { get; set; } = string.Empty;

	/// <summary>Protected envelope holding the API password used when no token is configured.</summary>
	public string ApiPassword { get; set; } = string.Empty;

	/// <summary>When false the API client accepts any server certificate. Defaults to true; the
	/// exemption exists for on-premises installations with a self-signed certificate.</summary>
	public bool ValidateServerCertificate { get; set; } = true;

	/// <summary>Timeout in seconds for one sender round-trip or one API call.</summary>
	public int TimeoutSeconds { get; set; } = DefaultTimeoutSeconds;

	/// <summary>Seconds between push cycles. The heartbeat is sent on the same cadence.</summary>
	public int PushIntervalSeconds { get; set; } = DefaultPushIntervalSeconds;

	/// <summary>Lowest alert severity that is forwarded to Zabbix.</summary>
	public AlertSeverity MinimumSeverity { get; set; } = AlertSeverity.Medium;

	/// <summary>Upper bound on incidents carried by one push.</summary>
	public int MaxIncidentsPerPush { get; set; } = DefaultMaxIncidentsPerPush;

	/// <summary>Upper bound on the local backlog. When more incidents are pending, the oldest are
	/// skipped, the skip count is reported in the payload, and the reason is logged — Zabbix is a
	/// notification channel, the local database stays the evidence store.</summary>
	public int MaxBacklogIncidents { get; set; } = DefaultMaxBacklogIncidents;

	/// <summary>Create the trigger set together with the host during provisioning.</summary>
	public bool ProvisionTriggers { get; set; } = true;

	/// <summary>Create the shared "one window" dashboard during the first provisioning.</summary>
	public bool CreateDashboard { get; set; } = true;

	/// <summary>Returns the effective trapper port, clamped to the valid TCP range.</summary>
	public int ResolveServerPort() => ServerPort is > 0 and <= 65_535 ? ServerPort : DefaultServerPort;

	/// <summary>Returns the configured timeout clamped to the supported range.</summary>
	public int ResolveTimeoutSeconds() => Math.Clamp(TimeoutSeconds, MinTimeoutSeconds, MaxTimeoutSeconds);

	/// <summary>Returns the push interval clamped to the supported range.</summary>
	public int ResolvePushIntervalSeconds()
		=> Math.Clamp(PushIntervalSeconds, MinPushIntervalSeconds, MaxPushIntervalSeconds);

	/// <summary>Returns the per-push incident cap clamped to the supported range.</summary>
	public int ResolveMaxIncidentsPerPush()
		=> Math.Clamp(MaxIncidentsPerPush, MinIncidentsPerPush, MaxIncidentsPerPushCeiling);

	/// <summary>Returns the backlog cap clamped to the supported range.</summary>
	public int ResolveMaxBacklogIncidents()
		=> Math.Clamp(MaxBacklogIncidents, MinBacklogIncidents, MaxBacklogIncidentsCeiling);

	/// <summary>Returns the host group name, falling back to the default when blank.</summary>
	public string ResolveHostGroup()
		=> string.IsNullOrWhiteSpace(HostGroup) ? DefaultHostGroup : HostGroup.Trim();

	/// <summary>True when enough is configured for the push worker to attempt a connection.</summary>
	public bool IsPushConfigured() => Enabled && !string.IsNullOrWhiteSpace(ServerHost);

	/// <summary>True when the API can be called at all (URL plus one credential form).</summary>
	public bool IsApiConfigured()
		=> !string.IsNullOrWhiteSpace(ApiUrl)
			&& (!string.IsNullOrWhiteSpace(ApiToken)
				|| (!string.IsNullOrWhiteSpace(ApiUser) && !string.IsNullOrWhiteSpace(ApiPassword)));

	/// <summary>Builds the JSON-RPC endpoint from <see cref="ApiUrl"/>, tolerating a URL that already
	/// points at the endpoint, a trailing slash, or a bare host.</summary>
	public string ResolveApiEndpoint()
	{
		string raw = (ApiUrl ?? string.Empty).Trim();
		if (raw.Length == 0)
		{
			return string.Empty;
		}

		if (raw.Contains("/api_jsonrpc.php", StringComparison.OrdinalIgnoreCase))
		{
			return raw;
		}

		if (!raw.Contains("://", StringComparison.Ordinal))
		{
			raw = "https://" + raw;
		}

		return raw.TrimEnd('/') + "/api_jsonrpc.php";
	}

	/// <summary>Builds the frontend origin (scheme plus authority) used for the "open in Zabbix"
	/// links, or an empty string when the URL is not usable.</summary>
	public string ResolveFrontendOrigin()
	{
		string raw = (ApiUrl ?? string.Empty).Trim();
		if (raw.Length == 0)
		{
			return string.Empty;
		}

		int marker = raw.IndexOf("/api_jsonrpc.php", StringComparison.OrdinalIgnoreCase);
		if (marker > 0)
		{
			raw = raw[..marker];
		}

		if (!raw.Contains("://", StringComparison.Ordinal))
		{
			raw = "https://" + raw;
		}

		return Uri.TryCreate(raw, UriKind.Absolute, out Uri? parsed)
			? parsed.GetLeftPart(UriPartial.Authority)
			: string.Empty;
	}
}
