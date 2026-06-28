// File:    src/RdpAudit.Core/Config/MikroTikOptions.cs
// Module:  RdpAudit.Core.Config
// Purpose: Configuration for the MikroTik RouterOS v7 external firewall provider (REST API).
//          Supports either a freeform BaseUrl OR explicit Scheme/Host/Port composition. The
//          BaseUrl wins when supplied so legacy appsettings.json documents keep binding. Stage 9
//          additions: ScheduleAddRules toggle (renamed alias of AddAttackerRules), Scheme/Host/
//          Port composition, FilterChain/Action for the firewall filter, a BlockDuration TimeSpan
//          (composed from days/hours/minutes) and a CommentPrefix used to recognise RdpAudit-owned
//          rules. The plaintext password must NEVER appear on disk, in logs or in IPC payloads —
//          it is wrapped by ISecretProtector before SaveSettings persists the document.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System.Globalization;

namespace RdpAudit.Core.Config;

/// <summary>Configuration for the MikroTik RouterOS v7 external firewall provider (REST API).</summary>
/// <remarks>
/// <see cref="Password"/> must be stored in protected-envelope form (e.g. a DPAPI payload tagged
/// with "$protected"). The service unprotects it at runtime through the configured
/// <c>ISecretProtector</c>; the raw password must never be logged or echoed in IPC responses.
/// </remarks>
public sealed class MikroTikOptions
{
	/// <summary>Enables outbound MikroTik integration. When false the REST client is never instantiated.</summary>
	public bool Enabled { get; set; }

	/// <summary>When true the provider creates firewall filter rules for attacker IPs. Defaults to true.</summary>
	/// <remarks>
	/// Operators may run with <see cref="Enabled"/>=true and <see cref="AddAttackerRules"/>=false to
	/// keep the connection wired for diagnostics / status reporting only without writing any rules.
	/// </remarks>
	public bool AddAttackerRules { get; set; } = true;

	/// <summary>Optional full base URL ("https://10.0.0.1:443"). When set this wins over Scheme/Host/Port.</summary>
	public string BaseUrl { get; set; } = string.Empty;

	/// <summary>True selects HTTPS; false selects HTTP. Honoured only when <see cref="BaseUrl"/> is empty.</summary>
	public bool UseHttps { get; set; } = true;

	/// <summary>Router host name or IP literal. Used to compose the REST URL when <see cref="BaseUrl"/> is empty.</summary>
	public string Host { get; set; } = string.Empty;

	/// <summary>Optional explicit TCP port. 0 means "use scheme default" (443 for https / 80 for http).</summary>
	public int Port { get; set; }

	/// <summary>API user name used for REST Basic authentication.</summary>
	public string UserName { get; set; } = string.Empty;

	/// <summary>Protected envelope holding the REST password. Empty value disables the provider.</summary>
	public string Password { get; set; } = string.Empty;

	/// <summary>Outbound HTTP timeout in seconds; clamped to a sensible range at use site.</summary>
	public int TimeoutSeconds { get; set; } = 15;

	/// <summary>Address list (e.g. "rdpaudit-block") into which the provider can optionally insert blocked IPs.</summary>
	/// <remarks>
	/// Stage 9 favours direct firewall filter rules — see <see cref="FilterChain"/> and
	/// <see cref="FilterAction"/> — but the address-list value is preserved for operators who want
	/// to map blocks into a router-side blocklist consumed by another rule.
	/// </remarks>
	public string AddressList { get; set; } = "rdpaudit-block";

	/// <summary>Firewall filter chain into which the per-IP block rule is inserted ("input" or "forward").</summary>
	public string FilterChain { get; set; } = "input";

	/// <summary>Firewall filter action ("drop" or "reject"). Defaults to "drop" to keep attackers blind.</summary>
	public string FilterAction { get; set; } = "drop";

	/// <summary>Optional comment template attached to each block entry for traceability.</summary>
	public string CommentTemplate { get; set; } = "RdpAudit auto-block";

	/// <summary>Prefix recognised on existing rules so the provider only removes its own entries.</summary>
	public string CommentPrefix { get; set; } = "RdpAudit";

	/// <summary>When true the provider validates the RouterOS TLS certificate. Disable only for lab use.</summary>
	public bool ValidateServerCertificate { get; set; } = true;

	/// <summary>Maximum API operations per minute (rate-limit guardrail).</summary>
	public int MaxOperationsPerMinute { get; set; } = 120;

	/// <summary>Block duration component — days. Defaults to 0.</summary>
	public int BlockDurationDays { get; set; }

	/// <summary>Block duration component — hours. Defaults to 1.</summary>
	public int BlockDurationHours { get; set; } = 1;

	/// <summary>Block duration component — minutes. Defaults to 0.</summary>
	public int BlockDurationMinutes { get; set; }

	/// <summary>Returns the composed block duration; falls back to one hour when all components are zero.</summary>
	public TimeSpan ComposedBlockDuration()
	{
		int days = BlockDurationDays < 0 ? 0 : BlockDurationDays;
		int hours = BlockDurationHours < 0 ? 0 : BlockDurationHours;
		int minutes = BlockDurationMinutes < 0 ? 0 : BlockDurationMinutes;

		TimeSpan total = TimeSpan.FromDays(days) + TimeSpan.FromHours(hours) + TimeSpan.FromMinutes(minutes);
		if (total <= TimeSpan.Zero)
		{
			return TimeSpan.FromHours(1);
		}
		return total;
	}

	/// <summary>Returns a sanitised description (no credentials) of the configured endpoint for logs/UI.</summary>
	public string DescribeEndpoint()
	{
		if (!string.IsNullOrWhiteSpace(BaseUrl))
		{
			return BaseUrl;
		}
		if (string.IsNullOrWhiteSpace(Host))
		{
			return string.Empty;
		}

		string scheme = UseHttps ? "https" : "http";
		if (Port > 0)
		{
			return string.Format(CultureInfo.InvariantCulture, "{0}://{1}:{2}", scheme, Host, Port);
		}
		return string.Format(CultureInfo.InvariantCulture, "{0}://{1}", scheme, Host);
	}
}
