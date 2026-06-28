// File:    src/RdpAudit.Core/Config/AbuseIpDbOptions.cs
// Module:  RdpAudit.Core.Config
// Purpose: Configuration for the AbuseIPDB external reputation / reporting provider.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

namespace RdpAudit.Core.Config;

/// <summary>Configuration for the AbuseIPDB external reputation / reporting provider.</summary>
/// <remarks>
/// The <see cref="ApiKey"/> property must be stored in protected-envelope form (a DPAPI payload tagged
/// with "$protected"). The service unprotects it at runtime through the configured
/// <c>ISecretProtector</c>; raw API keys must never be logged or echoed in IPC responses.
/// </remarks>
public sealed class AbuseIpDbOptions
{
	/// <summary>Enables outbound AbuseIPDB integration. When false the HTTP client is never instantiated.</summary>
	public bool Enabled { get; set; }

	/// <summary>When true the reporting worker submits Stage 8 reports for high-threat hostile IPs.</summary>
	public bool ReportAttacks { get; set; }

	/// <summary>Protected envelope holding the AbuseIPDB API key. Empty value disables the provider.</summary>
	public string ApiKey { get; set; } = string.Empty;

	/// <summary>Base URL of the AbuseIPDB API; configurable for on-premises proxies.</summary>
	public string BaseUrl { get; set; } = "https://api.abuseipdb.com";

	/// <summary>Endpoint URL used for submitting reports (Stage 8). Defaults to the v2 /report endpoint.</summary>
	public string EndpointUrl { get; set; } = "https://api.abuseipdb.com/api/v2/report";

	/// <summary>Outbound HTTP timeout in seconds; clamped to a sensible range at use site.</summary>
	public int TimeoutSeconds { get; set; } = 15;

	/// <summary>Maximum reports per minute submitted to AbuseIPDB. Acts as a client-side rate limit.</summary>
	public int MaxReportsPerMinute { get; set; } = 60;

	/// <summary>Maximum reports per hour. Soft cap honoured by the Stage 8 reporting worker.</summary>
	public int MaxReportsPerHour { get; set; } = 100;

	/// <summary>Maximum reports per day. Hard cap honoured by the Stage 8 reporting worker.</summary>
	public int MaxReportsPerDay { get; set; } = 500;

	/// <summary>Minimum dedup window (in minutes) between successive reports of the same IP.</summary>
	/// <remarks>AbuseIPDB enforces ~15 minutes server-side; the client honours at least this minimum.</remarks>
	public int DeduplicationWindowMinutes { get; set; } = 15;

	/// <summary>When true, reputation lookups are cached on disk to avoid duplicate API calls.</summary>
	public bool CacheLookups { get; set; } = true;

	/// <summary>How long, in minutes, a cached reputation lookup remains valid.</summary>
	public int CacheTtlMinutes { get; set; } = 60;

	/// <summary>Abuse confidence score (0..100) at or above which a remote IP is treated as hostile.</summary>
	public int ReportThreshold { get; set; } = 80;

	/// <summary>Minimum local threat score (from <c>AttackStat.ThreatScore</c>) required to fire a report.</summary>
	public double MinThreatScore { get; set; } = 60.0;

	/// <summary>Minimum failed-attempt count required to fire a Stage 8 report.</summary>
	public int MinFailedAttempts { get; set; } = 10;

	/// <summary>Category list submitted with each report. Defaults to RDP brute-force (22) and SSH (18).</summary>
	public List<int> ReportCategories { get; set; } = new() { 18, 22 };

	/// <summary>When true, suppress re-reporting an IP that has a SUCCESSFUL report within <see cref="ReportCooldownHours"/>.</summary>
	/// <remarks>Additive to <see cref="DeduplicationWindowMinutes"/>; enabled by default ("1 report per 1 IP"). Failed reports never suppress.</remarks>
	public bool ReportDedupeEnabled { get; set; } = true;

	/// <summary>Cooldown, in hours, before the same IP may be reported again once a successful report exists.</summary>
	/// <remarks>Clamped to [1, 8760] at use site. Only consulted when <see cref="ReportDedupeEnabled"/> is true.</remarks>
	public int ReportCooldownHours { get; set; } = 24;
}
