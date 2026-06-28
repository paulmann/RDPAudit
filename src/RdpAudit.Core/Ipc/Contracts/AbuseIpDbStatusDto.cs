// File:    src/RdpAudit.Core/Ipc/Contracts/AbuseIpDbStatusDto.cs
// Module:  RdpAudit.Core.Ipc.Contracts
// Purpose: DTO returned by GetAbuseIpDbStatus. Reports whether AbuseIPDB integration is configured /
//          enabled and surfaces aggregate report counters plus the last report outcome. NEVER contains
//          the API key — only a CredentialPresent flag.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using MessagePack;

namespace RdpAudit.Core.Ipc.Contracts;

/// <summary>DTO returned by <c>GetAbuseIpDbStatus</c>. Reports configuration and reporting telemetry only.</summary>
[MessagePackObject(keyAsPropertyName: false)]
public sealed class AbuseIpDbStatusDto
{
	[Key(0)]
	public IpcResultStatus Status { get; set; } = IpcResultStatus.Success;

	/// <summary>True when an API key envelope is present in the configured options.</summary>
	[Key(1)]
	public bool CredentialPresent { get; set; }

	/// <summary>True when both Enabled is set and ReportAttacks is selected.</summary>
	[Key(2)]
	public bool ReportingEnabled { get; set; }

	/// <summary>Endpoint URL configured for outbound reports.</summary>
	[Key(3)]
	public string EndpointUrl { get; set; } = string.Empty;

	/// <summary>Total reports recorded in the AbuseReports table.</summary>
	[Key(4)]
	public long TotalReports { get; set; }

	/// <summary>Reports recorded in the last hour.</summary>
	[Key(5)]
	public long ReportsLastHour { get; set; }

	/// <summary>Reports recorded in the last 24 hours.</summary>
	[Key(6)]
	public long ReportsLastDay { get; set; }

	/// <summary>HTTP status code of the most recent report attempt (0 when no attempts).</summary>
	[Key(7)]
	public int LastResponseCode { get; set; }

	/// <summary>UTC time of the most recent report attempt; null when no attempts yet.</summary>
	[Key(8)]
	public DateTime? LastReportUtc { get; set; }

	/// <summary>IP address reported on the most recent attempt; empty when no attempts yet.</summary>
	[Key(9)]
	public string LastReportedIp { get; set; } = string.Empty;

	/// <summary>Sanitised last-error string; null when most recent report succeeded.</summary>
	[Key(10)]
	public string? LastError { get; set; }

	/// <summary>True when the client-side rate-limit is currently engaged.</summary>
	[Key(11)]
	public bool RateLimited { get; set; }

	/// <summary>Optional human-readable message describing rate-limit state or reporting telemetry.</summary>
	[Key(12)]
	public string? Message { get; set; }

	/// <summary>Configured dedup window in minutes.</summary>
	[Key(13)]
	public int DeduplicationWindowMinutes { get; set; }

	/// <summary>Configured max reports per hour (informational).</summary>
	[Key(14)]
	public int MaxReportsPerHour { get; set; }

	/// <summary>Configured max reports per day (informational).</summary>
	[Key(15)]
	public int MaxReportsPerDay { get; set; }

	/// <summary>True when the success-filtered report cooldown ("1 report per 1 IP") is enabled.</summary>
	[Key(16)]
	public bool ReportDedupeEnabled { get; set; }

	/// <summary>Configured cooldown, in hours, before the same IP may be reported again after a success.</summary>
	[Key(17)]
	public int ReportCooldownHours { get; set; }
}
