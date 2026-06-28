// File:    src/RdpAudit.Core/Ipc/Contracts/AbuseIpDbReportLogDto.cs
// Module:  RdpAudit.Core.Ipc.Contracts
// Purpose: DTO carrying one AbuseIPDB report-log row to the Configurator grid (req 6). Mirrors the
//          persisted AbuseIpDbReportHistory columns; NEVER carries the API key. [Key(n)] ordinals are
//          append-only and must never be reordered or reused.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using MessagePack;
using RdpAudit.Core.Models;
using RdpAudit.Core.Util;

namespace RdpAudit.Core.Ipc.Contracts;

/// <summary>One AbuseIPDB report-log row for display in the Configurator.</summary>
[MessagePackObject(keyAsPropertyName: false)]
public sealed class AbuseIpDbReportLogDto
{
	/// <summary>Surrogate key of the underlying history row.</summary>
	[Key(0)]
	public long Id { get; set; }

	/// <summary>UTC instant of the attempt.</summary>
	[Key(1)]
	public DateTime TimeUtc { get; set; }

	/// <summary>Source (attacker) IP the row concerns.</summary>
	[Key(2)]
	public string SourceIp { get; set; } = string.Empty;

	/// <summary>Coarse reportability classification of the source IP.</summary>
	[Key(3)]
	public IpReportClassification Classification { get; set; }

	/// <summary>Operator-visible action recorded for the row.</summary>
	[Key(4)]
	public AbuseIpDbReportAction Action { get; set; }

	/// <summary>Machine-readable reason token (dedupe / non-reportable / outcome).</summary>
	[Key(5)]
	public string? Reason { get; set; }

	/// <summary>HTTP status code; 0 when the request was never transmitted.</summary>
	[Key(6)]
	public int HttpStatusCode { get; set; }

	/// <summary>AbuseIPDB report identifier when accepted; null otherwise.</summary>
	[Key(7)]
	public string? ReportId { get; set; }

	/// <summary>UTC instant when the dedupe cooldown expires; null when dedupe is off / not applicable.</summary>
	[Key(8)]
	public DateTime? CooldownExpiresUtc { get; set; }

	/// <summary>Failed-attempt count observed at report time.</summary>
	[Key(9)]
	public long FailedCount { get; set; }

	/// <summary>Successful-logon count observed at report time.</summary>
	[Key(10)]
	public long SuccessfulCount { get; set; }

	/// <summary>First-seen UTC for the IP; null when unknown.</summary>
	[Key(11)]
	public DateTime? FirstSeenUtc { get; set; }

	/// <summary>Last-seen UTC for the IP; null when unknown.</summary>
	[Key(12)]
	public DateTime? LastSeenUtc { get; set; }

	/// <summary>Sanitised usernames sample (max 10), comma separated.</summary>
	[Key(13)]
	public string? UsernamesSample { get; set; }

	/// <summary>Sanitised preview of the submitted report comment; never the API key.</summary>
	[Key(14)]
	public string? CommentPreview { get; set; }

	/// <summary>Originating source tag ("worker" / "manual").</summary>
	[Key(15)]
	public string? Source { get; set; }
}
