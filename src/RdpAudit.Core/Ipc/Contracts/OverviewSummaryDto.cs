// File:    src/RdpAudit.Core/Ipc/Contracts/OverviewSummaryDto.cs
// Module:  RdpAudit.Core.Ipc.Contracts
// Purpose: DTO returned by GetOverviewSummary describing the Stage A operator dashboard counters
//          (attacks today, blocked IPs, active sessions, failed logins, service health, DB size).
//          Append-only [Key] indices preserve cross-version IPC compatibility.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using MessagePack;

namespace RdpAudit.Core.Ipc.Contracts;

/// <summary>DTO returned by <c>GetOverviewSummary</c> describing the Stage A operator dashboard counters.</summary>
[MessagePackObject(keyAsPropertyName: false)]
public sealed class OverviewSummaryDto
{
	/// <summary>Controlled-result status; non-success values carry a non-null <see cref="Message"/>.</summary>
	[Key(0)]
	public IpcResultStatus Status { get; set; } = IpcResultStatus.Success;

	/// <summary>Number of attack-class alerts raised within the UTC-day window ending at <see cref="QueriedUtc"/>.</summary>
	[Key(1)]
	public long AttacksToday { get; set; }

	/// <summary>Total distinct IPs currently blocked by the configured firewall provider (Active + Pending).</summary>
	[Key(2)]
	public long BlockedIps { get; set; }

	/// <summary>Current count of active RDP sessions reported by the service (when available; 0 otherwise).</summary>
	[Key(3)]
	public long ActiveSessions { get; set; }

	/// <summary>Failed-logon count over the trailing 24 hours (RawEvents with the standard 4625 event id).</summary>
	[Key(4)]
	public long FailedLogins24h { get; set; }

	/// <summary>Operator-facing service health summary (e.g. <c>"Running"</c>, <c>"Stopped"</c>); never carries secrets.</summary>
	[Key(5)]
	public string ServiceHealth { get; set; } = string.Empty;

	/// <summary>Current SQLite database file size in bytes; <c>-1</c> when the file cannot be measured.</summary>
	[Key(6)]
	public long DatabaseSizeBytes { get; set; }

	/// <summary>Database growth in bytes versus the snapshot captured ~24 hours ago; <c>null</c> when no snapshot exists yet.</summary>
	[Key(7)]
	public long? DatabaseGrowthBytesDay { get; set; }

	/// <summary>Database growth in bytes versus the snapshot captured ~7 days ago; <c>null</c> when no snapshot exists yet.</summary>
	[Key(8)]
	public long? DatabaseGrowthBytesWeek { get; set; }

	/// <summary>Database growth in bytes versus the snapshot captured ~30 days ago; <c>null</c> when no snapshot exists yet.</summary>
	[Key(9)]
	public long? DatabaseGrowthBytesMonth { get; set; }

	/// <summary>Operator-facing summary message; never carries secret material.</summary>
	[Key(10)]
	public string? Message { get; set; }

	/// <summary>UTC timestamp of the query that produced this snapshot.</summary>
	[Key(11)]
	public DateTime QueriedUtc { get; set; }
}
