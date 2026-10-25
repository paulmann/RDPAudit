// File:    src/RdpAudit.Core/Ipc/Contracts/AttackStatsRebuildResultDto.cs
// Module:  RdpAudit.Core.Ipc.Contracts
// Purpose: Result of the DEBUG-gated RebuildAttackStats IPC action. Reports whether a synchronous
//          AttackStatsRefreshWorker projection pass ran, how many AttackStat rows it upserted, how
//          long it took, and the post-rebuild table total — so the RDP Activity tab can confirm a
//          manual rebuild actually advanced the projection. Plain JSON (no MessagePack keys) so it
//          round-trips trivially over the JSON IPC payload channel.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

namespace RdpAudit.Core.Ipc.Contracts;

/// <summary>Result of a manual RDP Activity (AttackStats) rebuild.</summary>
public sealed class AttackStatsRebuildResultDto
{
	public IpcResultStatus Status { get; set; } = IpcResultStatus.Success;

	public string? Message { get; set; }

	public DateTime GeneratedUtc { get; set; }

	/// <summary>Rows upserted by the synchronous projection pass.</summary>
	public int RowsUpserted { get; set; }

	/// <summary>Wall-clock duration of the projection pass.</summary>
	public long ElapsedMilliseconds { get; set; }

	/// <summary>Total rows in AttackStats after the rebuild.</summary>
	public long AttackStatsTotal { get; set; }

	// --- v1.3.6: prove the rebuild advanced the projection and re-derived current-day LastSeenUtc. ---

	/// <summary>True when this was a full rebuild (paged every in-window fact) rather than an
	/// incremental newest-first slice. The DEBUG action always requests a full rebuild.</summary>
	public bool FullRebuild { get; set; }

	/// <summary>AttackStats row count before the rebuild.</summary>
	public long RowsBefore { get; set; }

	/// <summary>AttackStats row count after the rebuild.</summary>
	public long RowsAfter { get; set; }

	/// <summary>Newest AuthAttemptFact.TimeUtc the rebuild considered (projection INPUT watermark).</summary>
	public DateTime? LatestSourceFactUtc { get; set; }

	/// <summary>Newest AttackStat.LastSeenUtc after the rebuild (projection OUTPUT watermark). After a
	/// successful rebuild on a host with fresh logins this should equal the current-day source fact.</summary>
	public DateTime? LatestAttackStatLastSeenUtc { get; set; }
}
