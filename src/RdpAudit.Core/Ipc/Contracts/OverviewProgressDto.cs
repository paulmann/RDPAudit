// File:    src/RdpAudit.Core/Ipc/Contracts/OverviewProgressDto.cs
// Module:  RdpAudit.Core.Ipc.Contracts
// Purpose: DTO returned by GetOverviewProgress describing the state of the long-running historical
//          log-analysis / backfill / indexing job. The Configurator's Overview tab polls this
//          lightly to drive a progress bar so the UI opens immediately and shows progress while the
//          service works through a large historical backlog (e.g. a 1 GB database with more than a
//          million events) instead of blocking on a full historical analysis. Append-only [Key]
//          indices preserve cross-version IPC compatibility.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using MessagePack;

namespace RdpAudit.Core.Ipc.Contracts;

/// <summary>DTO returned by <c>GetOverviewProgress</c> describing historical-analysis progress.</summary>
[MessagePackObject(keyAsPropertyName: false)]
public sealed class OverviewProgressDto
{
	[Key(0)]
	public IpcResultStatus Status { get; set; } = IpcResultStatus.Success;

	/// <summary>True while a backfill / indexing pass is actively running.</summary>
	[Key(1)]
	public bool IsRunning { get; set; }

	/// <summary>Human-readable current stage (e.g. "Idle", "Backfilling Security", "Indexing").</summary>
	[Key(2)]
	public string Stage { get; set; } = "Idle";

	/// <summary>Rows processed so far in the current pass.</summary>
	[Key(3)]
	public long ProcessedRows { get; set; }

	/// <summary>Estimated total rows for the current pass; <c>0</c> when unknown.</summary>
	[Key(4)]
	public long TotalRows { get; set; }

	/// <summary>Completion percentage in the range 0..100; <c>0</c> when total is unknown.</summary>
	[Key(5)]
	public double Percent { get; set; }

	/// <summary>When the current pass started; <c>null</c> when idle.</summary>
	[Key(6)]
	public DateTime? StartedUtc { get; set; }

	/// <summary>When the progress state was last updated.</summary>
	[Key(7)]
	public DateTime LastUpdatedUtc { get; set; }

	/// <summary>Channel currently being processed; <c>null</c> when not channel-scoped.</summary>
	[Key(8)]
	public string? CurrentChannel { get; set; }

	/// <summary>Timestamp of the most recent event processed; <c>null</c> when unknown.</summary>
	[Key(9)]
	public DateTime? LastEventUtc { get; set; }

	/// <summary>Count of non-fatal errors observed during the current / last pass.</summary>
	[Key(10)]
	public long Errors { get; set; }

	/// <summary>Operator-facing message; never carries secret material.</summary>
	[Key(11)]
	public string? Message { get; set; }
}
