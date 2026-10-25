/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 2.0.0
// File   : DatabaseBackupCreationDto.cs
// Project: RdpAudit.Core (RdpAudit.Core.Ipc.Contracts)
// Purpose: Result of a database snapshot request (IPC ordinal 85, and the pre-migration snapshot the
//          schema initializer takes internally). Reports what was written where, its SHA-256, how the
//          snapshot count changed, and which older snapshots the retention removed or deliberately
//          left alone. A failure carries the reason verbatim so the operator can act on it.
// Depends: MessagePack, IpcResultStatus
// Extends: Append fields only; [Key] indices are an append-only ABI.

using MessagePack;

namespace RdpAudit.Core.Ipc.Contracts;

/// <summary>Outcome of one database snapshot.</summary>
[MessagePackObject(keyAsPropertyName: false)]
public sealed class DatabaseBackupCreationDto
{
	/// <summary><see cref="IpcResultStatus.Success"/> when the snapshot was written and verified;
	/// otherwise the failure class (<see cref="IpcResultStatus.Refused"/> for a precondition such as
	/// free space, <see cref="IpcResultStatus.Unavailable"/> for an I/O failure).</summary>
	[Key(0)]
	public IpcResultStatus Status { get; set; } = IpcResultStatus.Success;

	/// <summary>UTC instant of the request.</summary>
	[Key(1)]
	public DateTime QueriedUtc { get; set; }

	/// <summary>Snapshot directory name (the UTC timestamp, plus a collision suffix when needed).</summary>
	[Key(2)]
	public string SnapshotName { get; set; } = string.Empty;

	/// <summary>Absolute snapshot directory.</summary>
	[Key(3)]
	public string SnapshotDirectory { get; set; } = string.Empty;

	/// <summary>Absolute path of the copied database inside the snapshot.</summary>
	[Key(4)]
	public string DatabasePath { get; set; } = string.Empty;

	/// <summary>Size of the copied database in bytes.</summary>
	[Key(5)]
	public long DatabaseBytes { get; set; }

	/// <summary>Uppercase hexadecimal SHA-256 of the copied database.</summary>
	[Key(6)]
	public string DatabaseSha256 { get; set; } = string.Empty;

	/// <summary>Snapshot origin: <c>Manual</c> or <c>PreMigration</c>.</summary>
	[Key(7)]
	public string Kind { get; set; } = string.Empty;

	/// <summary>Wall-clock duration of the snapshot.</summary>
	[Key(8)]
	public long DurationMs { get; set; }

	/// <summary>Number of database snapshots present before this one was taken.</summary>
	[Key(9)]
	public int SnapshotCountBefore { get; set; }

	/// <summary>Number of database snapshots present after retention ran.</summary>
	[Key(10)]
	public int SnapshotCountAfter { get; set; }

	/// <summary>Snapshot directory names the retention removed, newest first.</summary>
	[Key(11)]
	public List<string> RetentionDeleted { get; set; } = new();

	/// <summary>Snapshot directory names the retention refused to remove, with the reason. A settings
	/// or shadow-policy snapshot is never deleted by database retention, and this list says so.</summary>
	[Key(12)]
	public List<string> RetentionSkipped { get; set; } = new();

	/// <summary>True when the shard tree was copied into the snapshot.</summary>
	[Key(13)]
	public bool ShardsIncluded { get; set; }

	/// <summary>Number of shard files copied; zero when shards were not included.</summary>
	[Key(14)]
	public int ShardFileCount { get; set; }

	/// <summary>Bytes of shard data copied; zero when shards were not included.</summary>
	[Key(15)]
	public long ShardBytes { get; set; }

	/// <summary>Operator-facing outcome; for a failure it carries the reason and the path involved.</summary>
	[Key(16)]
	public string? Message { get; set; }
}
