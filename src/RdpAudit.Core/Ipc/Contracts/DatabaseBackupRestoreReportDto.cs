/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 2.0.0
// File   : DatabaseBackupRestoreReportDto.cs
// Project: RdpAudit.Core (RdpAudit.Core.Ipc.Contracts)
// Purpose: Result of restoring a database snapshot into a scratch directory. Every restore verifies
//          the snapshot before it writes a byte, reports the verification it relied on, and names the
//          file it produced, so "the restore ran" and "the restore produced a usable database" are two
//          distinguishable statements.
// Depends: MessagePack, IpcResultStatus
// Extends: Append fields only; [Key] indices are an append-only ABI.

using MessagePack;

namespace RdpAudit.Core.Ipc.Contracts;

/// <summary>Outcome of a snapshot restore into a target directory.</summary>
[MessagePackObject(keyAsPropertyName: false)]
public sealed class DatabaseBackupRestoreReportDto
{
	/// <summary><see cref="IpcResultStatus.Success"/> when the database copy was written and verified;
	/// <see cref="IpcResultStatus.Refused"/> when the snapshot did not pass verification and nothing was
	/// written.</summary>
	[Key(0)]
	public IpcResultStatus Status { get; set; } = IpcResultStatus.Success;

	/// <summary>UTC instant of the restore.</summary>
	[Key(1)]
	public DateTime QueriedUtc { get; set; }

	/// <summary>Snapshot directory name that was restored.</summary>
	[Key(2)]
	public string SnapshotName { get; set; } = string.Empty;

	/// <summary>Absolute directory the snapshot was restored into.</summary>
	[Key(3)]
	public string TargetDirectory { get; set; } = string.Empty;

	/// <summary>Absolute path of the restored database file; empty when nothing was written.</summary>
	[Key(4)]
	public string TargetDatabasePath { get; set; } = string.Empty;

	/// <summary>Bytes written for the database file.</summary>
	[Key(5)]
	public long DatabaseBytesCopied { get; set; }

	/// <summary>True when the shard tree was also restored into the target directory.</summary>
	[Key(6)]
	public bool ShardsRestored { get; set; }

	/// <summary>Number of shard files restored.</summary>
	[Key(7)]
	public int ShardFilesRestored { get; set; }

	/// <summary>Bytes of shard data restored.</summary>
	[Key(8)]
	public long ShardBytesRestored { get; set; }

	/// <summary>Verification the restore relied on; null when the snapshot was not verifiable at all.</summary>
	[Key(9)]
	public DatabaseBackupVerificationDto? Verification { get; set; }

	/// <summary>Operator-facing outcome, including the reason when the restore was refused.</summary>
	[Key(10)]
	public string? Message { get; set; }
}
