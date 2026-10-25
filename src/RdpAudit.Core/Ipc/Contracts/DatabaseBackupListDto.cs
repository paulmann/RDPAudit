/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 2.0.0
// File   : DatabaseBackupListDto.cs
// Project: RdpAudit.Core (RdpAudit.Core.Ipc.Contracts)
// Purpose: Newest-first inventory of the database snapshots under the backup root, one entry per
//          snapshot, with the manifest's verdict attached. Directories in the same root that belong to
//          another scope (settings, shadow policy) are counted but not listed, so the operator sees
//          that they exist and that database retention will not touch them.
// Depends: MessagePack, IpcResultStatus
// Extends: Append fields only; [Key] indices are an append-only ABI.

using MessagePack;

namespace RdpAudit.Core.Ipc.Contracts;

/// <summary>One database snapshot as listed by the Backup &amp; Restore surface.</summary>
[MessagePackObject(keyAsPropertyName: false)]
public sealed class DatabaseBackupEntryDto
{
	/// <summary>Snapshot directory name (UTC timestamp, optionally with a collision suffix).</summary>
	[Key(0)]
	public string Name { get; set; } = string.Empty;

	/// <summary>Absolute snapshot directory.</summary>
	[Key(1)]
	public string Directory { get; set; } = string.Empty;

	/// <summary>UTC instant the snapshot was taken: the manifest timestamp when the manifest is
	/// readable, otherwise the timestamp encoded in the directory name.</summary>
	[Key(2)]
	public DateTime CreatedUtc { get; set; }

	/// <summary>Size of the copied database in bytes; <c>-1</c> when it does not exist.</summary>
	[Key(3)]
	public long DatabaseBytes { get; set; } = -1;

	/// <summary>Total size of every file inside the snapshot directory in bytes; <c>-1</c> when the
	/// walk failed.</summary>
	[Key(4)]
	public long SnapshotBytes { get; set; } = -1;

	/// <summary>True when the manifest is present and parses as a database manifest of a version this
	/// build understands.</summary>
	[Key(5)]
	public bool ManifestValid { get; set; }

	/// <summary>Why the manifest could not be used; null when it is valid.</summary>
	[Key(6)]
	public string? ManifestError { get; set; }

	/// <summary>SHA-256 recorded in the manifest; null when the manifest is unreadable.</summary>
	[Key(7)]
	public string? DatabaseSha256 { get; set; }

	/// <summary>Newest EF migration recorded in the manifest; null when there is none.</summary>
	[Key(8)]
	public string? LastAppliedMigration { get; set; }

	/// <summary>Number of applied migrations recorded in the manifest; <c>-1</c> when unknown.</summary>
	[Key(9)]
	public int AppliedMigrationCount { get; set; } = -1;

	/// <summary>Snapshot origin: <c>Manual</c> or <c>PreMigration</c>; empty when the manifest is
	/// unreadable.</summary>
	[Key(10)]
	public string Kind { get; set; } = string.Empty;

	/// <summary>True when the manifest says the shard tree travelled with the snapshot.</summary>
	[Key(11)]
	public bool ShardsIncluded { get; set; }

	/// <summary>Number of shard files in the snapshot; zero when shards were not included.</summary>
	[Key(12)]
	public int ShardFileCount { get; set; }

	/// <summary>Bytes of shard data in the snapshot; zero when shards were not included.</summary>
	[Key(13)]
	public long ShardBytes { get; set; }

	/// <summary>Row counts recorded at snapshot time, keyed by table name.</summary>
	[Key(14)]
	public Dictionary<string, long> RowCounts { get; set; } = new();

	/// <summary>Product version recorded at snapshot time; null when the manifest is unreadable.</summary>
	[Key(15)]
	public string? ProductVersion { get; set; }
}

/// <summary>Newest-first list of database snapshots plus the effective backup settings.</summary>
[MessagePackObject(keyAsPropertyName: false)]
public sealed class DatabaseBackupListDto
{
	/// <summary><see cref="IpcResultStatus.Success"/> when the inventory was read; a store whose backup
	/// root is unreadable answers <see cref="IpcResultStatus.Unavailable"/>.</summary>
	[Key(0)]
	public IpcResultStatus Status { get; set; } = IpcResultStatus.Success;

	/// <summary>UTC instant this inventory describes.</summary>
	[Key(1)]
	public DateTime QueriedUtc { get; set; }

	/// <summary>Absolute backup root the inventory was taken from.</summary>
	[Key(2)]
	public string BackupDirectory { get; set; } = string.Empty;

	/// <summary>True when the operator-facing snapshot surface is enabled.</summary>
	[Key(3)]
	public bool Enabled { get; set; }

	/// <summary>True when a snapshot is required before EF migrations are applied.</summary>
	[Key(4)]
	public bool PreMigrationBackupEnabled { get; set; }

	/// <summary>Effective number of database snapshots kept.</summary>
	[Key(5)]
	public int RetentionCopies { get; set; }

	/// <summary>Snapshots, newest first.</summary>
	[Key(6)]
	public List<DatabaseBackupEntryDto> Entries { get; set; } = new();

	/// <summary>Number of snapshots returned.</summary>
	[Key(7)]
	public int TotalCount { get; set; }

	/// <summary>Directories in the backup root that are not database snapshots and are therefore never
	/// removed by database retention.</summary>
	[Key(8)]
	public int SkippedDirectoryCount { get; set; }

	/// <summary>True when the inventory was truncated because the snapshot count exceeded the bounded
	/// read limit, so the list is a lower bound.</summary>
	[Key(9)]
	public bool Truncated { get; set; }

	/// <summary>Operator-facing summary; never carries secret material.</summary>
	[Key(10)]
	public string? Message { get; set; }
}
