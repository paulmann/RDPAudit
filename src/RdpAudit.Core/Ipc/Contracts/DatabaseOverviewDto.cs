/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 2.0.0
// File   : DatabaseOverviewDto.cs
// Project: RdpAudit.Core (RdpAudit.Core.Ipc.Contracts)
// Purpose: Read-only snapshot of the evidence store for the Database tab's Overview section:
//          file sizes, volume free space, the shard tree footprint, per-table row counts, size
//          growth and projected time-to-cap, schema migration state, the migration-failure
//          marker, the effective retention-policy switches and the aggregated deletion-ledger
//          totals. Deliberately sectioned: the producer marks the snapshot partial and records a
//          per-section outcome instead of failing the whole command when one section is
//          unavailable (the GetDiagnostics contract).
// Depends: MessagePack, IpcResultStatus
// Extends: Append fields only; [Key] indices are an append-only ABI.

using MessagePack;

namespace RdpAudit.Core.Ipc.Contracts;

/// <summary>Row count of one evidence table, with a per-table failure note when the count could
/// not be read.</summary>
[MessagePackObject(keyAsPropertyName: false)]
public sealed class DatabaseTableRowCountDto
{
	/// <summary>Table name as persisted in the SQLite schema.</summary>
	[Key(0)]
	public string Table { get; set; } = string.Empty;

	/// <summary>Exact row count, or <c>-1</c> when the count could not be read.</summary>
	[Key(1)]
	public long RowCount { get; set; } = -1;

	/// <summary>Operator-facing failure note; null when the count succeeded.</summary>
	[Key(2)]
	public string? Error { get; set; }
}

/// <summary>Outcome of one bounded overview section, mirroring the Diagnostics section
/// contract: <c>Completed</c> / <c>TimedOut</c> / <c>Failed</c>.</summary>
[MessagePackObject(keyAsPropertyName: false)]
public sealed class DatabaseOverviewSectionDto
{
	/// <summary>Stable section name (for example <c>DbFiles</c>).</summary>
	[Key(0)]
	public string Section { get; set; } = string.Empty;

	/// <summary>Wall-clock duration of the section.</summary>
	[Key(1)]
	public long DurationMs { get; set; }

	/// <summary><c>Completed</c>, <c>TimedOut</c> or <c>Failed</c>.</summary>
	[Key(2)]
	public string Status { get; set; } = string.Empty;

	/// <summary>Failure or timeout detail; null on success.</summary>
	[Key(3)]
	public string? Error { get; set; }
}

/// <summary>Bounded, sectioned snapshot of the evidence store.</summary>
[MessagePackObject(keyAsPropertyName: false)]
public sealed class DatabaseOverviewDto
{
	// ── Envelope ────────────────────────────────────────────────────────────────

	/// <summary><see cref="IpcResultStatus.Unavailable"/> when nothing at all could be read;
	/// otherwise <see cref="IpcResultStatus.Success"/> even when the snapshot is partial.</summary>
	[Key(0)]
	public IpcResultStatus Status { get; set; } = IpcResultStatus.Success;

	/// <summary>UTC instant this snapshot describes. Every field is "as of" this stamp.</summary>
	[Key(1)]
	public DateTime QueriedUtc { get; set; }

	// ── Database file family ────────────────────────────────────────────────────

	/// <summary>Absolute path of the SQLite database file.</summary>
	[Key(2)]
	public string DatabasePath { get; set; } = string.Empty;

	/// <summary>Database file size in bytes; <c>0</c> when the file does not exist yet, <c>-1</c> when
	/// it exists but could not be measured.</summary>
	[Key(3)]
	public long DatabaseBytes { get; set; } = -1;

	/// <summary>Write-ahead log size in bytes; <c>0</c> when the file does not exist, <c>-1</c> when
	/// it exists but could not be measured.</summary>
	[Key(4)]
	public long WalBytes { get; set; } = -1;

	/// <summary>Shared-memory file size in bytes; <c>0</c> when the file does not exist, <c>-1</c>
	/// when it exists but could not be measured.</summary>
	[Key(5)]
	public long ShmBytes { get; set; } = -1;

	/// <summary>Database plus WAL plus SHM, in bytes; <c>-1</c> when any of the three could not be
	/// measured. This is the figure the <c>MaxDatabaseBytes</c> pressure trigger compares against.</summary>
	[Key(6)]
	public long TotalDatabaseFamilyBytes { get; set; } = -1;

	// ── Volumes ─────────────────────────────────────────────────────────────────

	/// <summary>Root of the volume hosting the database (for example <c>C:\</c>).</summary>
	[Key(7)]
	public string DatabaseVolumeRoot { get; set; } = string.Empty;

	/// <summary>Free bytes on the database volume; null when the volume could not be inspected.</summary>
	[Key(8)]
	public long? DatabaseVolumeFreeBytes { get; set; }

	/// <summary>Total bytes of the database volume; null when the volume could not be inspected.</summary>
	[Key(9)]
	public long? DatabaseVolumeTotalBytes { get; set; }

	/// <summary>Root of the volume hosting the shard tree.</summary>
	[Key(10)]
	public string ActionsVolumeRoot { get; set; } = string.Empty;

	/// <summary>Free bytes on the shard-tree volume; null when it could not be inspected.</summary>
	[Key(11)]
	public long? ActionsVolumeFreeBytes { get; set; }

	/// <summary>Total bytes of the shard-tree volume; null when it could not be inspected.</summary>
	[Key(12)]
	public long? ActionsVolumeTotalBytes { get; set; }

	// ── actions\ shard tree ─────────────────────────────────────────────────────

	/// <summary>Absolute path of the shard tree root.</summary>
	[Key(13)]
	public string ActionsRoot { get; set; } = string.Empty;

	/// <summary>Total size of every file under the shard tree, in bytes; <c>-1</c> when the tree
	/// could not be walked.</summary>
	[Key(14)]
	public long ActionsBytes { get; set; } = -1;

	/// <summary>Number of files under the shard tree; <c>-1</c> when the tree could not be walked.</summary>
	[Key(15)]
	public long ActionsFileCount { get; set; } = -1;

	/// <summary>True when the bounded walk stopped before enumerating the whole tree, so
	/// <see cref="ActionsBytes"/> and <see cref="ActionsFileCount"/> are lower bounds.</summary>
	[Key(16)]
	public bool ActionsScanTruncated { get; set; }

	// ── Row counts ──────────────────────────────────────────────────────────────

	/// <summary>Row counts of the key evidence tables, each independently failable.</summary>
	[Key(17)]
	public List<DatabaseTableRowCountDto> TableRowCounts { get; set; } = new();

	// ── Growth and projection ───────────────────────────────────────────────────

	/// <summary>Database growth over the last day from <c>DbSizeGrowthCalculator</c>; null when no
	/// usable snapshot exists.</summary>
	[Key(18)]
	public long? GrowthBytesDay { get; set; }

	/// <summary>Database growth over the last week; null when no usable snapshot exists.</summary>
	[Key(19)]
	public long? GrowthBytesWeek { get; set; }

	/// <summary>Database growth over the last month; null when no usable snapshot exists.</summary>
	[Key(20)]
	public long? GrowthBytesMonth { get; set; }

	/// <summary>Whole days until the database family reaches <c>MaxDatabaseBytes</c> at the monthly
	/// growth rate. Null when the ceiling is disabled, the growth rate is unknown or not positive,
	/// or the ceiling is already breached (see <see cref="GrowthNote"/>).</summary>
	[Key(21)]
	public long? ProjectedDaysToCap { get; set; }

	/// <summary>Explains how <see cref="ProjectedDaysToCap"/> was derived, or why it is null.</summary>
	[Key(22)]
	public string? GrowthNote { get; set; }

	// ── Schema state ────────────────────────────────────────────────────────────

	/// <summary>Migrations already applied to the live database, oldest first.</summary>
	[Key(23)]
	public List<string> AppliedMigrations { get; set; } = new();

	/// <summary>Migrations known to the binaries but not yet applied, in apply order.</summary>
	[Key(24)]
	public List<string> PendingMigrations { get; set; } = new();

	/// <summary>True when the migration-failure marker file is present.</summary>
	[Key(25)]
	public bool MigrationFailureMarkerPresent { get; set; }

	/// <summary>UTC instant recorded in the migration-failure marker; null when absent.</summary>
	[Key(26)]
	public DateTime? MigrationFailureUtc { get; set; }

	/// <summary>Failure message recorded in the marker; null when absent. Never contains secrets.</summary>
	[Key(27)]
	public string? MigrationFailureMessage { get; set; }

	/// <summary>Migrations that were pending when the marker was written; empty when absent.</summary>
	[Key(28)]
	public List<string> MigrationFailurePendingMigrations { get; set; } = new();

	// ── Effective retention policy ──────────────────────────────────────────────

	/// <summary>True when the information-density retention policy is enabled.</summary>
	[Key(29)]
	public bool RetentionPolicyEnabled { get; set; }

	/// <summary>True when a legal hold is in force, which makes every pressure rule inert.</summary>
	[Key(30)]
	public bool LegalHold { get; set; }

	/// <summary>Effective database-family ceiling in bytes; <c>0</c> means the trigger is disabled.</summary>
	[Key(31)]
	public long MaxDatabaseBytes { get; set; }

	/// <summary>Effective <c>RawEvents</c> row ceiling; <c>0</c> means the trigger is disabled.</summary>
	[Key(32)]
	public long MaxRawEventRows { get; set; }

	/// <summary>Effective free-disk floor in bytes; <c>0</c> means the trigger is disabled.</summary>
	[Key(33)]
	public long MinFreeDiskBytes { get; set; }

	// ── Deletion ledger aggregate ───────────────────────────────────────────────

	/// <summary>Number of <c>EventDeletionLedger</c> rows; <c>-1</c> when the aggregate failed.</summary>
	[Key(34)]
	public long LedgerEntryCount { get; set; } = -1;

	/// <summary>Sum of <c>RowsDeleted</c> across the whole ledger; <c>-1</c> when the aggregate
	/// failed. This is the number of evidence rows removed by an audited rule.</summary>
	[Key(35)]
	public long LedgerRowsDeleted { get; set; } = -1;

	/// <summary>UTC instant of the newest ledger entry; null when the ledger is empty.</summary>
	[Key(36)]
	public DateTime? LedgerLastCreatedUtc { get; set; }

	// ── Sharding ────────────────────────────────────────────────────────────────

	/// <summary>True when per-IP shard writing is enabled.</summary>
	[Key(37)]
	public bool ShardingEnabled { get; set; }

	/// <summary>Number of <c>.rdpshard</c> files under the shard tree; <c>-1</c> when the tree could
	/// not be walked.</summary>
	[Key(38)]
	public long ShardCount { get; set; } = -1;

	/// <summary>Configured cap on the number of shard files.</summary>
	[Key(39)]
	public int MaxShardFiles { get; set; }

	// ── Partial-result markers ──────────────────────────────────────────────────

	/// <summary>True when at least one section timed out or failed, so the snapshot is incomplete.</summary>
	[Key(40)]
	public bool IsPartial { get; set; }

	/// <summary>Per-section outcome, in execution order.</summary>
	[Key(41)]
	public List<DatabaseOverviewSectionDto> Sections { get; set; } = new();

	/// <summary>One line per degraded section, for direct display.</summary>
	[Key(42)]
	public List<string> Warnings { get; set; } = new();

	/// <summary>Operator-facing summary; never carries secret material.</summary>
	[Key(43)]
	public string? Message { get; set; }

	// ── Database snapshots ──────────────────────────────────────────────────────

	/// <summary>True when the operator-facing snapshot surface is enabled
	/// (<c>Storage:Backup:Enabled</c>).</summary>
	[Key(44)]
	public bool BackupEnabled { get; set; }

	/// <summary>True when a snapshot is required before EF migrations are applied
	/// (<c>Storage:Backup:PreMigrationBackupEnabled</c>, on by default).</summary>
	[Key(45)]
	public bool PreMigrationBackupEnabled { get; set; }

	/// <summary>Absolute backup root the snapshot inventory was taken from.</summary>
	[Key(46)]
	public string BackupDirectory { get; set; } = string.Empty;

	/// <summary>Number of database snapshots currently present.</summary>
	[Key(47)]
	public int BackupSnapshotCount { get; set; } = -1;

	/// <summary>Effective number of database snapshots kept by retention.</summary>
	[Key(48)]
	public int BackupRetentionCopies { get; set; }

	/// <summary>UTC instant the newest snapshot was taken; null when there is none.</summary>
	[Key(49)]
	public DateTime? BackupLastCreatedUtc { get; set; }

	/// <summary>Absolute directory of the newest snapshot; null when there is none.</summary>
	[Key(50)]
	public string? BackupLastSnapshotDirectory { get; set; }

	/// <summary>SHA-256 recorded for the newest snapshot; null when there is none or its manifest is
	/// unreadable.</summary>
	[Key(51)]
	public string? BackupLastSnapshotSha256 { get; set; }

	/// <summary>Explains the snapshot section when it could not be read.</summary>
	[Key(52)]
	public string? BackupNote { get; set; }

	// ── Shard capacity state ────────────────────────────────────────────────────

	/// <summary>Live capacity state of the shard sink: why it is refusing new shard files, since when,
	/// how many sources that affected, and whether the byte budget or the disk floor is breached. Null
	/// when this host has no shard sink at all, which is an honest absence rather than a healthy
	/// default.</summary>
	[Key(53)]
	public ShardCapacityStatusDto? ShardCapacityStatus { get; set; }

	// ── Store integrity and tamper evidence (Stage 5) ───────────────────────────

	/// <summary>True when the deletion-ledger hash chain verified on the last inspection. Null means it was
	/// not inspected, which is not the same as a pass.</summary>
	[Key(54)]
	public bool? LedgerChainIntact { get; set; }

	/// <summary>Ledger entries that carry a chain link.</summary>
	[Key(55)]
	public long LedgerChainedRows { get; set; } = -1;

	/// <summary>Ledger entries written before the chain existed; they cannot be verified and are reported as
	/// such rather than counted as a break.</summary>
	[Key(56)]
	public long LedgerUnchainedRows { get; set; } = -1;

	/// <summary>Human-readable result of the ledger-chain verification.</summary>
	[Key(57)]
	public string? LedgerChainMessage { get; set; }

	/// <summary>When the clean-shutdown store fingerprint was captured, or null when the service has never
	/// stopped cleanly since the feature was enabled.</summary>
	[Key(58)]
	public DateTime? FingerprintCleanShutdownUtc { get; set; }

	/// <summary>When the last periodic store fingerprint was captured, or null.</summary>
	[Key(59)]
	public DateTime? FingerprintPeriodicUtc { get; set; }

	/// <summary>True when a store-integrity anomaly marker is present, i.e. the last start-up comparison
	/// found something an operator should read.</summary>
	[Key(60)]
	public bool IntegrityAnomalyMarkerPresent { get; set; }

	/// <summary>Detail of the anomaly marker's contents (best effort, truncated).</summary>
	[Key(61)]
	public string? IntegrityAnomalyDetail { get; set; }

	/// <summary>Outcome of the newest journaled quick check.</summary>
	[Key(62)]
	public DatabaseIntegrityCheckRowDto? LastQuickCheck { get; set; }

	/// <summary>Outcome of the newest journaled full integrity check, or null when one never ran (which is
	/// the default: the full check is opt-in).</summary>
	[Key(63)]
	public DatabaseIntegrityCheckRowDto? LastFullIntegrityCheck { get; set; }

	/// <summary>Outcome of the newest journaled foreign-key check.</summary>
	[Key(64)]
	public DatabaseIntegrityCheckRowDto? LastForeignKeyCheck { get; set; }

	/// <summary>Outcome of the newest journaled ledger-chain verification.</summary>
	[Key(65)]
	public DatabaseIntegrityCheckRowDto? LastLedgerChainCheck { get; set; }

	/// <summary>ACL compliance of the evidence tree: true when every inspected folder matches the storage
	/// policy, false when at least one does not, null when the assessment is unavailable (non-Windows) or
	/// nothing could be inspected.</summary>
	[Key(66)]
	public bool? StorageAclCompliant { get; set; }

	/// <summary>Per-folder ACL findings, so drift is shown where it is, not only as a boolean.</summary>
	[Key(67)]
	public string? StorageAclMessage { get; set; }

	/// <summary>The scheduled integrity-check cadence in force, for the operator to read back.</summary>
	[Key(68)]
	public string? IntegrityCadence { get; set; }

	/// <summary>The encryption-at-rest mode in force. Never a confirmation that data is encrypted unless the
	/// mode says so; <c>None</c> is the default and means the store is plain text.</summary>
	[Key(69)]
	public string? EncryptionMode { get; set; }

	/// <summary>State of the store-fingerprint CHAIN (B19): <c>ok</c>, <c>missing</c>, <c>unreadable</c>,
	/// <c>chain-broken</c> or <c>interrupted</c>. Reported separately from the fingerprint timestamps because
	/// "there is no baseline yet" and "entries that were recorded are gone" must never render the same way, and
	/// as of B24 neither must "a capture was cut short" (<c>interrupted</c>, corroborated by a durable write
	/// intent) render as "the chain was rolled back or replaced" (<c>chain-broken</c>).</summary>
	[Key(70)]
	public string? FingerprintChainState { get; set; }

	/// <summary>How many entries the readable chain holds. A count, not a guess: unreadable files are not
	/// counted here and are described in <see cref="FingerprintChainMessage"/>.</summary>
	[Key(71)]
	public int FingerprintChainEntryCount { get; set; }

	/// <summary>The chain verdict in full, including every finding behind a non-Ok state.</summary>
	[Key(72)]
	public string? FingerprintChainMessage { get; set; }

	/// <summary>Whether the key facts of the chain are mirrored outside the integrity folder (the Windows
	/// event-log sink). False means the sealed tip is the only second store; that is a limitation to show, not
	/// a failure.</summary>
	[Key(73)]
	public bool? FingerprintChainMirrorAvailable { get; set; }

	// ── Store page accounting and auto-vacuum mode (B16 / B27) ───────────────────

	/// <summary>The store's <c>PRAGMA auto_vacuum</c> mode: <c>0</c> NONE, <c>1</c> FULL, <c>2</c>
	/// INCREMENTAL. Null when it could not be read, which is reported as unknown rather than as a mode.
	/// Only <c>2</c> lets the online path release free pages at all - on <c>0</c> the bounded
	/// <c>PRAGMA incremental_vacuum</c> of the purge and the maintenance surface is a documented no-op, so a
	/// client must show this value next to any "reclaimed nothing" report.</summary>
	[Key(74)]
	public int? AutoVacuumMode { get; set; }

	/// <summary>The store's journal mode as reported by <c>PRAGMA journal_mode</c> (normally <c>wal</c>);
	/// null when it could not be read.</summary>
	[Key(75)]
	public string? JournalMode { get; set; }

	/// <summary>The store's page size in bytes; null when it could not be read.</summary>
	[Key(76)]
	public int? PageSize { get; set; }

	/// <summary>How many pages the store occupies; null when it could not be read.</summary>
	[Key(77)]
	public long? PageCount { get; set; }

	/// <summary>How many of those pages are free (inside the file, holding no row); null when it could not
	/// be read. This is the depth the online reclamation path tries to release.</summary>
	[Key(78)]
	public long? FreeListPages { get; set; }

	/// <summary><c>PageSize × FreeListPages</c>: the bytes currently allocated to free pages. A LOWER BOUND
	/// on what an offline compaction could return to the filesystem, not a promise - fragments inside
	/// partially used pages are not counted - and null whenever either factor is unknown.</summary>
	[Key(79)]
	public long? ReclaimableBytes { get; set; }

	/// <summary>What the two facts above mean together for THIS store: whether online space reclamation can
	/// work at all, and - when the mode is not INCREMENTAL and free pages are waiting inside the file - that
	/// only the offline compaction can return them. Null when the mode could not be read, because a sentence
	/// derived from an unknown mode would be a guess.</summary>
	[Key(80)]
	public string? SpaceReclamationNote { get; set; }

	// ── Ingest persistence pipeline ─────────────────────────────────────────────

	/// <summary>Batches the ingest worker kept in memory for retry after a failed persist, cumulative since
	/// the service started. Non-zero means the database refused a write and the worker kept the evidence
	/// instead of discarding it; while a batch is retained the worker stops draining, so the counter is the
	/// honest signal that a bookmark cannot have advanced past unwritten events. <c>-1</c> when the service
	/// reported no counter, which must render as unknown rather than as "nothing went wrong".</summary>
	[Key(81)]
	public long PersistBatchRetainedCount { get; set; } = -1;

	/// <summary>Retained batches that stayed unwritten past the stall threshold (ten minutes) and were
	/// escalated to the log and the operation journal. Does not imply data loss: the batch is still
	/// retried. <c>-1</c> when the service reported no counter.</summary>
	[Key(82)]
	public long PersistBatchStalledCount { get; set; } = -1;
}

/// <summary>One journaled integrity-check outcome, as shown in the Database-tab overview.</summary>
[MessagePackObject(keyAsPropertyName: false)]
public sealed class DatabaseIntegrityCheckRowDto
{
	/// <summary>Which check this row describes.</summary>
	[Key(0)]
	public string Kind { get; set; } = string.Empty;

	/// <summary>Ok | Warning | Failed. A Warning means the check ran but reported something, or could not run
	/// at all - it is never presented as a pass.</summary>
	[Key(1)]
	public string Outcome { get; set; } = string.Empty;

	/// <summary>When the check completed (UTC).</summary>
	[Key(2)]
	public DateTime CompletedUtc { get; set; }

	/// <summary>How long it took, in milliseconds.</summary>
	[Key(3)]
	public long DurationMs { get; set; }

	/// <summary>Who ran it: <c>Schedule</c> or <c>Operator:&lt;identity&gt;</c>.</summary>
	[Key(4)]
	public string InitiatedBy { get; set; } = string.Empty;

	/// <summary>What the check returned, truncated to the report budget.</summary>
	[Key(5)]
	public string Detail { get; set; } = string.Empty;
}
