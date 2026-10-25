/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 2.0.2
// File   : StorageBenchmarkMetric.cs
// Project: RdpAudit.Core (RdpAudit.Core.Diagnostics)
// Purpose: The stable vocabulary of the storage benchmark report. The probe that measures a quantity,
//          the recommendation engine that consumes it and the report writer that prints it must all
//          name it identically, so the identifiers live in one place instead of as string literals at
//          three call sites. Identifiers are lower snake case so they survive being used as JSON keys
//          and as table rows unchanged.
// Depends: System.Globalization
// Extends: Add a metric by adding its identifier here, measuring it in a probe and consuming it in
//          StorageTuningAdvisor; a metric no recommendation reads is still worth reporting.

namespace RdpAudit.Core.Diagnostics;

/// <summary>Identifiers of every quantity the storage benchmark can measure.</summary>
public static class StorageBenchmarkMetric
{
	// ── Store creation and fill ──────────────────────────────────────────────────

	/// <summary>Rows written per second while the synthetic store is filled.</summary>
	public const string SeedRowsPerSecond = "seed.rows_per_second";

	/// <summary>Seconds to write one 100 000-row chunk. Measured per chunk, so the report can state
	/// what 100k rows actually cost on this machine instead of extrapolating it.</summary>
	public const string SeedSecondsPer100kRows = "seed.seconds_per_100k_rows";

	/// <summary>Seconds to write a million rows. Only measured when the run actually wrote a million
	/// rows; extrapolating it would be an estimate, not a measurement.</summary>
	public const string SeedSecondsPerMillionRows = "seed.seconds_per_million_rows";

	/// <summary>Length of the main database file after the seed.</summary>
	public const string SeedStoreBytes = "seed.store_bytes";

	/// <summary>Combined length of the database file, its write-ahead log and its shared-memory file.</summary>
	public const string SeedStoreFamilyBytes = "seed.store_family_bytes";

	// ── Information-density retention ────────────────────────────────────────────

	/// <summary>Rows removed per second by a real retention pass.</summary>
	public const string RetentionRowsPerSecond = "retention.rows_per_second";

	/// <summary>Bytes released to the SQLite freelist by a real retention pass.</summary>
	public const string RetentionReclaimedBytes = "retention.reclaimed_bytes";

	/// <summary>Freelist bytes released per second by a real retention pass.</summary>
	public const string RetentionReclaimedBytesPerSecond = "retention.reclaimed_bytes_per_second";

	/// <summary>Committed delete-plus-ledger batches in one pass.</summary>
	public const string RetentionBatches = "retention.batches";

	/// <summary>Writer-lock hold of one committed batch, in milliseconds.</summary>
	public const string RetentionBatchLockMs = "retention.batch_lock_ms";

	/// <summary>Rows per batch the writer-lock metric was measured at, so a per-row cost can be derived
	/// from it and so the report states the batch size the measurement describes.</summary>
	public const string RetentionBatchRows = "retention.batch_rows";

	/// <summary>Wall-clock duration of one retention pass.</summary>
	public const string RetentionPassSeconds = "retention.pass_seconds";

	/// <summary>Rows the planner intended to remove in the pass it ran.</summary>
	public const string RetentionPlannedRows = "retention.planned_rows";

	/// <summary>Main-file length before the retention pass.</summary>
	public const string RetentionStoreBytesBefore = "retention.store_bytes_before";

	/// <summary>Main-file length after the retention pass.</summary>
	public const string RetentionStoreBytesAfter = "retention.store_bytes_after";

	/// <summary>Latency of the dry-run (preview) evaluation over the same state.</summary>
	public const string RetentionPreviewSeconds = "retention.preview_seconds";

	/// <summary>Rows the dry run said it would remove.</summary>
	public const string RetentionPreviewPlannedRows = "retention.preview_planned_rows";

	/// <summary>Rows actually removed divided by the rows the dry run predicted. One means the dry run
	/// predicted the pass exactly.</summary>
	public const string RetentionPreviewVolumeRatio = "retention.preview_volume_ratio";

	// ── Deletion ledger ─────────────────────────────────────────────────────────

	/// <summary>Chained ledger entries appended per second.</summary>
	public const string LedgerEntriesPerSecond = "ledger.entries_per_second";

	/// <summary>Append latency of one chained ledger entry.</summary>
	public const string LedgerAppendMs = "ledger.append_ms";

	// ── Snapshot and verification ────────────────────────────────────────────────

	/// <summary>Duration of one database snapshot.</summary>
	public const string BackupSnapshotSeconds = "backup.snapshot_seconds";

	/// <summary>Bytes of the copied database inside the snapshot.</summary>
	public const string BackupSnapshotBytes = "backup.snapshot_bytes";

	/// <summary>Snapshot throughput in mebibytes per second.</summary>
	public const string BackupSnapshotMebibytesPerSecond = "backup.snapshot_mebibytes_per_second";

	/// <summary>Duration of verifying the snapshot (hash, quick_check, migration and row-count compare).</summary>
	public const string BackupVerifySeconds = "backup.verify_seconds";

	/// <summary>Shard files copied into a snapshot taken with shards included.</summary>
	public const string BackupShardFiles = "backup.shard_files";

	/// <summary>Bytes of shard data copied into a snapshot taken with shards included.</summary>
	public const string BackupShardBytes = "backup.shard_bytes";

	/// <summary>Duration of a snapshot taken with shards included.</summary>
	public const string BackupShardSnapshotSeconds = "backup.shard_snapshot_seconds";

	/// <summary>Throughput of a snapshot taken with shards included.</summary>
	public const string BackupShardSnapshotMebibytesPerSecond = "backup.shard_snapshot_mebibytes_per_second";

	// ── Maintenance ─────────────────────────────────────────────────────────────

	/// <summary>Duration of <c>PRAGMA quick_check</c> on the measured store.</summary>
	public const string IntegrityQuickCheckSeconds = "integrity.quick_check_seconds";

	/// <summary>Duration of <c>PRAGMA integrity_check</c> on the measured store.</summary>
	public const string IntegrityFullCheckSeconds = "integrity.full_check_seconds";

	/// <summary>Duration of <c>PRAGMA foreign_key_check</c> on the measured store.</summary>
	public const string IntegrityForeignKeyCheckSeconds = "integrity.foreign_key_check_seconds";

	/// <summary>Duration of a <c>PRAGMA wal_checkpoint(TRUNCATE)</c>.</summary>
	public const string CheckpointTruncateSeconds = "checkpoint.truncate_seconds";

	/// <summary>Duration of a bounded <c>PRAGMA incremental_vacuum(N)</c>.</summary>
	public const string VacuumIncrementalSeconds = "vacuum.incremental_seconds";

	/// <summary>Freelist pages the incremental vacuum was asked to release.</summary>
	public const string VacuumIncrementalPages = "vacuum.incremental_pages";

	/// <summary>Duration of an offline compaction (VACUUM INTO plus the validated swap) on a copy.</summary>
	public const string CompactionSeconds = "compaction.seconds";

	/// <summary>Main-file length before the offline compaction.</summary>
	public const string CompactionBytesBefore = "compaction.bytes_before";

	/// <summary>Main-file length after the offline compaction.</summary>
	public const string CompactionBytesAfter = "compaction.bytes_after";

	/// <summary>Bytes the offline compaction removed.</summary>
	public const string CompactionBytesReclaimed = "compaction.bytes_reclaimed";

	/// <summary>One when the compaction reported success, zero otherwise.</summary>
	public const string CompactionSucceeded = "compaction.succeeded";

	// ── Store volume ────────────────────────────────────────────────────────────

	/// <summary>Latency of one small write followed by a flush to disk.</summary>
	public const string VolumeWriteLatencyMs = "volume.write_latency_ms";

	/// <summary>Flushed small writes per second.</summary>
	public const string VolumeWriteIops = "volume.write_iops";

	/// <summary>Free bytes on the volume hosting the store.</summary>
	public const string VolumeFreeBytes = "volume.free_bytes";

	/// <summary>Total bytes of the volume hosting the store.</summary>
	public const string VolumeTotalBytes = "volume.total_bytes";

	/// <summary>True when the metric identifier is a volume metric (used by the advisor to decide
	/// whether a measurement describes the store volume or the store itself).</summary>
	public static bool IsVolumeMetric(string metric)
	{
		ArgumentNullException.ThrowIfNull(metric);
		return metric.StartsWith("volume.", StringComparison.Ordinal);
	}
}
