// File:    src/RdpAudit.Core/Config/StorageOptions.cs
// Module:  RdpAudit.Core.Config
// Purpose: Database location, retention windows, and log retention settings.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using RdpAudit.Core.Util;

namespace RdpAudit.Core.Config;

/// <summary>Database location, retention, and log retention settings.</summary>
public sealed class StorageOptions
{
	public string DatabasePath { get; set; } = string.Empty;

	public int EventRetentionDays { get; set; } = 365;

	public int LogRetentionDays { get; set; } = 90;

	public int AlertRetentionDays { get; set; } = 730;

	public string LogDirectory { get; set; } = string.Empty;

	/// <summary>Retention window for rows in <c>AbuseReports</c>.
	/// Defaults to 365 days. Minimum effective value enforced by the maintenance worker is 30.</summary>
	public int AbuseReportRetentionDays { get; set; } = 365;

	/// <summary>Retention window for expired / removed rows in <c>ActiveBlocks</c>.
	/// Only rows whose <c>Status</c> is <c>Removed</c> or whose <c>ExpiresUtc</c> is in the past
	/// and is older than this window are eligible for pruning. Active rules are never deleted.
	/// Defaults to 90 days. Minimum effective value enforced by the maintenance worker is 7.</summary>
	public int ActiveBlockRetentionDays { get; set; } = 90;

	/// <summary>Retention window for stale rows in <c>AttackStats</c>. Rows whose <c>LastSeenUtc</c>
	/// has not been updated within this window are eligible for pruning. Defaults to 180 days.
	/// Minimum effective value enforced by the maintenance worker is 14.</summary>
	public int AttackStatRetentionDays { get; set; } = 180;

	/// <summary>Retention window for <c>SessionIpCorrelations</c>. Rows whose <c>LastSeenUtc</c>
	/// has not been refreshed within this window are eligible for pruning. Defaults to 30 days.
	/// Minimum effective value enforced by the maintenance worker is 7.</summary>
	public int SessionIpCorrelationRetentionDays { get; set; } = 30;

	/// <summary>Retention window for <c>RdpConnectionFacts</c>. Rows whose <c>LastSeenUtc</c> has
	/// not been refreshed within this window are eligible for pruning. Defaults to 90 days.
	/// Minimum effective value enforced by the maintenance worker is 30.</summary>
	public int RdpConnectionFactRetentionDays { get; set; } = 90;

	/// <summary>Maximum number of rows deleted from a single retention pass per table.
	/// Keeps the writer lock short on very large databases. Defaults to 50000.</summary>
	public int MaintenanceBatchSize { get; set; } = 50000;

	/// <summary>Optional frequency-oriented decimation of raw event telemetry performed by the
	/// retention worker after ordinary pruning. Disabled by default.</summary>
	public DecimationOptions Decimation { get; set; } = new();

	/// <summary>Optional information-density retention: a pressure rule that reclaims space by deleting
	/// only the information-poor interior of the densest event codes, never anchors and never the
	/// protected tail, with every removed window recorded in <c>EventDeletionLedger</c>. Disabled by
	/// default, so an installation that does not set it keeps today's behaviour exactly.</summary>
	public RetentionPolicyOptions RetentionPolicy { get; set; } = new();

	/// <summary>Optional database snapshots: consistent online copies of the SQLite store with a
	/// SHA-256 manifest, bounded retention, and the mandatory snapshot taken before EF migrations are
	/// applied. The operator-facing surface is disabled by default; the pre-migration snapshot defaults
	/// to on because it protects the schema upgrade itself.</summary>
	public BackupOptions Backup { get; set; } = new();

	/// <summary>Scheduled integrity checks and the store fingerprint used to detect modification of the
	/// evidence store while the service was stopped. The fingerprint is cheap and on by default; the full
	/// integrity check is off by default because it reads the whole file.</summary>
	public StorageIntegrityOptions Integrity { get; set; } = new();

	/// <summary>Encryption at rest. Defaults to <c>None</c>, which is today's behaviour: the store, its WAL
	/// and the shard tree are plain files and the only encrypted material is the secret store. See
	/// docs/89-encryption-at-rest-decision.md for the decision record and the migration path.</summary>
	public StorageEncryptionOptions Encryption { get; set; } = new();

	/// <summary>Returns the configured database path or a sensible default under ProgramData.</summary>
	public string ResolveDatabasePath()
	{
		if (!string.IsNullOrWhiteSpace(DatabasePath))
		{
			return DatabasePath;
		}

		return RdpAuditPaths.Default.DatabasePath;
	}

	/// <summary>Returns the configured log directory or a sensible default under ProgramData.</summary>
	public string ResolveLogDirectory()
	{
		if (!string.IsNullOrWhiteSpace(LogDirectory))
		{
			return LogDirectory;
		}

		return RdpAuditPaths.Default.LogDirectory;
	}
}
