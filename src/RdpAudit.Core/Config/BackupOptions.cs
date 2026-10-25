/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 2.0.0
// File   : BackupOptions.cs
// Project: RdpAudit.Core (RdpAudit.Core.Config)
// Purpose: Settings for the database backup and restore feature: how many snapshots to keep, how
//          much free space must remain on the destination volume, whether the shard tree travels
//          with the database, and whether the schema initializer must take a snapshot before it
//          applies EF migrations. Every bound resolves through a clamped Resolve* helper so a
//          hand-edited appsettings.json can never widen a limit beyond the supported range.
// Depends: System.Globalization, RdpAuditPaths
// Extends: Add a new bound by adding its Resolve* clamp and the matching member to the options
//          template in AppSettingsTemplate.cs and DefaultAppSettings.cs.

using System.Globalization;
using RdpAudit.Core.Util;

namespace RdpAudit.Core.Config;

/// <summary>
/// Settings for database snapshots. <see cref="Enabled"/> gates the operator-facing surface (the
/// snapshot list, manual creation and snapshot retention); <see cref="PreMigrationBackupEnabled"/> is
/// deliberately independent of it, because a snapshot taken before a schema migration protects the
/// upgrade itself and defaults to on.
/// </summary>
public sealed class BackupOptions
{
	// ── Supported bounds ─────────────────────────────────────────────────────────

	/// <summary>Smallest effective snapshot count. Zero would mean "back up and immediately delete",
	/// which reads as a backup but provides no recovery point.</summary>
	public const int MinRetentionCopies = 1;

	/// <summary>Largest effective snapshot count. Bounds the disk the backup folder may occupy.</summary>
	public const int MaxRetentionCopies = 1_000;

	// ── Master switches ──────────────────────────────────────────────────────────

	/// <summary>Master switch for the database-snapshot surface (list, manual create, retention by
	/// count). Defaults to false so an installation that does not configure backups never grows a
	/// backup folder on its own. A pre-migration snapshot is governed by
	/// <see cref="PreMigrationBackupEnabled"/>, not by this switch.</summary>
	public bool Enabled { get; set; }

	/// <summary>Number of database snapshots kept under the backup root; older snapshots created by
	/// this feature are removed after a successful new snapshot. Defaults to 5; clamped to
	/// [1, 1000]. Snapshots of other scopes (settings / shadow policy) are never counted and never
	/// deleted by this retention.</summary>
	public int RetentionCopies { get; set; } = 5;

	/// <summary>Free-space floor in bytes that must remain on the destination volume after a snapshot
	/// has been written. Zero means "only require the snapshot's own size to fit". Defaults to 0.</summary>
	public long MinFreeDiskBytesBeforeBackup { get; set; }

	/// <summary>When true the snapshot also copies the shard tree (<c>actions\</c>) into the snapshot
	/// directory. Defaults to false: the shard tree can be far larger than the database and copying it
	/// is a best-effort file copy, not a transactional snapshot.</summary>
	public bool IncludeShards { get; set; }

	/// <summary>When true the schema initializer takes one snapshot before it applies pending EF
	/// migrations and refuses to migrate when that snapshot cannot be taken. Defaults to true: every
	/// schema upgrade must leave a restorable pre-upgrade state. Set to false only to migrate without a
	/// recovery point (for example when the volume cannot hold a second copy).</summary>
	public bool PreMigrationBackupEnabled { get; set; } = true;

	/// <summary>Backup root. An empty value resolves to <c>%ProgramData%\RdpAudit\Backups</c>, the same
	/// folder the settings snapshots use, so one snapshot directory can describe both scopes.</summary>
	public string BackupDirectory { get; set; } = string.Empty;

	// ── Clamped resolution ───────────────────────────────────────────────────────

	/// <summary>Returns <see cref="RetentionCopies"/> clamped to the supported range.</summary>
	public int ResolveRetentionCopies() => Math.Clamp(RetentionCopies, MinRetentionCopies, MaxRetentionCopies);

	/// <summary>Returns <see cref="MinFreeDiskBytesBeforeBackup"/> clamped to zero or above; zero means
	/// only the snapshot's own size must fit.</summary>
	public long ResolveMinFreeDiskBytesBeforeBackup() => Math.Max(0L, MinFreeDiskBytesBeforeBackup);

	/// <summary>Resolves the effective backup root: the configured directory, or the ProgramData
	/// backups folder when the setting is empty.</summary>
	public string ResolveBackupDirectory(string programDataRdpAudit)
	{
		ArgumentException.ThrowIfNullOrWhiteSpace(programDataRdpAudit);
		return string.IsNullOrWhiteSpace(BackupDirectory)
			? Path.Combine(programDataRdpAudit, RdpAuditPaths.BackupsFolderName)
			: BackupDirectory;
	}

	/// <summary>Human-readable summary of the effective settings for operator logs.</summary>
	public string Describe()
		=> string.Format(
			CultureInfo.InvariantCulture,
			"Enabled={0} PreMigrationBackupEnabled={1} RetentionCopies={2} MinFreeDiskBytesBeforeBackup={3} IncludeShards={4} BackupDirectory={5}",
			Enabled,
			PreMigrationBackupEnabled,
			ResolveRetentionCopies(),
			ResolveMinFreeDiskBytesBeforeBackup(),
			IncludeShards,
			string.IsNullOrWhiteSpace(BackupDirectory) ? "(default: ProgramData\\Backups)" : BackupDirectory);
}
