/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 2.0.0
// File   : DatabaseBackupLayout.cs
// Project: RdpAudit.Core (RdpAudit.Core.Backup)
// Purpose: Pure path math for the database backup snapshot layout. A database snapshot lives in
//          %ProgramData%\RdpAudit\Backups\<yyyyMMdd-HHmmss>\db\rdpaudit.db with a manifest.json
//          beside the db\ folder, so a snapshot directory can carry the settings scope (the
//          pre-existing BackupLayout: appsettings.json + metadata.json) and the database scope at
//          the same time. This class performs no I/O at all: it is the testable half of the backup
//          feature, and the service owns every read, write and delete. Timestamps are UTC and
//          second-resolution; a second snapshot inside the same second gets a bounded -NN suffix so
//          two backups can never overwrite each other.
// Depends: System.Globalization, PathSafety, BackupLayout, RdpAuditPaths
// Extends: Add a new artifact of the database scope by adding its file name constant and its path
//          to DatabaseSnapshotPaths; never compute a snapshot path by hand outside this class.

using System.Globalization;
using RdpAudit.Core.Util;

namespace RdpAudit.Core.Backup;

/// <summary>Absolute paths of one database backup snapshot. Never constructed outside
/// <see cref="DatabaseBackupLayout"/> so a caller cannot invent a layout the retention logic does
/// not recognise.</summary>
public sealed record DatabaseSnapshotPaths(
	string RootDirectory,
	string Timestamp,
	string SnapshotDirectory,
	string DatabaseDirectory,
	string DatabasePath,
	string ShardsDirectory,
	string ManifestPath);

/// <summary>Pure path math for the database backup layout. No I/O is performed here.</summary>
public static class DatabaseBackupLayout
{
	/// <summary>Snapshot root folder under the RdpAudit ProgramData directory. Mirrors
	/// <see cref="RdpAuditPaths.BackupsFolderName"/> (single source of truth) and is deliberately the
	/// same folder the settings snapshots use, so one snapshot directory can describe both scopes.</summary>
	public const string BackupsFolderName = RdpAuditPaths.BackupsFolderName;

	/// <summary>Sub-folder holding the database copy inside a snapshot.</summary>
	public const string DatabaseFolderName = "db";

	/// <summary>File name of the database copy. Mirrors <see cref="RdpAuditPaths.DatabaseFileName"/>.</summary>
	public const string DatabaseFileName = RdpAuditPaths.DatabaseFileName;

	/// <summary>Sub-folder holding the optional shard-tree copy inside a snapshot. Mirrors
	/// <see cref="RdpAuditPaths.ActionsRootFolderName"/>.</summary>
	public const string ShardsFolderName = RdpAuditPaths.ActionsRootFolderName;

	/// <summary>Name of the manifest describing the database scope of a snapshot.</summary>
	public const string ManifestFileName = "manifest.json";

	/// <summary>Suffix of the working directory a snapshot is assembled in before it is renamed into
	/// its final timestamped name. A directory carrying this suffix is never a valid snapshot.</summary>
	public const string PartialSuffix = ".partial";

	/// <summary>Snapshot directory timestamp format — UTC, sortable, second resolution. Mirrors
	/// <see cref="BackupLayout.TimestampFormat"/> so both scopes name their directories identically.</summary>
	public const string TimestampFormat = BackupLayout.TimestampFormat;

	/// <summary>Length of the bare <c>yyyyMMdd-HHmmss</c> timestamp.</summary>
	public const int TimestampLength = 15;

	/// <summary>Largest collision index used when two snapshots land in the same UTC second. The
	/// bound keeps the suffix two digits wide so string ordering stays meaningful.</summary>
	public const int MaxCollisionIndex = 99;

	/// <summary>Resolves the snapshot root under a ProgramData directory.</summary>
	public static string ResolveBackupsRoot(string programDataRdpAudit)
	{
		ArgumentException.ThrowIfNullOrWhiteSpace(programDataRdpAudit);
		return Path.Combine(Path.GetFullPath(programDataRdpAudit), BackupsFolderName);
	}

	/// <summary>Builds the snapshot paths for the supplied UTC instant under the ProgramData root,
	/// using the bare timestamp (no collision suffix). Callers that must not overwrite an existing
	/// snapshot resolve the name through <see cref="ResolveUniqueTimestamp"/> first and then call
	/// <see cref="ForTimestamp"/>.</summary>
	public static DatabaseSnapshotPaths Create(string programDataRdpAudit, DateTime utcNow)
	{
		ArgumentException.ThrowIfNullOrWhiteSpace(programDataRdpAudit);
		if (utcNow.Kind == DateTimeKind.Unspecified)
		{
			throw new ArgumentException("DateTimeKind must be Utc or Local", nameof(utcNow));
		}

		string timestamp = utcNow.ToUniversalTime().ToString(TimestampFormat, CultureInfo.InvariantCulture);
		return ForTimestamp(ResolveBackupsRoot(programDataRdpAudit), timestamp);
	}

	/// <summary>Builds the snapshot paths for an already-formatted snapshot name under the given
	/// BackupLayout-compatible root. The name is validated and combined through
	/// <see cref="PathSafety.SafeChildPath"/>, so a traversal attempt throws rather than escaping.</summary>
	public static DatabaseSnapshotPaths ForTimestamp(string backupsRoot, string timestamp)
	{
		ArgumentException.ThrowIfNullOrWhiteSpace(backupsRoot);
		ArgumentException.ThrowIfNullOrWhiteSpace(timestamp);

		string root = Path.GetFullPath(backupsRoot);
		if (!TryParseTimestamp(timestamp, out _, out _))
		{
			throw new ArgumentException(
				string.Format(
					CultureInfo.InvariantCulture,
					"'{0}' is not a valid {1} snapshot name.",
					timestamp,
					TimestampFormat),
				nameof(timestamp));
		}

		string snapshot = PathSafety.SafeChildPath(root, timestamp);
		string databaseDirectory = PathSafety.SafeChildPath(snapshot, DatabaseFolderName);
		return new DatabaseSnapshotPaths(
			RootDirectory: root,
			Timestamp: timestamp,
			SnapshotDirectory: snapshot,
			DatabaseDirectory: databaseDirectory,
			DatabasePath: Path.Combine(databaseDirectory, DatabaseFileName),
			ShardsDirectory: PathSafety.SafeChildPath(snapshot, ShardsFolderName),
			ManifestPath: Path.Combine(snapshot, ManifestFileName));
	}

	/// <summary>Directory a snapshot is assembled in before the atomic rename into
	/// <see cref="DatabaseSnapshotPaths.SnapshotDirectory"/>.</summary>
	public static string GetPartialDirectory(string backupsRoot, string timestamp)
	{
		DatabaseSnapshotPaths paths = ForTimestamp(backupsRoot, timestamp);
		return paths.SnapshotDirectory + PartialSuffix;
	}

	/// <summary>True when a directory name is a working directory that was never completed.</summary>
	public static bool IsPartialDirectoryName(string name)
		=> !string.IsNullOrWhiteSpace(name) && name.EndsWith(PartialSuffix, StringComparison.Ordinal);

	/// <summary>
	/// Parses a snapshot directory name: either the bare <c>yyyyMMdd-HHmmss</c> timestamp or that
	/// timestamp with a <c>-NN</c> collision suffix. Returns false for anything else, including a
	/// settings-snapshot directory name that happens to live in the same root (those are also bare
	/// timestamps, so this method cannot and does not try to distinguish scopes — the manifest does).
	/// </summary>
	public static bool TryParseTimestamp(string? snapshotName, out DateTime utc, out int collisionIndex)
	{
		utc = default;
		collisionIndex = 0;
		if (string.IsNullOrWhiteSpace(snapshotName))
		{
			return false;
		}

		string name = snapshotName.Trim();
		string stamp;
		if (name.Length == TimestampLength)
		{
			stamp = name;
		}
		else if (name.Length == TimestampLength + 3 && name[TimestampLength] == '-')
		{
			stamp = name[..TimestampLength];
			if (!int.TryParse(name.AsSpan(TimestampLength + 1), NumberStyles.None, CultureInfo.InvariantCulture, out int index)
				|| index < 1
				|| index > MaxCollisionIndex)
			{
				return false;
			}

			collisionIndex = index;
		}
		else
		{
			return false;
		}

		return DateTime.TryParseExact(
			stamp,
			TimestampFormat,
			CultureInfo.InvariantCulture,
			DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal,
			out utc);
	}

	/// <summary>
	/// Picks the snapshot name to use for <paramref name="timestamp"/> given the names already
	/// present in the root. Pure: the caller supplies the directory listing. The first free name wins,
	/// so an existing snapshot is never overwritten; running out of the bounded suffix range throws
	/// instead of silently replacing evidence.
	/// </summary>
	public static string ResolveUniqueTimestamp(IEnumerable<string> existingNames, string timestamp)
	{
		ArgumentNullException.ThrowIfNull(existingNames);
		ArgumentException.ThrowIfNullOrWhiteSpace(timestamp);
		if (!TryParseTimestamp(timestamp, out _, out _))
		{
			throw new ArgumentException(
				string.Format(
					CultureInfo.InvariantCulture,
					"'{0}' is not a valid {1} snapshot name.",
					timestamp,
					TimestampFormat),
				nameof(timestamp));
		}

		HashSet<string> taken = new(StringComparer.OrdinalIgnoreCase);
		foreach (string name in existingNames)
		{
			if (!string.IsNullOrWhiteSpace(name))
			{
				taken.Add(name);
			}
		}

		if (!taken.Contains(timestamp))
		{
			return timestamp;
		}

		for (int index = 1; index <= MaxCollisionIndex; index++)
		{
			string candidate = timestamp + "-" + index.ToString("00", CultureInfo.InvariantCulture);
			if (!taken.Contains(candidate))
			{
				return candidate;
			}
		}

		throw new InvalidOperationException(
			string.Format(
				CultureInfo.InvariantCulture,
				"More than {0} snapshots share the UTC second {1}; refusing to overwrite one. Remove old snapshots or wait one second.",
				MaxCollisionIndex,
				timestamp));
	}

	/// <summary>Orders snapshot names newest first. Names that are not snapshot timestamps are
	/// dropped, and the collision suffix breaks a tie inside one second (highest suffix = newest).</summary>
	public static IReadOnlyList<string> SortNewestFirst(IEnumerable<string> snapshotNames)
	{
		ArgumentNullException.ThrowIfNull(snapshotNames);
		List<(string Name, DateTime Utc, int Index)> parsed = [];
		foreach (string name in snapshotNames)
		{
			if (TryParseTimestamp(name, out DateTime utc, out int index))
			{
				parsed.Add((name, utc, index));
			}
		}

		parsed.Sort(static (left, right) =>
		{
			int byTime = right.Utc.CompareTo(left.Utc);
			if (byTime != 0)
			{
				return byTime;
			}

			int byIndex = right.Index.CompareTo(left.Index);
			return byIndex != 0 ? byIndex : string.CompareOrdinal(right.Name, left.Name);
		});

		List<string> ordered = new(parsed.Count);
		foreach ((string name, _, _) in parsed)
		{
			ordered.Add(name);
		}

		return ordered;
	}
}
