// File:    src/RdpAudit.Core/Backup/BackupLayout.cs
// Module:  RdpAudit.Core.Backup
// Purpose: Pure path math for the backup directory layout used by RdpAudit when
//          the Configurator captures or restores settings, audit policy, SACL
//          state and service configuration. No I/O; intentionally Windows-API
//          free so it is testable on Linux/macOS CI.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System.Globalization;
using RdpAudit.Core.Util;

namespace RdpAudit.Core.Backup;

/// <summary>Describes one backup snapshot directory rooted under ProgramData.
/// The registry export uses a sub-folder rather than a single file because
/// reg.exe writes one .reg file per key.</summary>
public sealed record BackupSnapshotPaths(
	string RootDirectory,
	string Timestamp,
	string SnapshotDirectory,
	string AppSettingsPath,
	string AuditPolicyCsvPath,
	string RegistryDirectory,
	string ServiceConfigPath,
	string MetadataPath);

/// <summary>Pure path math for the backup directory layout used by the Configurator.
/// No I/O is performed here; all filesystem work lives in the Configurator backup runner.</summary>
public static class BackupLayout
{
	/// <summary>Subdirectory under <c>%ProgramData%\RdpAudit</c> that holds every snapshot.</summary>
	public const string BackupsFolderName = "Backups";

	/// <summary>Canonical name of the appsettings.json copy inside a snapshot.</summary>
	public const string AppSettingsFileName = "appsettings.json";

	/// <summary>Audit policy CSV export (one row per subcategory).</summary>
	public const string AuditPolicyFileName = "audit-policy.csv";

	/// <summary>Subdirectory holding one .reg file per captured registry key.</summary>
	public const string RegistryFolderName = "registry";

	/// <summary>Service configuration captured via <c>sc.exe qc</c>.</summary>
	public const string ServiceConfigFileName = "service.config.txt";

	/// <summary>Metadata describing machine, user, time and product version.</summary>
	public const string MetadataFileName = "metadata.json";

	/// <summary>Format used for timestamped snapshot directory names — UTC, sortable.</summary>
	public const string TimestampFormat = "yyyyMMdd-HHmmss";

	/// <summary>Builds the snapshot path under the given ProgramData root for the supplied UTC instant.</summary>
	public static BackupSnapshotPaths Create(string programDataRdpAudit, DateTime utcNow)
	{
		ArgumentException.ThrowIfNullOrWhiteSpace(programDataRdpAudit);
		if (utcNow.Kind == DateTimeKind.Unspecified)
		{
			throw new ArgumentException("DateTimeKind must be Utc or Local", nameof(utcNow));
		}

		string root = Path.Combine(programDataRdpAudit, BackupsFolderName);
		string stamp = utcNow.ToUniversalTime().ToString(TimestampFormat, CultureInfo.InvariantCulture);
		string snapshot = PathSafety.SafeChildPath(root, stamp);
		return new BackupSnapshotPaths(
			RootDirectory: root,
			Timestamp: stamp,
			SnapshotDirectory: snapshot,
			AppSettingsPath: Path.Combine(snapshot, AppSettingsFileName),
			AuditPolicyCsvPath: Path.Combine(snapshot, AuditPolicyFileName),
			RegistryDirectory: Path.Combine(snapshot, RegistryFolderName),
			ServiceConfigPath: Path.Combine(snapshot, ServiceConfigFileName),
			MetadataPath: Path.Combine(snapshot, MetadataFileName));
	}

	/// <summary>Enumerates already-created snapshot directory names, newest first.
	/// Pure helper — caller does directory enumeration and passes the candidate list.</summary>
	public static IReadOnlyList<string> SortNewestFirst(IEnumerable<string> snapshotNames)
	{
		ArgumentNullException.ThrowIfNull(snapshotNames);
		List<string> ordered = snapshotNames
			.Where(name => !string.IsNullOrWhiteSpace(name)
				&& DateTime.TryParseExact(
					name,
					TimestampFormat,
					CultureInfo.InvariantCulture,
					DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal,
					out _))
			.OrderByDescending(name => name, StringComparer.Ordinal)
			.ToList();
		return ordered;
	}
}
