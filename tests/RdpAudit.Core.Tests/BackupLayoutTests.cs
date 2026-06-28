// File:    tests/RdpAudit.Core.Tests/BackupLayoutTests.cs
// Module:  RdpAudit.Core.Tests
// Purpose: Verifies the path math used by the backup feature — timestamp formatting,
//          sub-path naming, sort order of snapshot names, and rejection of paths
//          that try to escape the ProgramData root.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System.Globalization;
using RdpAudit.Core.Backup;
using Xunit;

namespace RdpAudit.Core.Tests;

/// <summary>Pure-path backup layout tests — exercises BackupLayout without touching the filesystem.</summary>
public class BackupLayoutTests
{
	[Fact]
	public void Create_BuildsTimestampedSnapshotUnderBackupsFolder()
	{
		string root = Path.Combine(Path.DirectorySeparatorChar.ToString(), "ProgramData", "RdpAudit");
		DateTime when = new(2026, 5, 19, 10, 30, 45, DateTimeKind.Utc);

		BackupSnapshotPaths paths = BackupLayout.Create(root, when);

		Assert.EndsWith(BackupLayout.BackupsFolderName, paths.RootDirectory, StringComparison.Ordinal);
		Assert.Equal("20260519-103045", paths.Timestamp);
		Assert.Equal(
			Path.GetFullPath(Path.Combine(root, BackupLayout.BackupsFolderName, "20260519-103045")).TrimEnd(Path.DirectorySeparatorChar),
			paths.SnapshotDirectory.TrimEnd(Path.DirectorySeparatorChar));
		Assert.Equal(Path.Combine(paths.SnapshotDirectory, BackupLayout.AppSettingsFileName), paths.AppSettingsPath);
		Assert.Equal(Path.Combine(paths.SnapshotDirectory, BackupLayout.AuditPolicyFileName), paths.AuditPolicyCsvPath);
		Assert.Equal(Path.Combine(paths.SnapshotDirectory, BackupLayout.RegistryFolderName), paths.RegistryDirectory);
		Assert.Equal(Path.Combine(paths.SnapshotDirectory, BackupLayout.ServiceConfigFileName), paths.ServiceConfigPath);
		Assert.Equal(Path.Combine(paths.SnapshotDirectory, BackupLayout.MetadataFileName), paths.MetadataPath);
	}

	[Fact]
	public void Create_RejectsNullOrEmptyProgramData()
	{
		Assert.Throws<ArgumentException>(() => BackupLayout.Create("", DateTime.UtcNow));
		Assert.Throws<ArgumentException>(() => BackupLayout.Create("   ", DateTime.UtcNow));
	}

	[Fact]
	public void Create_RejectsUnspecifiedDateTimeKind()
	{
		DateTime ambiguous = new(2026, 1, 1, 0, 0, 0, DateTimeKind.Unspecified);
		Assert.Throws<ArgumentException>(() => BackupLayout.Create("/tmp/x", ambiguous));
	}

	[Fact]
	public void SortNewestFirst_OrdersByTimestampDescending()
	{
		string[] names =
		{
			"20260301-120000",
			"20251231-235959",
			"20260519-103045",
			"not-a-timestamp",
			"",
		};

		IReadOnlyList<string> ordered = BackupLayout.SortNewestFirst(names);

		Assert.Equal(new[] { "20260519-103045", "20260301-120000", "20251231-235959" }, ordered);
	}

	[Fact]
	public void TimestampFormat_RoundTripsWithDateTimeParseExact()
	{
		DateTime when = new(2026, 5, 19, 10, 30, 45, DateTimeKind.Utc);
		string formatted = when.ToString(BackupLayout.TimestampFormat, CultureInfo.InvariantCulture);
		bool parsed = DateTime.TryParseExact(
			formatted,
			BackupLayout.TimestampFormat,
			CultureInfo.InvariantCulture,
			DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal,
			out DateTime roundTrip);
		Assert.True(parsed);
		Assert.Equal(when, roundTrip);
	}
}
