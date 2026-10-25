/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 2.0.0
// File   : DatabaseBackupLayoutTests.cs
// Project: RdpAudit.Core.Tests (RdpAudit.Core.Tests)
// Purpose: Verifies the path math of the database backup layout: the snapshot sits under
//          Backups\<yyyyMMdd-HHmmss>\db\rdpaudit.db with manifest.json beside the db\ folder, names
//          that are not snapshot timestamps are rejected, a second snapshot inside the same UTC second
//          gets a bounded collision suffix instead of overwriting the first, and a name that tries to
//          escape the backup root throws rather than resolving outside it.
// Depends: RdpAudit.Core.Backup.DatabaseBackupLayout, xUnit
// Extends: Add an assertion here when the snapshot layout gains an artifact.

using RdpAudit.Core.Backup;
using Xunit;

namespace RdpAudit.Core.Tests;

/// <summary>Pure-path tests for the database snapshot layout - no filesystem is touched.</summary>
public sealed class DatabaseBackupLayoutTests
{
	private static readonly string Root = Path.Combine(
		Path.DirectorySeparatorChar.ToString(),
		"ProgramData",
		"RdpAudit");

	[Fact]
	public void Create_BuildsSnapshotUnderBackupsFolderWithDatabaseAndManifest()
	{
		DateTime when = new(2026, 9, 14, 10, 30, 45, DateTimeKind.Utc);

		DatabaseSnapshotPaths paths = DatabaseBackupLayout.Create(Root, when);

		Assert.Equal("20260914-103045", paths.Timestamp);
		Assert.EndsWith(DatabaseBackupLayout.BackupsFolderName, paths.RootDirectory, StringComparison.Ordinal);
		Assert.Equal(
			Path.Combine(Path.GetFullPath(Root), DatabaseBackupLayout.BackupsFolderName, "20260914-103045"),
			paths.SnapshotDirectory);
		Assert.Equal(Path.Combine(paths.SnapshotDirectory, "db"), paths.DatabaseDirectory);
		Assert.Equal(Path.Combine(paths.SnapshotDirectory, "db", "rdpaudit.db"), paths.DatabasePath);
		Assert.Equal(Path.Combine(paths.SnapshotDirectory, "actions"), paths.ShardsDirectory);
		Assert.Equal(Path.Combine(paths.SnapshotDirectory, "manifest.json"), paths.ManifestPath);
	}

	[Fact]
	public void Create_RejectsNullOrEmptyProgramData()
	{
		Assert.Throws<ArgumentException>(() => DatabaseBackupLayout.Create("", DateTime.UtcNow));
		Assert.Throws<ArgumentException>(() => DatabaseBackupLayout.Create("   ", DateTime.UtcNow));
	}

	[Fact]
	public void Create_RejectsUnspecifiedDateTimeKind()
	{
		DateTime ambiguous = new(2026, 1, 1, 0, 0, 0, DateTimeKind.Unspecified);
		Assert.Throws<ArgumentException>(() => DatabaseBackupLayout.Create(Root, ambiguous));
	}

	[Fact]
	public void Create_ConvertsLocalTimeToUtcInTheDirectoryName()
	{
		DateTime local = new(2026, 9, 14, 12, 0, 0, DateTimeKind.Local);

		DatabaseSnapshotPaths paths = DatabaseBackupLayout.Create(Root, local);

		Assert.Equal(local.ToUniversalTime().ToString("yyyyMMdd-HHmmss", null), paths.Timestamp);
	}

	[Fact]
	public void ForTimestamp_RejectsNamesThatAreNotSnapshotTimestamps()
	{
		string backups = Path.Combine(Path.GetFullPath(Root), "Backups");

		Assert.Throws<ArgumentException>(() => DatabaseBackupLayout.ForTimestamp(backups, "not-a-timestamp"));
		Assert.Throws<ArgumentException>(() => DatabaseBackupLayout.ForTimestamp(backups, "2026-09-14-103045"));
		Assert.Throws<ArgumentException>(() => DatabaseBackupLayout.ForTimestamp(backups, "20260914-103045-100"));
	}

	[Fact]
	public void ForTimestamp_RejectsAPathTraversalAttemptInsteadOfEscapingTheRoot()
	{
		string backups = Path.Combine(Path.GetFullPath(Root), "Backups");

		Assert.Throws<ArgumentException>(() => DatabaseBackupLayout.ForTimestamp(backups, @"..\..\Windows\System32"));
	}

	[Theory]
	[InlineData("20260914-103045", true, 0)]
	[InlineData("20260914-103045-01", true, 1)]
	[InlineData("20260914-103045-99", true, 99)]
	[InlineData("20260914-103045-00", false, 0)]
	[InlineData("20260914-103045-100", false, 0)]
	[InlineData("20260914-103045.partial", false, 0)]
	[InlineData("20261314-103045", false, 0)]
	[InlineData("", false, 0)]
	public void TryParseTimestamp_AcceptsOnlySnapshotNames(string name, bool expected, int expectedIndex)
	{
		bool parsed = DatabaseBackupLayout.TryParseTimestamp(name, out _, out int index);

		Assert.Equal(expected, parsed);
		if (expected)
		{
			Assert.Equal(expectedIndex, index);
		}
	}

	[Fact]
	public void ResolveUniqueTimestamp_ReturnsTheBareNameWhenItIsFree()
	{
		string resolved = DatabaseBackupLayout.ResolveUniqueTimestamp(["20250101-000000"], "20260914-103045");

		Assert.Equal("20260914-103045", resolved);
	}

	[Fact]
	public void ResolveUniqueTimestamp_NeverOverwritesAnExistingSnapshot()
	{
		string resolved = DatabaseBackupLayout.ResolveUniqueTimestamp(
			["20260914-103045"],
			"20260914-103045");

		Assert.Equal("20260914-103045-01", resolved);
	}

	[Fact]
	public void ResolveUniqueTimestamp_SkipsEveryTakenSuffix()
	{
		string resolved = DatabaseBackupLayout.ResolveUniqueTimestamp(
			["20260914-103045", "20260914-103045-01", "20260914-103045-02"],
			"20260914-103045");

		Assert.Equal("20260914-103045-03", resolved);
	}

	[Fact]
	public void ResolveUniqueTimestamp_ThrowsRatherThanReusingANameWhenTheRangeIsExhausted()
	{
		List<string> existing = ["20260914-103045"];
		for (int index = 1; index <= DatabaseBackupLayout.MaxCollisionIndex; index++)
		{
			existing.Add("20260914-103045-" + index.ToString("00", null));
		}

		Assert.Throws<InvalidOperationException>(
			() => DatabaseBackupLayout.ResolveUniqueTimestamp(existing, "20260914-103045"));
	}

	[Fact]
	public void GetPartialDirectory_UsesTheSiblingPartialSuffix()
	{
		string backups = Path.Combine(Path.GetFullPath(Root), "Backups");

		string partial = DatabaseBackupLayout.GetPartialDirectory(backups, "20260914-103045");

		Assert.Equal(
			Path.Combine(backups, "20260914-103045") + DatabaseBackupLayout.PartialSuffix,
			partial);
		Assert.True(DatabaseBackupLayout.IsPartialDirectoryName(Path.GetFileName(partial)));
		Assert.False(DatabaseBackupLayout.IsPartialDirectoryName("20260914-103045"));
	}

	[Fact]
	public void SortNewestFirst_OrdersByTimestampThenByCollisionSuffix()
	{
		string[] names =
		{
			"20260301-120000",
			"20260914-103045",
			"20251231-235959",
			"20260914-103045-01",
			"not-a-snapshot",
		};

		IReadOnlyList<string> ordered = DatabaseBackupLayout.SortNewestFirst(names);

		Assert.Equal(
			["20260914-103045-01", "20260914-103045", "20260301-120000", "20251231-235959"],
			ordered);
	}
}
