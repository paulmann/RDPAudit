/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 2.0.0
// File   : BackupOptionsTests.cs
// Project: RdpAudit.Core.Tests (RdpAudit.Core.Tests)
// Purpose: Verifies the snapshot settings and their clamps: a hand-edited appsettings.json cannot set a
//          snapshot count that deletes the snapshot it just wrote, a negative free-space floor cannot
//          invert the space check, an empty backup directory resolves to the ProgramData backups folder
//          rather than to the working directory, and the two switches keep their documented defaults -
//          the operator surface off, the pre-migration snapshot on.
// Depends: RdpAudit.Core.Config.BackupOptions, RdpAudit.Core.Util.RdpAuditPaths, xUnit
// Extends: Add an assertion here when BackupOptions gains a bound.

using RdpAudit.Core.Config;
using Xunit;

namespace RdpAudit.Core.Tests;

/// <summary>Defaults and clamp tests for <see cref="BackupOptions"/>.</summary>
public sealed class BackupOptionsTests
{
	[Fact]
	public void Defaults_MatchTheDocumentedBehaviour()
	{
		BackupOptions options = new();

		Assert.False(options.Enabled);
		Assert.Equal(5, options.RetentionCopies);
		Assert.Equal(0L, options.MinFreeDiskBytesBeforeBackup);
		Assert.False(options.IncludeShards);
		Assert.True(options.PreMigrationBackupEnabled);
		Assert.Equal(string.Empty, options.BackupDirectory);
	}

	[Theory]
	[InlineData(0, BackupOptions.MinRetentionCopies)]
	[InlineData(-25, BackupOptions.MinRetentionCopies)]
	[InlineData(1, 1)]
	[InlineData(5, 5)]
	[InlineData(int.MaxValue, BackupOptions.MaxRetentionCopies)]
	public void ResolveRetentionCopies_ClampsToTheSupportedRange(int configured, int expected)
	{
		BackupOptions options = new() { RetentionCopies = configured };

		Assert.Equal(expected, options.ResolveRetentionCopies());
	}

	[Theory]
	[InlineData(0L, 0L)]
	[InlineData(-1L, 0L)]
	[InlineData(long.MinValue, 0L)]
	[InlineData(1024L, 1024L)]
	public void ResolveMinFreeDiskBytesBeforeBackup_ClampsToZeroOrAbove(long configured, long expected)
	{
		BackupOptions options = new() { MinFreeDiskBytesBeforeBackup = configured };

		Assert.Equal(expected, options.ResolveMinFreeDiskBytesBeforeBackup());
	}

	[Fact]
	public void ResolveBackupDirectory_UsesProgramDataBackupsWhenUnset()
	{
		BackupOptions options = new();
		string programData = Path.Combine(Path.DirectorySeparatorChar.ToString(), "ProgramData", "RdpAudit");

		string resolved = options.ResolveBackupDirectory(programData);

		Assert.Equal(Path.Combine(programData, RdpAuditKeys.BackupsFolder), resolved);
	}

	[Fact]
	public void ResolveBackupDirectory_HonoursAnExplicitDirectory()
	{
		BackupOptions options = new() { BackupDirectory = @"E:\EvidenceBackups" };
		string programData = Path.Combine(Path.DirectorySeparatorChar.ToString(), "ProgramData", "RdpAudit");

		Assert.Equal(@"E:\EvidenceBackups", options.ResolveBackupDirectory(programData));
	}

	[Fact]
	public void ResolveBackupDirectory_RejectsAnEmptyProgramDataRoot()
	{
		BackupOptions options = new();

		Assert.Throws<ArgumentException>(() => options.ResolveBackupDirectory(""));
	}

	[Fact]
	public void Describe_NamesEveryEffectiveSetting()
	{
		string described = new BackupOptions { Enabled = true, RetentionCopies = 3 }.Describe();

		Assert.Contains("Enabled=True", described, StringComparison.Ordinal);
		Assert.Contains("PreMigrationBackupEnabled=True", described, StringComparison.Ordinal);
		Assert.Contains("RetentionCopies=3", described, StringComparison.Ordinal);
		Assert.Contains("IncludeShards=False", described, StringComparison.Ordinal);
		Assert.Contains("(default: ProgramData\\Backups)", described, StringComparison.Ordinal);
	}

	/// <summary>Local mirror of the folder name so the test does not depend on the path helper's
	/// platform behaviour.</summary>
	private static class RdpAuditKeys
	{
		internal const string BackupsFolder = "Backups";
	}
}
