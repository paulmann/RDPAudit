// File:    tests/RdpAudit.Core.Tests/RdpAuditPathsTests.cs
// Module:  RdpAudit.Core.Tests
// Purpose: Locks the D2 single-source-of-truth path layout. RdpAuditPaths must resolve every
//          canonical runtime path under an explicit root (a temp folder in tests) so the test
//          suite never constructs, creates or inspects the real %ProgramData%\RdpAudit tree.
//          Also pins DiagnosticLogRotation: append-restart on the size cap, exact newline
//          handling, and directory auto-create. No test here may touch the machine's
//          CommonApplicationData folder.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using RdpAudit.Core.Util;
using Xunit;

namespace RdpAudit.Core.Tests;

/// <summary>D2 path-layout and rotation contract tests.</summary>
public class RdpAuditPathsTests : IDisposable
{
	private readonly string _root;

	public RdpAuditPathsTests()
	{
		_root = Path.Combine(Path.GetTempPath(), "rdpaudit-paths-tests-" + Guid.NewGuid().ToString("N"));
	}

	public void Dispose()
	{
		try
		{
			if (Directory.Exists(_root))
			{
				Directory.Delete(_root, recursive: true);
			}
		}
		catch
		{
			// Best-effort cleanup; test temp folders must never outlive the run as a hard gate.
		}
	}

	[Fact]
	public void Ctor_ResolvesFullCanonicalRoot()
	{
		RdpAuditPaths paths = new(_root);
		Assert.Equal(Path.GetFullPath(_root), paths.ProgramDataDirectory);
	}

	[Fact]
	public void Ctor_NullOrBlank_Throws()
	{
		Assert.Throws<ArgumentNullException>(() => new RdpAuditPaths(null!));
		Assert.Throws<ArgumentException>(() => new RdpAuditPaths(""));
		Assert.Throws<ArgumentException>(() => new RdpAuditPaths("   "));
	}

	[Fact]
	public void Layout_EveryPathSitsUnderRoot()
	{
		RdpAuditPaths paths = new(_root);
		string root = Path.GetFullPath(_root);

		Assert.Equal(root, paths.ProgramDataDirectory);
		Assert.Equal(Path.Combine(root, RdpAuditPaths.LogsFolderName), paths.LogDirectory);
		Assert.Equal(Path.Combine(root, RdpAuditPaths.CrashFolderName), paths.CrashDirectory);
		Assert.Equal(Path.Combine(root, RdpAuditPaths.BackupsFolderName), paths.BackupsDirectory);
		Assert.Equal(Path.Combine(root, RdpAuditPaths.ActionsRootFolderName), paths.ActionsRootDirectory);
		Assert.Equal(Path.Combine(root, RdpAuditPaths.AppSettingsFileName), paths.AppSettingsPath);
		Assert.Equal(Path.Combine(root, RdpAuditPaths.DatabaseFileName), paths.DatabasePath);
		Assert.Equal(Path.Combine(root, RdpAuditPaths.LogsFolderName, RdpAuditPaths.ServiceLogFilePrefix), paths.ServiceLogPrefix);
		Assert.Equal(Path.Combine(root, RdpAuditPaths.LogsFolderName, RdpAuditPaths.DebugLogFileName), paths.DebugLogPath);
		Assert.Equal(Path.Combine(root, RdpAuditPaths.LogsFolderName, RdpAuditPaths.IpcStartupLogFileName), paths.IpcStartupLogPath);
		Assert.Equal(Path.Combine(root, RdpAuditPaths.LogsFolderName, RdpAuditPaths.StartupSequenceLogFileName), paths.StartupSequenceLogPath);
		Assert.Equal(Path.Combine(root, RdpAuditPaths.CrashFolderName, RdpAuditPaths.CrashReportFileName), paths.CrashReportPath);
		Assert.Equal(Path.Combine(root, RdpAuditPaths.MigrationFailureMarkerFileName), paths.MigrationFailureMarkerPath);
	}

	[Fact]
	public void Construction_DoesNotCreateDirectories()
	{
		_ = new RdpAuditPaths(_root);
		Assert.False(Directory.Exists(_root), "RdpAuditPaths construction must be side-effect free.");
	}

	[Fact]
	public void DefaultProvider_ExposesDefaultInstance()
	{
		IRdpAuditPathsProvider provider = new DefaultRdpAuditPathsProvider();
		Assert.Same(RdpAuditPaths.Default, provider.Paths);
	}

	[Fact]
	public void FakeProvider_ReturnsGivenLayout()
	{
		RdpAuditPaths paths = new(_root);
		IRdpAuditPathsProvider provider = new FakePathsProvider(paths);
		Assert.Same(paths, provider.Paths);
	}

	[Fact]
	public void DiagnosticLogRotation_AppendsLine_AndCreatesDirectory()
	{
		string log = Path.Combine(_root, "logs", "ipc-startup.log");
		DiagnosticLogRotation.AppendLine(log, "first");
		DiagnosticLogRotation.AppendLine(log, "second");

		string[] lines = File.ReadAllLines(log);
		Assert.Equal(new[] { "first", "second" }, lines);
	}

	[Fact]
	public void DiagnosticLogRotation_OverCap_RestartsFile()
	{
		string log = Path.Combine(_root, "logs", "rotation.log");
		// Seed the file past the cap directly so the next append forces a rotation.
		Directory.CreateDirectory(Path.GetDirectoryName(log)!);
		File.WriteAllText(log, new string('x', 600));

		DiagnosticLogRotation.AppendLine(log, "fresh", maxBytes: 512);

		string[] lines = File.ReadAllLines(log);
		Assert.Single(lines);
		Assert.Equal("fresh", lines[0]);
	}

	[Fact]
	public void DiagnosticLogRotation_AtOrUnderCap_Appends()
	{
		string log = Path.Combine(_root, "logs", "rotation-under.log");
		Directory.CreateDirectory(Path.GetDirectoryName(log)!);
		File.WriteAllText(log, "existing" + Environment.NewLine);

		DiagnosticLogRotation.AppendLine(log, "extra", maxBytes: 64 * 1024);

		string[] lines = File.ReadAllLines(log);
		Assert.Equal(new[] { "existing", "extra" }, lines);
	}

	[Fact]
	public void DiagnosticLogRotation_InvalidArgs_Throw()
	{
		Assert.Throws<ArgumentException>(() => DiagnosticLogRotation.AppendLine("", "x"));
		Assert.Throws<ArgumentException>(() => DiagnosticLogRotation.AppendLine("x", ""));
		Assert.Throws<ArgumentOutOfRangeException>(() => DiagnosticLogRotation.AppendLine("x", "line", maxBytes: 0));
	}

	/// <summary>Test-only path provider for exercising the injectable contract.</summary>
	private sealed class FakePathsProvider : IRdpAuditPathsProvider
	{
		private readonly RdpAuditPaths _paths;

		public FakePathsProvider(RdpAuditPaths paths) => _paths = paths;

		public RdpAuditPaths Paths => _paths;
	}
}
