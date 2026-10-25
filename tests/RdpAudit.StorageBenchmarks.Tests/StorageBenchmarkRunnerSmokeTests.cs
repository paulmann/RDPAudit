// File:    tests/RdpAudit.StorageBenchmarks.Tests/StorageBenchmarkRunnerSmokeTests.cs
// Module:  RdpAudit.StorageBenchmarks.Tests
// Purpose: Runs the storage benchmark end to end, in process, against a deliberately small temporary
//          store, and checks the three things that would make it dangerous or useless if they regressed:
//          the run produces the report artifacts and the sections an operator reads; it exits with the
//          documented code; and it leaves the production %ProgramData%\RdpAudit tree bit-for-bit as it
//          found it. The last one is the reason this test exists at all - it is the only automated
//          evidence that the tool's own safety boundary holds.
//          The run is in-process rather than a spawned process so a failure points at the runner, and the
//          store is small (50 000 rows, one sample) so the test stays inside a normal suite's budget while
//          still exercising every probe except the ones a quick profile deliberately skips.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System.Diagnostics;
using System.Globalization;
using System.Text;
using RdpAudit.Core.Diagnostics;
using RdpAudit.Core.Util;
using RdpAudit.StorageBenchmarks;
using Xunit;
using Xunit.Abstractions;

namespace RdpAudit.StorageBenchmarks.Tests;

/// <summary>End-to-end smoke test of the storage benchmark runner.</summary>
public class StorageBenchmarkRunnerSmokeTests
{
	private readonly ITestOutputHelper _output;

	public StorageBenchmarkRunnerSmokeTests(ITestOutputHelper output)
	{
		_output = output;
	}

	[Fact]
	public async Task QuickProfile_RunProducesTheThreeArtifactsAndDoesNotTouchTheProductionDataDirectory()
	{
		ProductionDataFingerprint before = ProductionDataFingerprint.Capture();
		string workRoot = Path.Combine(Path.GetTempPath(), "rdpaudit-benchmark-smoke-" + Guid.NewGuid().ToString("N"));
		string reportDirectory = Path.Combine(workRoot, "reports");
		StringBuilder console = new();
		using StringWriter output = new(console);

		try
		{
			Stopwatch watch = Stopwatch.StartNew();
			int exitCode = await StorageBenchmarkRunner.RunAsync(
				[
					"--quick",
					"--rows", "50000",
					"--codes", "8",
					"--samples", "1",
					"--warmup", "0",
					"--work-root", workRoot,
					"--out", reportDirectory,
				],
				output,
				CancellationToken.None);
			watch.Stop();
			_output.WriteLine(string.Format(
				CultureInfo.InvariantCulture,
				"quick smoke run: exit {0}, {1:0.###} s",
				exitCode,
				watch.Elapsed.TotalSeconds));
			_output.WriteLine(console.ToString());

			Assert.Equal(StorageBenchmarkExitCode.Success, exitCode);

			string markdownPath = Path.Combine(reportDirectory, StorageBenchmarkReportWriter.MarkdownFileName);
			string jsonPath = Path.Combine(reportDirectory, StorageBenchmarkReportWriter.JsonFileName);
			string settingsPath = Path.Combine(reportDirectory, StorageBenchmarkReportWriter.RecommendedSettingsFileName);
			Assert.True(File.Exists(markdownPath), "report.md was not written");
			Assert.True(File.Exists(jsonPath), "report.json was not written");
			Assert.True(File.Exists(settingsPath), "recommended-settings.json was not written");

			string markdown = File.ReadAllText(markdownPath);
			foreach (string section in new[]
			{
				"## 1. Machine profile",
				"## 2. Methodology",
				"## 3. Measured values",
				"## 4. Recommendations",
				"## 5. Limitations",
				"## 6. Scope",
			})
			{
				Assert.Contains(section, markdown, StringComparison.Ordinal);
			}

			Assert.Contains("These are **not applied**", markdown, StringComparison.Ordinal);
			Assert.Contains(StorageBenchmarkMetric.RetentionRowsPerSecond, markdown, StringComparison.Ordinal);
			Assert.Contains(StorageBenchmarkMetric.IntegrityFullCheckSeconds, markdown, StringComparison.Ordinal);
			Assert.Contains(StorageBenchmarkMetric.BackupSnapshotMebibytesPerSecond, markdown, StringComparison.Ordinal);

			// The report must be re-readable by the tool's own parser, which is what a consumer does.
			Assert.NotNull(StorageBenchmarkReportWriter.ParseJson(File.ReadAllText(jsonPath)));

			// The run announced the two things it must announce.
			Assert.Contains("profile        : quick", console.ToString(), StringComparison.Ordinal);
			Assert.Contains("Nothing was applied", console.ToString(), StringComparison.Ordinal);
		}
		finally
		{
			DeleteTreeTolerantly(workRoot);
		}

		Assert.Equal(before, ProductionDataFingerprint.Capture());
	}

	[Fact]
	public async Task ExistingStoreInTheStoreDirectory_IsRefusedWithoutTheOverride()
	{
		string workRoot = Path.Combine(Path.GetTempPath(), "rdpaudit-benchmark-refuse-" + Guid.NewGuid().ToString("N"));
		string storeDirectory = Path.Combine(workRoot, "store");
		Directory.CreateDirectory(storeDirectory);
		string databasePath = Path.Combine(storeDirectory, RdpAuditPaths.DatabaseFileName);
		await File.WriteAllTextAsync(databasePath, "not a real database");
		StringBuilder console = new();
		using StringWriter output = new(console);

		try
		{
			int exitCode = await StorageBenchmarkRunner.RunAsync(
				["--quick", "--store", storeDirectory, "--work-root", workRoot],
				output,
				CancellationToken.None);

			Assert.Equal(StorageBenchmarkExitCode.Refused, exitCode);
			Assert.Contains("Refusing to start", console.ToString(), StringComparison.Ordinal);
			Assert.Contains("--allow-existing-store", console.ToString(), StringComparison.Ordinal);

			// The refusal left the file exactly as it was and created nothing else beside the store
			// directory the caller had already made.
			Assert.Equal("not a real database", await File.ReadAllTextAsync(databasePath));
			Assert.Equal([storeDirectory], Directory.GetFileSystemEntries(workRoot));
		}
		finally
		{
			if (Directory.Exists(workRoot))
			{
				Directory.Delete(workRoot, recursive: true);
			}
		}
	}

	[Fact]
	public async Task ProductionDataDirectory_IsRefusedWithNoOverride()
	{
		string productionRoot = RdpAuditPaths.Default.ProgramDataDirectory;
		string nested = Path.Combine(productionRoot, "benchmark-should-never-be-created");
		using StringWriter output = new();

		int exitCode = await StorageBenchmarkRunner.RunAsync(
			["--quick", "--store", nested],
			output,
			CancellationToken.None);

		Assert.Equal(StorageBenchmarkExitCode.Refused, exitCode);
		Assert.Contains("production RdpAudit data directory", output.ToString(), StringComparison.Ordinal);
		Assert.False(Directory.Exists(nested), "the run created a directory inside the production data directory");
	}

	[Fact]
	public async Task UnknownOption_IsAUsageError()
	{
		using StringWriter output = new();

		int exitCode = await StorageBenchmarkRunner.RunAsync(["--not-an-option"], output, CancellationToken.None);

		Assert.Equal(StorageBenchmarkExitCode.UsageError, exitCode);
		Assert.Contains("is not a recognised option", output.ToString(), StringComparison.Ordinal);
	}

	[Fact]
	public async Task HelpRequest_PrintsTheUsageAndSucceeds()
	{
		using StringWriter output = new();

		int exitCode = await StorageBenchmarkRunner.RunAsync(["--help"], output, CancellationToken.None);

		Assert.Equal(StorageBenchmarkExitCode.Success, exitCode);
		Assert.Contains("RdpAudit storage benchmark", output.ToString(), StringComparison.Ordinal);
		Assert.Contains("What it never does", output.ToString(), StringComparison.Ordinal);
		Assert.Contains("--allow-existing-store", output.ToString(), StringComparison.Ordinal);
	}

	[Theory]
	[InlineData("--rows", "10")]
	[InlineData("--rows", "99999999")]
	[InlineData("--codes", "0")]
	[InlineData("--codes", "100000")]
	[InlineData("--samples", "0")]
	[InlineData("--samples", "100000")]
	[InlineData("--rows", "lots")]
	public async Task OutOfRangeOptions_AreUsageErrors(string name, string value)
	{
		using StringWriter output = new();

		int exitCode = await StorageBenchmarkRunner.RunAsync([name, value], output, CancellationToken.None);

		Assert.Equal(StorageBenchmarkExitCode.UsageError, exitCode);
		Assert.Contains(name, output.ToString(), StringComparison.Ordinal);
	}

	/// <summary>
	/// Removes a test's temporary tree, tolerating a handle that has not been released yet. Cleanup must not
	/// decide whether a test passed: a lingering SQLite handle is not a product defect, and a red test for
	/// it would hide the assertions that matter.
	/// </summary>
	private static void DeleteTreeTolerantly(string directory)
	{
		for (int attempt = 0; attempt < 10; attempt++)
		{
			try
			{
				if (Directory.Exists(directory))
				{
					Directory.Delete(directory, recursive: true);
				}

				return;
			}
			catch (IOException)
			{
				Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();
				Thread.Sleep(200);
			}
			catch (UnauthorizedAccessException)
			{
				Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();
				Thread.Sleep(200);
			}
		}
	}

	/// <summary>
	/// A comparable snapshot of the production data directory: every file's path, length and last-write
	/// time, plus every directory path. Comparing two of these is how the smoke test proves the tool left
	/// the evidence store alone. It reads the tree, and nothing more.
	/// </summary>
	private sealed record ProductionDataFingerprint(int FileCount, int DirectoryCount, string Digest)
	{
		public static ProductionDataFingerprint Capture()
		{
			string root = RdpAuditPaths.Default.ProgramDataDirectory;
			if (!Directory.Exists(root))
			{
				return new ProductionDataFingerprint(0, 0, "(absent)");
			}

			List<string> entries = [];
			int files = 0;
			foreach (string file in Directory.EnumerateFiles(root, "*", SearchOption.AllDirectories))
			{
				FileInfo info = new(file);
				entries.Add(string.Format(
					CultureInfo.InvariantCulture,
					"F|{0}|{1}|{2}",
					Path.GetRelativePath(root, file),
					info.Length,
					info.LastWriteTimeUtc.Ticks));
				files++;
			}

			int directories = 0;
			foreach (string directory in Directory.EnumerateDirectories(root, "*", SearchOption.AllDirectories))
			{
				entries.Add("D|" + Path.GetRelativePath(root, directory));
				directories++;
			}

			entries.Sort(StringComparer.Ordinal);
			byte[] hash = System.Security.Cryptography.SHA256.HashData(Encoding.UTF8.GetBytes(string.Join('\n', entries)));
			return new ProductionDataFingerprint(files, directories, Convert.ToHexString(hash));
		}
	}
}
