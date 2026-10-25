/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// File   : NotifierAutostartServiceTests.cs
// Project: RdpAudit.Configurator.Tests
// Purpose: Step 6 verification for the notifier autostart: the schtasks-backed
//          INotifierAutostartService registers an ONLOGON /RL HIGHEST task for the tray
//          notifier exe and removes it on demand. The process runner is faked via the
//          internal seam, so no real Task Scheduler state is touched.
// Depends: NotifierAutostartService, INotifierAutostartService, xunit

using System.Runtime.Versioning;
using RdpAudit.Configurator.Services;
using Xunit;

namespace RdpAudit.Configurator.Tests;

[SupportedOSPlatform("windows")]
public sealed class NotifierAutostartServiceTests
{
	private sealed class RecordingRunner
	{
		public List<(string Verb, string Arguments)> Calls { get; } = new();
		public Func<string, string, Task<NotifierAutostartService.SchTasksResult>> Delegate { get; }

		public RecordingRunner(params int[] responses)
		{
			int index = 0;
			Delegate = (verb, args) =>
			{
				Calls.Add((verb, args));
				int code = index < responses.Length ? responses[index] : 0;
				index++;
				return Task.FromResult(new NotifierAutostartService.SchTasksResult(code, string.Empty, string.Empty));
			};
		}
	}

	/// <summary>Writes a fake notifier executable into a directory unique to this test and returns its
	/// path. The path must be unique per test: a fixed name under <c>%TEMP%</c> is a machine-wide
	/// resource shared with every other process - a second run of this project, a parallel run of the
	/// solution, or a leftover from a host that was killed - and any of them writing or deleting that
	/// name turns this class into an intermittent failure that no log attributes correctly (B26).</summary>
	private static string CreateFakeNotifierExe(out string directory)
	{
		directory = Path.Combine(Path.GetTempPath(), "rdpaudit-notifier-" + Guid.NewGuid().ToString("N"));
		Directory.CreateDirectory(directory);
		string path = Path.Combine(directory, NotifierAutostartService.NotifierExeName);
		File.WriteAllText(path, "fake");
		return path;
	}

	/// <summary>Best-effort removal of a per-test directory. A failed delete must not turn a passing
	/// assertion into a failure.</summary>
	private static void DeleteDirectory(string directory)
	{
		try
		{
			if (Directory.Exists(directory))
			{
				Directory.Delete(directory, recursive: true);
			}
		}
		catch (IOException)
		{
		}
		catch (UnauthorizedAccessException)
		{
		}
	}

	/// <summary>Given two fake notifier executables, when they are created, then each lives in its own
	/// directory: this class may never depend on a machine-wide fixed path, because a foreign process
	/// owning that name would break it non-deterministically.</summary>
	[Fact]
	public void FakeNotifierPaths_AreUniquePerTest_SoAnotherRunCannotCollideWithThem()
	{
		string first = CreateFakeNotifierExe(out string firstDirectory);
		string second = CreateFakeNotifierExe(out string secondDirectory);
		try
		{
			Assert.NotEqual(firstDirectory, secondDirectory);
			Assert.NotEqual(first, second);
			Assert.True(File.Exists(first) && File.Exists(second));
			Assert.NotEqual(Path.GetTempPath(), firstDirectory);
		}
		finally
		{
			DeleteDirectory(firstDirectory);
			DeleteDirectory(secondDirectory);
		}
	}

	[Fact]
	public void ResolveNotifierExecutable_PrefersSiblingNotifierFolder()
	{
		string root = Path.Combine(Path.GetTempPath(), "rdpaudit-resolve-" + Guid.NewGuid().ToString("N"));
		string configDir = Path.Combine(root, "Configurator");
		string notifierDir = Path.Combine(root, "Notifier");
		Directory.CreateDirectory(configDir);
		Directory.CreateDirectory(notifierDir);
		string siblingExe = Path.Combine(notifierDir, NotifierAutostartService.NotifierExeName);
		File.WriteAllText(siblingExe, "fake");

		try
		{
			string resolved = NotifierAutostartService.ResolveNotifierExecutable(configDir);
			Assert.Equal(Path.GetFullPath(siblingExe), Path.GetFullPath(resolved));
		}
		finally
		{
			try { Directory.Delete(root, recursive: true); } catch { }
		}
	}

	[Fact]
	public void ResolveNotifierExecutable_FallsBackToOwnDirectory()
	{
		string configDir = Path.Combine(Path.GetTempPath(), "rdpaudit-resolve-" + Guid.NewGuid().ToString("N"));
		Directory.CreateDirectory(configDir);
		try
		{
			string resolved = NotifierAutostartService.ResolveNotifierExecutable(configDir);
			Assert.Equal(
				Path.GetFullPath(Path.Combine(configDir, NotifierAutostartService.NotifierExeName)),
				Path.GetFullPath(resolved));
		}
		finally
		{
			try { Directory.Delete(configDir, recursive: true); } catch { }
		}
	}

	[Fact]
	public async Task Apply_True_RegistersTask_WithQuotedOnLogonArguments()
	{
		string exePath = CreateFakeNotifierExe(out string exeDirectory);
		RecordingRunner runner = new(0);
		NotifierAutostartService service = new(runner.Delegate, () => exePath);

		try
		{
			NotifierAutostartResult result = await service.ApplyAsync(startWithWindows: true);

			Assert.True(result.Success);
			Assert.True(result.TaskPresent);
			(string verb, string args) = Assert.Single(runner.Calls);
			Assert.Equal("Create", verb);
			Assert.Contains("/TN \"RdpAuditNotifier\"", args);
			Assert.Contains("/TR \"\\\"" + exePath + "\\\"\"", args);
			Assert.Contains("/SC ONLOGON", args);
			Assert.Contains("/RL HIGHEST", args);
			Assert.Contains("/F", args);
		}
		finally
		{
			DeleteDirectory(exeDirectory);
		}
	}

	[Fact]
	public async Task Apply_True_ExeMissing_FailsWithoutInvokingSchtasks()
	{
		string missing = Path.Combine(Path.GetTempPath(), "definitely-missing-" + Guid.NewGuid().ToString("N") + ".exe");
		RecordingRunner runner = new(0);
		NotifierAutostartService service = new(runner.Delegate, () => missing);

		NotifierAutostartResult result = await service.ApplyAsync(startWithWindows: true);

		Assert.False(result.Success);
		Assert.False(result.TaskPresent);
		Assert.Empty(runner.Calls);
		Assert.Contains("not found", result.Message);
	}

	[Fact]
	public async Task Apply_True_SchtasksFailure_ReportsFailure()
	{
		string exePath = CreateFakeNotifierExe(out string exeDirectory);
		RecordingRunner runner = new(1); // Create fails with exit code 1
		NotifierAutostartService service = new(runner.Delegate, () => exePath);

		try
		{
			NotifierAutostartResult result = await service.ApplyAsync(startWithWindows: true);

			Assert.False(result.Success);
			Assert.False(result.TaskPresent);
			Assert.Single(runner.Calls);
		}
		finally
		{
			DeleteDirectory(exeDirectory);
		}
	}

	[Fact]
	public async Task Apply_False_TaskAbsent_ReturnsSuccessWithoutDelete()
	{
		RecordingRunner runner = new(1); // Query fails -> task absent
		NotifierAutostartService service = new(runner.Delegate, () => string.Empty);

		NotifierAutostartResult result = await service.ApplyAsync(startWithWindows: false);

		Assert.True(result.Success);
		Assert.False(result.TaskPresent);
		(string verb, _) = Assert.Single(runner.Calls);
		Assert.Equal("Query", verb);
	}

	[Fact]
	public async Task Apply_False_TaskPresent_DeletesTask()
	{
		RecordingRunner runner = new(0, 0); // Query ok, Delete ok
		NotifierAutostartService service = new(runner.Delegate, () => string.Empty);

		NotifierAutostartResult result = await service.ApplyAsync(startWithWindows: false);

		Assert.True(result.Success);
		Assert.False(result.TaskPresent);
		Assert.Equal(2, runner.Calls.Count);
		Assert.Equal("Query", runner.Calls[0].Verb);
		Assert.Equal("Delete", runner.Calls[1].Verb);
		Assert.Contains("/F", runner.Calls[1].Arguments);
	}

	[Fact]
	public async Task Apply_False_DeleteFails_ReportsFailure()
	{
		RecordingRunner runner = new(0, 1); // Query ok, Delete fails
		NotifierAutostartService service = new(runner.Delegate, () => string.Empty);

		NotifierAutostartResult result = await service.ApplyAsync(startWithWindows: false);

		Assert.False(result.Success);
		Assert.True(result.TaskPresent);
		Assert.Equal(2, runner.Calls.Count);
	}
}
