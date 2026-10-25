// File:    src/RdpAudit.Configurator/Services/NotifierAutostartService.cs
// Module:  RdpAudit.Configurator.Services
// Purpose: Windows Task Scheduler registration of the elevated tray notifier. The task runs
//          /SC ONLOGON /RL HIGHEST under the interactive user, so it is registered by the
//          elevated Configurator rather than the Session-0 service. Deletion treats a missing
//          task as success. All schtasks interaction relies on exit codes only (locale-safe).
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Runtime.Versioning;

namespace RdpAudit.Configurator.Services;

/// <summary>Registers or removes the RdpAuditNotifier ONLOGON scheduled task via schtasks.exe.</summary>
[SupportedOSPlatform("windows")]
public sealed class NotifierAutostartService : INotifierAutostartService
{
	/// <summary>Scheduler task name used for the notifier autostart.</summary>
	public const string TaskName = "RdpAuditNotifier";

	/// <summary>The file name of the notifier executable.</summary>
	public const string NotifierExeName = "RdpAudit.Notifier.exe";

	private static readonly TimeSpan SchTasksTimeout = TimeSpan.FromSeconds(20);

	private readonly Func<string, string, Task<SchTasksResult>> _runner;
	private readonly Func<string> _executableResolver;

	/// <summary>Creates the production service backed by the real schtasks.exe process runner.</summary>
	public NotifierAutostartService()
		: this(RunAsync, () => ResolveNotifierExecutable())
	{
	}

	/// <summary>Test seam: the runner receives verb/arguments and returns a schtasks outcome;
	/// the resolver supplies the candidate notifier executable path.</summary>
	internal NotifierAutostartService(
		Func<string, string, Task<SchTasksResult>> runner,
		Func<string> executableResolver)
	{
		_runner = runner;
		_executableResolver = executableResolver;
	}

	/// <inheritdoc/>
	public async Task<NotifierAutostartResult> ApplyAsync(bool startWithWindows)
	{
		return startWithWindows ? await RegisterTaskAsync().ConfigureAwait(false) : await RemoveTaskAsync().ConfigureAwait(false);
	}

	/// <summary>Finds the notifier executable: the sibling 'Notifier' publish folder first,
	/// then the Configurator's own directory (framework-dependent dev layout).</summary>
	public static string ResolveNotifierExecutable(string? configuratorDirectory = null)
	{
		string baseDir = (configuratorDirectory ?? AppContext.BaseDirectory)
			.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
		string parent = Path.GetDirectoryName(baseDir) ?? baseDir;

		string sibling = Path.Combine(parent, "Notifier", NotifierExeName);
		if (File.Exists(sibling))
		{
			return sibling;
		}

		return Path.Combine(baseDir, NotifierExeName);
	}

	private async Task<NotifierAutostartResult> RegisterTaskAsync()
	{
		string exePath = _executableResolver();
		if (!File.Exists(exePath))
		{
			return new NotifierAutostartResult(false, false, string.Format(
				CultureInfo.InvariantCulture,
				"{0} was not found; the autostart task was not registered.",
				NotifierExeName));
		}

		string action = string.Format(
			CultureInfo.InvariantCulture,
			"/TN \"{0}\" /TR \"\\\"{1}\\\"\" /SC ONLOGON /RL HIGHEST /F",
			TaskName,
			exePath);
		SchTasksResult result = await _runner("Create", action).ConfigureAwait(false);
		if (result.ExitCode != 0)
		{
			return new NotifierAutostartResult(false, false,
				"Failed to register the autostart task: " + result.Diagnostic());
		}

		return new NotifierAutostartResult(true, true, "Autostart task registered.");
	}

	private async Task<NotifierAutostartResult> RemoveTaskAsync()
	{
		string queryArgs = string.Format(CultureInfo.InvariantCulture, "/TN \"{0}\"", TaskName);
		SchTasksResult query = await _runner("Query", queryArgs).ConfigureAwait(false);
		if (query.ExitCode != 0)
		{
			return new NotifierAutostartResult(true, false, "Autostart task was not present.");
		}

		SchTasksResult delete = await _runner("Delete", queryArgs + " /F").ConfigureAwait(false);
		if (delete.ExitCode != 0)
		{
			return new NotifierAutostartResult(false, true,
				"Failed to remove the autostart task: " + delete.Diagnostic());
		}

		return new NotifierAutostartResult(true, false, "Autostart task removed.");
	}

	/// <summary>Runs schtasks.exe without blocking the calling thread for the duration of the child
	/// process. Outputs are drained while the process is awaited so a chatty child can never deadlock the
	/// pipe, and the 20-second budget plus the kill-on-timeout behaviour are unchanged. Every failure
	/// collapses into a SchTasksResult with exit code -1.</summary>
	internal static async Task<SchTasksResult> RunAsync(string verb, string arguments)
	{
		ProcessStartInfo psi = new("schtasks.exe")
		{
			UseShellExecute = false,
			RedirectStandardOutput = true,
			RedirectStandardError = true,
			CreateNoWindow = true,
		};
		psi.Arguments = verb + " " + arguments;

		try
		{
			using Process? process = Process.Start(psi);
			if (process is null)
			{
				return new SchTasksResult(-1, string.Empty, "schtasks.exe failed to start");
			}

			Task<string> outTask = process.StandardOutput.ReadToEndAsync();
			Task<string> errTask = process.StandardError.ReadToEndAsync();

			using CancellationTokenSource timeoutCts = new(SchTasksTimeout);
			try
			{
				await process.WaitForExitAsync(timeoutCts.Token).ConfigureAwait(false);
			}
			catch (OperationCanceledException)
			{
				KillProcessTree(process);
				await ObserveStaleReadsAsync(outTask, errTask).ConfigureAwait(false);
				return new SchTasksResult(-1, string.Empty, "schtasks.exe timed out");
			}

			string stdout = await outTask.ConfigureAwait(false);
			string stderr = await errTask.ConfigureAwait(false);
			return new SchTasksResult(process.ExitCode, stdout.Trim(), stderr.Trim());
		}
		catch (Exception ex)
		{
			return new SchTasksResult(-1, string.Empty, ex.Message);
		}
	}

	private static void KillProcessTree(Process process)
	{
		try
		{
			process.Kill(entireProcessTree: true);
		}
		catch (InvalidOperationException)
		{
			// Already exited between the timeout and the kill.
		}
	}

	/// <summary>Observes the pending stdio reads after a killed child, so their faults cannot escape as
	/// unobserved task exceptions.</summary>
	private static async Task ObserveStaleReadsAsync(Task<string> stdoutTask, Task<string> stderrTask)
	{
		try
		{
			await stdoutTask.ConfigureAwait(false);
		}
		catch (Exception)
		{
		}

		try
		{
			await stderrTask.ConfigureAwait(false);
		}
		catch (Exception)
		{
		}
	}

	/// <summary>Outcome of a single schtasks.exe invocation (exit code + trimmed output).</summary>
	internal sealed record SchTasksResult(int ExitCode, string Stdout, string Stderr)
	{
		public string Diagnostic()
		{
			if (Stderr.Length > 0)
			{
				return Stderr;
			}

			if (Stdout.Length > 0)
			{
				return Stdout;
			}

			return string.Format(CultureInfo.InvariantCulture, "exit code {0}", ExitCode);
		}
	}
}
