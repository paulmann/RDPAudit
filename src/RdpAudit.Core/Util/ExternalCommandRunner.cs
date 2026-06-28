// File:    src/RdpAudit.Core/Util/ExternalCommandRunner.cs
// Module:  RdpAudit.Core.Util
// Purpose: Centralized async runner for every external Windows command spawned by RdpAudit.
//          Exposes two methods:
//
//          * RunEnglishConsoleAsync — spawns cmd.exe /d /c "chcp 437 >nul & <fixed command>"
//            so the captured stdout contains the stable English / Latin-script tokens used
//            by RdpAudit's parsers (qwinsta state, netsh rule "LocalPort", auditpol /r CSV
//            "Inclusion Setting", gpresult headings). Used for fixed / whitelisted commands
//            only — there is no string-concat path through which operator input flows into
//            the cmd argument string. The OEM code page is also used for stdout decoding,
//            so a localized fallback still decodes correctly when the chcp pin is rejected
//            by the host configuration.
//
//          * RunDirectAsync — spawns the executable via ProcessStartInfo.ArgumentList. No
//            shell, no string concatenation, no parsing-dependent encoding. Used for
//            destructive commands (netsh add/delete rule, logoff, tsdiscon, sc, reg) that
//            carry validated dynamic arguments but whose stdout we do NOT parse for English
//            content.
//
//          Result shape is ExternalCommandResult — captures every field needed for an
//          actionable diagnostic: command label, exit code, both streams, timed-out flag,
//          wall duration, and which mode was used. Logging callers should prefer
//          ExternalCommandResult.BuildDiagnosticSummary so multi-line stdout never reaches
//          the log file verbatim.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.Versioning;
using System.Text;

namespace RdpAudit.Core.Util;

/// <summary>Centralized async runner for every external Windows command spawned by RdpAudit.</summary>
public interface IExternalCommandRunner
{
	/// <summary>Runs a whitelisted command through the parse-stable English console
	/// (<c>cmd /d /c "chcp 437 >nul &amp; ..."</c>). The argument string is built by
	/// <see cref="EnglishConsoleCommandFactory"/> from constants and validated tokens.</summary>
	Task<ExternalCommandResult> RunEnglishConsoleAsync(
		TrustedEnglishConsoleTool tool,
		EnglishConsoleArgs? args,
		TimeSpan timeout,
		CancellationToken ct);

	/// <summary>Runs an executable with a sanitised argument vector via
	/// <see cref="ProcessStartInfo.ArgumentList"/>. No shell wrapping.</summary>
	Task<ExternalCommandResult> RunDirectAsync(
		string commandLabel,
		string executable,
		IReadOnlyList<string> arguments,
		TimeSpan timeout,
		CancellationToken ct);
}

/// <summary>Default <see cref="IExternalCommandRunner"/> implementation backed by
/// <see cref="Process"/>. Decodes both streams with the host OEM code page so the localized
/// fallback path stays usable even when <c>chcp 437</c> is rejected by the host.</summary>
[SupportedOSPlatform("windows")]
public sealed class ExternalCommandRunner : IExternalCommandRunner
{
	/// <summary>Default hard timeout — 15s is generous for every parsed-stdout tool we drive.</summary>
	public static readonly TimeSpan DefaultTimeout = TimeSpan.FromSeconds(15);

	/// <inheritdoc/>
	public async Task<ExternalCommandResult> RunEnglishConsoleAsync(
		TrustedEnglishConsoleTool tool,
		EnglishConsoleArgs? args,
		TimeSpan timeout,
		CancellationToken ct)
	{
		EnglishConsoleSpawn spawn = EnglishConsoleCommandFactory.Build(tool, args);
		Encoding encoding = QwinstaConsoleEncoding.Resolve();

		ProcessStartInfo psi = new(spawn.Executable)
		{
			Arguments = spawn.Arguments,
			UseShellExecute = false,
			CreateNoWindow = true,
			RedirectStandardOutput = true,
			RedirectStandardError = true,
			StandardOutputEncoding = encoding,
			StandardErrorEncoding = encoding,
		};

		return await RunCoreAsync(
			commandLabel: spawn.CommandLabel,
			psi: psi,
			timeout: timeout,
			englishConsoleMode: true,
			ct: ct).ConfigureAwait(false);
	}

	/// <inheritdoc/>
	public async Task<ExternalCommandResult> RunDirectAsync(
		string commandLabel,
		string executable,
		IReadOnlyList<string> arguments,
		TimeSpan timeout,
		CancellationToken ct)
	{
		ArgumentException.ThrowIfNullOrWhiteSpace(commandLabel);
		ArgumentException.ThrowIfNullOrWhiteSpace(executable);
		ArgumentNullException.ThrowIfNull(arguments);

		ProcessStartInfo psi = new(executable)
		{
			UseShellExecute = false,
			CreateNoWindow = true,
			RedirectStandardOutput = true,
			RedirectStandardError = true,
		};

		foreach (string a in arguments)
		{
			psi.ArgumentList.Add(a);
		}

		return await RunCoreAsync(
			commandLabel: commandLabel,
			psi: psi,
			timeout: timeout,
			englishConsoleMode: false,
			ct: ct).ConfigureAwait(false);
	}

	private static async Task<ExternalCommandResult> RunCoreAsync(
		string commandLabel,
		ProcessStartInfo psi,
		TimeSpan timeout,
		bool englishConsoleMode,
		CancellationToken ct)
	{
		Stopwatch sw = Stopwatch.StartNew();
		using CancellationTokenSource cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
		if (timeout > TimeSpan.Zero)
		{
			cts.CancelAfter(timeout);
		}

		Process? proc = null;
		try
		{
			proc = Process.Start(psi);
			if (proc is null)
			{
				return new ExternalCommandResult(
					CommandLabel: commandLabel,
					Executable: psi.FileName,
					ExitCode: -1,
					StdOut: string.Empty,
					StdErr: psi.FileName + " failed to start.",
					TimedOut: false,
					Duration: sw.Elapsed,
					EnglishConsoleMode: englishConsoleMode);
			}

			Task<string> stdoutTask = proc.StandardOutput.ReadToEndAsync(cts.Token);
			Task<string> stderrTask = proc.StandardError.ReadToEndAsync(cts.Token);

			try
			{
				await proc.WaitForExitAsync(cts.Token).ConfigureAwait(false);
			}
			catch (OperationCanceledException)
			{
				if (ct.IsCancellationRequested)
				{
					KillProcessTreeQuiet(proc);
					throw;
				}

				// Timeout (not external cancellation) — kill and surface a structured result.
				KillProcessTreeQuiet(proc);
				string partialOut = await DrainQuiet(stdoutTask).ConfigureAwait(false);
				string partialErr = await DrainQuiet(stderrTask).ConfigureAwait(false);
				return new ExternalCommandResult(
					CommandLabel: commandLabel,
					Executable: psi.FileName,
					ExitCode: -1,
					StdOut: partialOut,
					StdErr: partialErr,
					TimedOut: true,
					Duration: sw.Elapsed,
					EnglishConsoleMode: englishConsoleMode);
			}

			string stdout = await stdoutTask.ConfigureAwait(false);
			string stderr = await stderrTask.ConfigureAwait(false);
			return new ExternalCommandResult(
				CommandLabel: commandLabel,
				Executable: psi.FileName,
				ExitCode: proc.ExitCode,
				StdOut: stdout,
				StdErr: stderr,
				TimedOut: false,
				Duration: sw.Elapsed,
				EnglishConsoleMode: englishConsoleMode);
		}
		catch (Win32Exception ex)
		{
			return new ExternalCommandResult(
				CommandLabel: commandLabel,
				Executable: psi.FileName,
				ExitCode: -1,
				StdOut: string.Empty,
				StdErr: ex.GetType().Name + ": " + ex.Message,
				TimedOut: false,
				Duration: sw.Elapsed,
				EnglishConsoleMode: englishConsoleMode);
		}
		finally
		{
			proc?.Dispose();
		}
	}

	private static void KillProcessTreeQuiet(Process proc)
	{
		try
		{
			if (!proc.HasExited)
			{
				proc.Kill(entireProcessTree: true);
			}
		}
		catch (InvalidOperationException)
		{
			// Process exited between the cancellation check and Kill.
		}
		catch (Win32Exception)
		{
			// Best-effort kill.
		}
		catch (NotSupportedException)
		{
			// Older runtimes — accept that the child may outlive cancellation.
		}
	}

	private static async Task<string> DrainQuiet(Task<string> readTask)
	{
		try
		{
			return await readTask.ConfigureAwait(false);
		}
		catch (OperationCanceledException)
		{
			return string.Empty;
		}
		catch (IOException)
		{
			return string.Empty;
		}
	}
}
