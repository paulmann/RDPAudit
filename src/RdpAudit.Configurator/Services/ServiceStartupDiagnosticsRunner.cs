/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 1.0.0
// File   : ServiceStartupDiagnosticsRunner.cs
// Project: RdpAudit.Configurator (RdpAudit.Configurator.Services)
// Purpose: Locally-collected, IPC-free startup diagnostics for the RdpAudit Windows service.
//          When the service will not start (SCM Win32 exit 1067 and friends) the running IPC
//          pipe is by definition unreachable, so the existing IPC-driven Diagnostics tab cannot
//          explain the failure. This runner collects everything an operator needs to root-cause
//          the failure without leaving the Configurator:
//            * SCM state and exit codes via WmiServiceInfoReader.
//            * Log tails from %ProgramData%\RdpAudit\logs\ipc-startup.log, RDPAudit_DEBUG_Log.txt,
//              and any crash-report artifacts, via DiagnosticsExtrasCollector.
//            * Windows Application event log entries from source 'RdpAuditService' in the last
//              24 hours (Error and Warning) so early startup faults that never reach any file
//              logger still surface here.
//            * .NET runtime availability via `dotnet --list-runtimes` (net8.0-windows requires
//              Microsoft.WindowsDesktop.App 8.x).
//            * appsettings.json integrity check (present, valid JSON, contains RdpAudit section).
//            * ACL / writability probes for %ProgramData%\RdpAudit and the SQLite database file.
//            * Optional console self-test: launches RdpAudit.Service.exe with `--console` in a
//              child process, captures stdout+stderr for a short window, then kills it. This
//              produces the FATAL breadcrumb from Program.cs / IpcServerWorker that the SCM path
//              swallows.
// Depends: WmiServiceInfoReader, DiagnosticsExtrasCollector, ServiceLayout, ServiceInstallationInfo,
//          System.Diagnostics.EventLog, System.Diagnostics.Process
// Extends: To add a new probe, append another AppendSection(sb, "<title>", () => { ... }) call
//          inside CollectAsync. Each probe must swallow its own exceptions and never throw.

using System.Diagnostics;
using System.Diagnostics.Eventing.Reader;
using System.Globalization;
using System.Runtime.Versioning;
using System.Security;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using RdpAudit.Core.Util;

namespace RdpAudit.Configurator.Services;

/// <summary>
/// Composes a self-contained "why is the service not starting" report. Never throws:
/// every probe is guarded and failures are rendered inline so the operator can still
/// read the sections that succeeded.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class ServiceStartupDiagnosticsRunner
{
	private const string ServiceName          = "RdpAuditService";
	private const string EventLogSource       = "RdpAuditService";
	private const string ConsoleTestArg       = "--console";
	private static readonly TimeSpan ConsoleTestTimeout = TimeSpan.FromSeconds(8);
	private static readonly TimeSpan EventLogWindow     = TimeSpan.FromHours(24);
	private const int    EventLogMaxRecords   = 25;

	private readonly string _configuratorDirectory;
	private readonly bool   _runConsoleSelfTest;

	public ServiceStartupDiagnosticsRunner(string configuratorDirectory, bool runConsoleSelfTest)
	{
		_configuratorDirectory = configuratorDirectory ?? throw new ArgumentNullException(nameof(configuratorDirectory));
		_runConsoleSelfTest    = runConsoleSelfTest;
	}

	/// <summary>Collects every probe into a single human-readable report.</summary>
	public async Task<string> CollectAsync(CancellationToken ct = default)
	{
		StringBuilder sb = new(capacity: 16 * 1024);

		sb.AppendLine("RdpAudit — Service Startup Diagnostics");
		sb.AppendLine("======================================");
		sb.AppendLine("Generated (UTC): " + DateTime.UtcNow.ToString("yyyy-MM-dd HH:mm:ss'Z'", CultureInfo.InvariantCulture));
		sb.AppendLine("Configurator dir: " + _configuratorDirectory);
		sb.AppendLine();

		ServiceLayoutInfo layout = ServiceLayout.Discover(_configuratorDirectory);
		ServiceInstallationInfo? scmInfo = null;

		await AppendSectionAsync(sb, "1. SCM state (Win32 + service-specific exit codes)", async () =>
		{
			WmiServiceInfoReader reader = new(ServiceName);
			try
			{
				scmInfo = await reader.ReadAsync(ct).ConfigureAwait(false);
			}
			catch (Exception ex)
			{
				return "  WMI query failed: " + ex.GetType().Name + " — " + ex.Message;
			}
			return FormatScm(scmInfo);
		}).ConfigureAwait(false);

		AppendSection(sb, "2. Distribution / install paths", () => FormatLayout(layout, scmInfo));

		AppendSection(sb, "3. Windows Application event log — source 'RdpAuditService' (last 24h, Error/Warning)",
			() => FormatEventLog());

		AppendSection(sb, "4. .NET runtime availability (dotnet --list-runtimes)", () => FormatDotnetRuntimes());

		AppendSection(sb, "5. appsettings.json integrity", () => FormatAppSettings(layout.AppSettingsPath));

		AppendSection(sb, "6. ProgramData ACL and SQLite database writability",
			() => FormatWritabilityChecks(layout.ProgramDataDirectory, layout.DefaultDatabasePath));

		AppendSection(sb, "7. On-disk log tails (ipc-startup.log, RDPAudit_DEBUG_Log.txt, crash reports)",
			() => FormatExtras(layout));

		if (_runConsoleSelfTest)
		{
			string installedExe = Path.Combine(layout.InstallDirectory, ServiceLayout.ServiceExeName);
			await AppendSectionAsync(sb, "8. Console self-test (launch service exe with --console for " +
				ConsoleTestTimeout.TotalSeconds.ToString("0", CultureInfo.InvariantCulture) + "s)",
				() => RunConsoleSelfTestAsync(installedExe, ct)).ConfigureAwait(false);
		}
		else
		{
			sb.AppendLine("8. Console self-test");
			sb.AppendLine("--------------------");
			sb.AppendLine("Skipped (toggle 'Run console self-test' to enable — requires the service to be stopped).");
			sb.AppendLine();
		}

		AppendSection(sb, "9. Interpretation hints", () => FormatInterpretation(scmInfo));

		return sb.ToString();
	}

	// ── Sections ─────────────────────────────────────────────────────────────────

	private static string FormatScm(ServiceInstallationInfo? info)
	{
		if (info is null)
		{
			return "  Unable to read SCM state (WMI query returned no row).";
		}

		StringBuilder sb = new();
		sb.AppendLine("  ServiceName:             " + info.ServiceName);
		sb.AppendLine("  Installed:               " + info.Installed);
		sb.AppendLine("  DisplayName:             " + (info.DisplayName ?? "(none)"));
		sb.AppendLine("  State:                   " + (info.StateName ?? "(unknown)") + " (code=" + (info.StateCode?.ToString(CultureInfo.InvariantCulture) ?? "?") + ")");
		sb.AppendLine("  StartMode:               " + (info.StartMode ?? "(unknown)"));
		sb.AppendLine("  Status:                  " + (info.Status ?? "(unknown)"));
		sb.AppendLine("  ProcessId:               " + (info.ProcessId?.ToString(CultureInfo.InvariantCulture) ?? "(none)"));
		sb.AppendLine("  ImagePath:               " + (info.ImagePath ?? "(none)"));
		sb.AppendLine("  Win32ExitCode:           " + FormatExitCode(info.Win32ExitCode));
		sb.AppendLine("  ServiceSpecificExitCode: " + (info.ServiceSpecificExitCode?.ToString(CultureInfo.InvariantCulture) ?? "0"));
		if (!string.IsNullOrEmpty(info.Diagnostic))
		{
			sb.AppendLine("  Diagnostic:              " + info.Diagnostic);
		}
		return sb.ToString();
	}

	private static string FormatExitCode(int? code)
	{
		if (code is null)
		{
			return "(none)";
		}
		return code switch
		{
			0    => "0 (no error)",
			1053 => "1053 ERROR_SERVICE_REQUEST_TIMEOUT — the service did not report to SCM within the 30s window",
			1064 => "1064 ERROR_EXCEPTION_IN_SERVICE — an unhandled exception occurred inside the service",
			1067 => "1067 ERROR_PROCESS_ABORTED — the service process terminated unexpectedly (crashed) during startup",
			1068 => "1068 ERROR_SERVICE_DEPENDENCY_FAIL — a dependent service failed to start",
			_    => code.Value.ToString(CultureInfo.InvariantCulture) + " (see WinError.h)",
		};
	}

	private static string FormatLayout(ServiceLayoutInfo layout, ServiceInstallationInfo? scmInfo)
	{
		StringBuilder sb = new();
		sb.AppendLine("  Configurator dir:       " + layout.ConfiguratorDirectory);
		sb.AppendLine("  Distribution dir:       " + (layout.DistributionDirectory ?? "(unknown)"));
		sb.AppendLine("  Distribution exe:       " + layout.ExpectedServiceExecutable +
			(layout.ServiceExecutableExists ? " (present)" : " (MISSING)"));
		string installedExe = Path.Combine(layout.InstallDirectory, ServiceLayout.ServiceExeName);
		sb.AppendLine("  Install dir:            " + layout.InstallDirectory);
		sb.AppendLine("  Installed exe:          " + installedExe +
			(File.Exists(installedExe) ? " (present)" : " (MISSING)"));
		sb.AppendLine("  Installed exe (SCM):    " + (scmInfo?.ImagePath ?? "(unknown)"));
		sb.AppendLine("  ProgramData root:       " + layout.ProgramDataDirectory);
		sb.AppendLine("  appsettings.json:       " + layout.AppSettingsPath +
			(File.Exists(layout.AppSettingsPath) ? " (present)" : " (MISSING)"));
		sb.AppendLine("  Database path (dflt):   " + layout.DefaultDatabasePath +
			(File.Exists(layout.DefaultDatabasePath) ? " (present)" : " (missing — created on first run)"));
		return sb.ToString();
	}

	private static string FormatEventLog()
	{
		StringBuilder sb = new();

		// Query the Application log for both explicit source RdpAuditService and generic .NET Runtime /
		// Application Error records that name our exe. The .NET Runtime source is where an unhandled
		// exception from the service worker surfaces first — critical for diagnosing exit 1067.
		try
		{
			string query = string.Format(
				CultureInfo.InvariantCulture,
				"*[System[(Level=1 or Level=2 or Level=3) and TimeCreated[timediff(@SystemTime) <= {0}] " +
				"and (Provider[@Name='{1}'] or Provider[@Name='.NET Runtime'] or Provider[@Name='Application Error'])]]",
				(long)EventLogWindow.TotalMilliseconds,
				EventLogSource);

			EventLogQuery elq = new("Application", PathType.LogName, query) { ReverseDirection = true };
			using EventLogReader reader = new(elq);

			int count = 0;
			EventRecord? rec;
			while (count < EventLogMaxRecords && (rec = reader.ReadEvent()) is not null)
			{
				try
				{
					string when = rec.TimeCreated?.ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss'Z'", CultureInfo.InvariantCulture) ?? "(no timestamp)";
					string level = rec.LevelDisplayName ?? rec.Level?.ToString(CultureInfo.InvariantCulture) ?? "?";
					string provider = rec.ProviderName ?? "?";
					string message;
					try
					{
						message = rec.FormatDescription() ?? "(no message)";
					}
					catch (EventLogException)
					{
						message = "(FormatDescription failed — provider messages not installed)";
					}

					// Only show the .NET Runtime / Application Error record when it names our exe,
					// otherwise we would flood with unrelated crashes from other apps.
					if ((provider == ".NET Runtime" || provider == "Application Error")
						&& !message.Contains("RdpAudit.Service", StringComparison.OrdinalIgnoreCase)
						&& !message.Contains(ServiceName, StringComparison.OrdinalIgnoreCase))
					{
						continue;
					}

					sb.Append("  [").Append(when).Append("] ").Append(level).Append(" — ")
						.Append(provider).Append(" (EventID ").Append(rec.Id).AppendLine("):");
					sb.AppendLine(IndentBlock(TruncateMessage(message, 1600), "    "));
					sb.AppendLine();
					count++;
				}
				finally
				{
					rec.Dispose();
				}
			}

			if (count == 0)
			{
				sb.AppendLine("  No matching records in the last " + EventLogWindow.TotalHours.ToString("0", CultureInfo.InvariantCulture) + " hours.");
			}
		}
		catch (UnauthorizedAccessException)
		{
			sb.AppendLine("  Access denied reading the Application event log. Run the Configurator as Administrator.");
		}
		catch (EventLogNotFoundException)
		{
			sb.AppendLine("  The Application event log is not available on this host.");
		}
		catch (Exception ex)
		{
			sb.AppendLine("  Event log probe failed: " + ex.GetType().Name + " — " + ex.Message);
		}

		return sb.ToString();
	}

	private static string FormatDotnetRuntimes()
	{
		try
		{
			ProcessStartInfo psi = new()
			{
				FileName               = "dotnet",
				Arguments              = "--list-runtimes",
				RedirectStandardOutput = true,
				RedirectStandardError  = true,
				UseShellExecute        = false,
				CreateNoWindow         = true,
			};
			using Process p = Process.Start(psi)!;
			string stdout = p.StandardOutput.ReadToEnd();
			string stderr = p.StandardError.ReadToEnd();
			p.WaitForExit(5_000);
			if (!p.HasExited)
			{
				try { p.Kill(entireProcessTree: true); } catch { /* best effort */ }
				return "  Timed out waiting for `dotnet --list-runtimes`.";
			}

			string all = string.IsNullOrWhiteSpace(stdout) ? stderr : stdout;
			bool hasWpfNet8 = all.Contains("Microsoft.WindowsDesktop.App 8.", StringComparison.OrdinalIgnoreCase);
			bool hasAspNet8 = all.Contains("Microsoft.AspNetCore.App 8.",     StringComparison.OrdinalIgnoreCase);
			bool hasCore8   = all.Contains("Microsoft.NETCore.App 8.",        StringComparison.OrdinalIgnoreCase);

			StringBuilder sb = new();
			sb.AppendLine(IndentBlock(all.TrimEnd(), "  "));
			sb.AppendLine();
			sb.Append("  Detected: ")
				.Append("NETCore.App 8=").Append(hasCore8 ? "YES" : "no").Append("  ")
				.Append("WindowsDesktop.App 8=").Append(hasWpfNet8 ? "YES" : "NO (required by Configurator, net8.0-windows)").Append("  ")
				.Append("AspNetCore.App 8=").Append(hasAspNet8 ? "YES" : "no")
				.AppendLine();
			return sb.ToString();
		}
		catch (Exception ex)
		{
			return "  `dotnet` is not on PATH or could not be launched: " + ex.GetType().Name + " — " + ex.Message;
		}
	}

	private static string FormatAppSettings(string path)
	{
		if (!File.Exists(path))
		{
			return "  appsettings.json is MISSING — first-run wizard has not completed.";
		}

		try
		{
			byte[] bytes = File.ReadAllBytes(path);
			using JsonDocument doc = JsonDocument.Parse(bytes);

			StringBuilder sb = new();
			sb.AppendLine("  Size:                    " + bytes.Length.ToString("N0", CultureInfo.InvariantCulture) + " bytes");
			sb.AppendLine("  JSON parse:              OK");

			if (!doc.RootElement.TryGetProperty("RdpAudit", out JsonElement rdp))
			{
				sb.AppendLine("  WARNING: 'RdpAudit' section is missing at the root — service will use built-in defaults.");
				return sb.ToString();
			}

			if (rdp.TryGetProperty("EnabledEventIds", out JsonElement ids) && ids.ValueKind == JsonValueKind.Array)
			{
				sb.AppendLine("  EnabledEventIds count:   " + ids.GetArrayLength().ToString(CultureInfo.InvariantCulture));
			}
			if (rdp.TryGetProperty("Database", out JsonElement db) && db.TryGetProperty("Path", out JsonElement dbPath))
			{
				sb.AppendLine("  Database.Path:           " + dbPath.GetString());
			}
			if (rdp.TryGetProperty("Diagnostics", out JsonElement diag) && diag.TryGetProperty("DebugMode", out JsonElement dbg))
			{
				sb.AppendLine("  Diagnostics.DebugMode:   " + dbg);
			}
			return sb.ToString();
		}
		catch (JsonException jx)
		{
			return "  appsettings.json is present but INVALID JSON — service startup will fail: " + jx.Message;
		}
		catch (Exception ex)
		{
			return "  Could not read appsettings.json: " + ex.GetType().Name + " — " + ex.Message;
		}
	}

	private static string FormatWritabilityChecks(string? programDataRdp, string dbPath)
	{
		StringBuilder sb = new();
		if (string.IsNullOrEmpty(programDataRdp))
		{
			sb.AppendLine("  ProgramData path unknown.");
			return sb.ToString();
		}

		sb.AppendLine("  Folder:   " + programDataRdp);
		sb.AppendLine("    Exists:  " + Directory.Exists(programDataRdp));
		sb.AppendLine("    Writable: " + CanWrite(programDataRdp));
		AppendAclSummary(sb, programDataRdp, "      ");

		sb.AppendLine("  Database: " + dbPath);
		sb.AppendLine("    Exists:   " + File.Exists(dbPath));
		if (File.Exists(dbPath))
		{
			try
			{
				FileInfo fi = new(dbPath);
				sb.AppendLine("    Size:     " + fi.Length.ToString("N0", CultureInfo.InvariantCulture) + " bytes");
				sb.AppendLine("    LastWrite: " + fi.LastWriteTimeUtc.ToString("yyyy-MM-dd HH:mm:ss'Z'", CultureInfo.InvariantCulture));
				sb.AppendLine("    ReadOnly:  " + fi.IsReadOnly);
				sb.AppendLine("    Locked:    " + IsFileLocked(dbPath));
			}
			catch (Exception ex)
			{
				sb.AppendLine("    Stat failed: " + ex.GetType().Name + " — " + ex.Message);
			}
		}
		return sb.ToString();
	}

	private static void AppendAclSummary(StringBuilder sb, string path, string indent)
	{
		try
		{
			DirectoryInfo di = new(path);
			DirectorySecurity acl = di.GetAccessControl();
			IdentityReference? owner = acl.GetOwner(typeof(NTAccount));
			sb.AppendLine(indent + "Owner: " + (owner?.Value ?? "(unknown)"));
			foreach (FileSystemAccessRule rule in acl.GetAccessRules(true, true, typeof(NTAccount)))
			{
				string who = rule.IdentityReference.Value;
				if (!who.Contains("SYSTEM", StringComparison.OrdinalIgnoreCase)
					&& !who.Contains("NetworkService", StringComparison.OrdinalIgnoreCase)
					&& !who.Contains("LocalService", StringComparison.OrdinalIgnoreCase)
					&& !who.Contains("Administrators", StringComparison.OrdinalIgnoreCase)
					&& !who.Contains("RdpAudit", StringComparison.OrdinalIgnoreCase))
				{
					continue;
				}
				sb.Append(indent).Append(rule.AccessControlType).Append(' ')
					.Append(who).Append(" -> ").Append(rule.FileSystemRights).AppendLine();
			}
		}
		catch (Exception ex)
		{
			sb.AppendLine(indent + "ACL read failed: " + ex.GetType().Name + " — " + ex.Message);
		}
	}

	private static bool CanWrite(string dir)
	{
		try
		{
			string probe = Path.Combine(dir, "._rdpaudit_write_probe_" + Environment.ProcessId + ".tmp");
			File.WriteAllText(probe, "ok");
			File.Delete(probe);
			return true;
		}
		catch
		{
			return false;
		}
	}

	private static bool IsFileLocked(string path)
	{
		try
		{
			using FileStream fs = File.Open(path, FileMode.Open, FileAccess.ReadWrite, FileShare.None);
			return false;
		}
		catch (IOException)
		{
			return true;
		}
		catch (UnauthorizedAccessException)
		{
			return true;
		}
		catch (SecurityException)
		{
			return true;
		}
	}

	private static string FormatExtras(ServiceLayoutInfo layout)
	{
		try
		{
			string programDataRdp = layout.ProgramDataDirectory;
			if (string.IsNullOrEmpty(programDataRdp))
			{
				return "  ProgramData path unknown — no logs to tail.";
			}

			// This local report never talks to IPC — pass sentinel values for the IPC fields so the
			// existing collector contract is satisfied without lying about a probe we did not run.
			ServiceDiagnosticsExtras extras = DiagnosticsExtrasCollector.Collect(
				appSettingsPath:      layout.AppSettingsPath,
				programDataDirectory: programDataRdp,
				ipcOutcome:           "NotProbed",
				ipcErrorDetail:       null,
				ipcErrorType:         null,
				ipcDurationMs:        0,
				ipcTimeoutMs:         0,
				ipcPipeConnected:     false,
				ipcResponseReceived:  false);

			StringBuilder sb = new();
			AppendTail(sb, "ipc-startup.log (logs\\ipc-startup.log)", extras.IpcStartupLogTail);
			AppendTail(sb, "RDPAudit_DEBUG_Log.txt (root)", extras.DebugLogTail);
			AppendTail(sb, "service-*.log (logs\\ — newest)", extras.ServiceLogTail);
			AppendCrash(sb, extras);
			return sb.ToString();
		}
		catch (Exception ex)
		{
			return "  Log extras collector failed: " + ex.GetType().Name + " — " + ex.Message;
		}
	}

	private static void AppendTail(StringBuilder sb, string title, IReadOnlyList<string>? lines)
	{
		sb.AppendLine("  " + title + ":");
		if (lines is null || lines.Count == 0)
		{
			sb.AppendLine("    (empty or missing)");
			sb.AppendLine();
			return;
		}
		foreach (string line in lines)
		{
			sb.Append("    ").AppendLine(line);
		}
		sb.AppendLine();
	}

	private static void AppendCrash(StringBuilder sb, ServiceDiagnosticsExtras extras)
	{
		if (extras.CrashFiles is null || extras.CrashFiles.Count == 0)
		{
			sb.AppendLine("  crash\\: (none)");
			return;
		}
		sb.AppendLine("  crash\\ (" + extras.CrashFiles.Count.ToString(CultureInfo.InvariantCulture) + " file(s)):");
		foreach (string f in extras.CrashFiles)
		{
			sb.AppendLine("    " + f);
		}
		if (!string.IsNullOrEmpty(extras.LastCrashExcerpt))
		{
			sb.AppendLine("  Latest crash excerpt:");
			sb.AppendLine(IndentBlock(extras.LastCrashExcerpt!.TrimEnd(), "    "));
		}
	}

	private static async Task<string> RunConsoleSelfTestAsync(string exePath, CancellationToken ct)
	{
		if (!File.Exists(exePath))
		{
			return "  Installed service executable not found at " + exePath + " — cannot self-test.";
		}

		ProcessStartInfo psi = new()
		{
			FileName               = exePath,
			Arguments              = ConsoleTestArg,
			RedirectStandardOutput = true,
			RedirectStandardError  = true,
			UseShellExecute        = false,
			CreateNoWindow         = true,
			WorkingDirectory       = Path.GetDirectoryName(exePath) ?? Environment.CurrentDirectory,
		};

		StringBuilder stdout = new();
		StringBuilder stderr = new();

		try
		{
			using Process p = new() { StartInfo = psi, EnableRaisingEvents = true };
			p.OutputDataReceived += (_, e) => { if (e.Data is not null) stdout.AppendLine(e.Data); };
			p.ErrorDataReceived  += (_, e) => { if (e.Data is not null) stderr.AppendLine(e.Data); };

			if (!p.Start())
			{
				return "  Process.Start returned false — could not launch service exe.";
			}
			p.BeginOutputReadLine();
			p.BeginErrorReadLine();

			using CancellationTokenSource testCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
			testCts.CancelAfter(ConsoleTestTimeout);

			try
			{
				await p.WaitForExitAsync(testCts.Token).ConfigureAwait(false);
			}
			catch (OperationCanceledException)
			{
				// Service was healthy enough to run for the whole window — kill and report success.
			}

			if (!p.HasExited)
			{
				try { p.Kill(entireProcessTree: true); } catch { /* best effort */ }
				try { await p.WaitForExitAsync(CancellationToken.None).ConfigureAwait(false); } catch { /* best effort */ }
			}

			StringBuilder sb = new();
			sb.AppendLine("  Exit code:           " + p.ExitCode.ToString(CultureInfo.InvariantCulture));
			sb.AppendLine("  Ran for full window: " + (p.ExitCode == 0 || stdout.Length + stderr.Length == 0 ? "unknown" : "no (exited early)"));
			sb.AppendLine("  stdout tail:");
			sb.AppendLine(IndentBlock(TailLines(stdout.ToString(), 40), "    "));
			sb.AppendLine("  stderr tail:");
			sb.AppendLine(IndentBlock(TailLines(stderr.ToString(), 40), "    "));
			return sb.ToString();
		}
		catch (Exception ex)
		{
			return "  Self-test failed: " + ex.GetType().Name + " — " + ex.Message;
		}
	}

	private static string FormatInterpretation(ServiceInstallationInfo? scmInfo)
	{
		StringBuilder sb = new();
		sb.AppendLine("  * Win32ExitCode 1067 (ERROR_PROCESS_ABORTED) means the service process aborted during");
		sb.AppendLine("    startup. Section 3 (event log) and section 7 (log tails) contain the exception; section");
		sb.AppendLine("    8 (console self-test, if enabled) reproduces it in the current console with the full");
		sb.AppendLine("    stack trace visible.");
		sb.AppendLine("  * If section 4 shows 'WindowsDesktop.App 8=NO', install .NET 8 Desktop Runtime x64. This");
		sb.AppendLine("    is required even though the Service itself is a console app because publish.ps1 produces");
		sb.AppendLine("    framework-dependent binaries.");
		sb.AppendLine("  * If section 5 flags invalid JSON, restore appsettings.json from the previous version or");
		sb.AppendLine("    delete it and let the first-run wizard rebuild it.");
		sb.AppendLine("  * If section 6 shows 'Locked=true' on the database, another RdpAudit process still owns");
		sb.AppendLine("    the SQLite file — kill it before restarting the service.");
		if (scmInfo?.Win32ExitCode is 1053)
		{
			sb.AppendLine("  * You are hitting exit 1053 (timeout). ExecuteAsync is running but never returning from");
			sb.AppendLine("    StartAsync inside the 30s SCM window. Look for a blocking synchronous call in");
			sb.AppendLine("    Program.cs or the earliest worker in the DI graph.");
		}
		return sb.ToString();
	}

	// ── Helpers ──────────────────────────────────────────────────────────────────

	private static void AppendSection(StringBuilder sb, string title, Func<string> body)
	{
		sb.AppendLine(title);
		sb.AppendLine(new string('-', title.Length));
		try
		{
			sb.AppendLine(body().TrimEnd());
		}
		catch (Exception ex)
		{
			sb.AppendLine("  Section failed: " + ex.GetType().Name + " — " + ex.Message);
		}
		sb.AppendLine();
	}

	private static async Task AppendSectionAsync(StringBuilder sb, string title, Func<Task<string>> body)
	{
		sb.AppendLine(title);
		sb.AppendLine(new string('-', title.Length));
		try
		{
			string content = await body().ConfigureAwait(false);
			sb.AppendLine(content.TrimEnd());
		}
		catch (Exception ex)
		{
			sb.AppendLine("  Section failed: " + ex.GetType().Name + " — " + ex.Message);
		}
		sb.AppendLine();
	}

	private static string IndentBlock(string text, string indent)
	{
		if (string.IsNullOrEmpty(text))
		{
			return indent + "(empty)";
		}
		StringBuilder sb = new(text.Length + 64);
		foreach (string line in text.Split('\n'))
		{
			sb.Append(indent).AppendLine(line.TrimEnd('\r'));
		}
		return sb.ToString().TrimEnd();
	}

	private static string TruncateMessage(string message, int limit)
	{
		if (message.Length <= limit)
		{
			return message;
		}
		return message.Substring(0, limit) + "…  (" + (message.Length - limit).ToString(CultureInfo.InvariantCulture) + " more chars)";
	}

	private static string TailLines(string text, int lines)
	{
		if (string.IsNullOrEmpty(text))
		{
			return "(empty)";
		}
		string[] all = text.Split('\n');
		if (all.Length <= lines)
		{
			return text.TrimEnd();
		}
		return string.Join('\n', all, all.Length - lines, lines).TrimEnd();
	}
}
