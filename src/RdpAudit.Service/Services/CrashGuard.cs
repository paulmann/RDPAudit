// File:    src/RdpAudit.Service/Services/CrashGuard.cs
// Module:  RdpAudit.Service.Services
// Purpose: Process-wide last-resort crash diagnostics. Installs AppDomain.UnhandledException and
//          TaskScheduler.UnobservedTaskException handlers so a fault anywhere in the service is
//          recorded as a Critical OperationLog (when the database is reachable) and always to the
//          Windows Event Log and a plain fallback file under ProgramData — even if the host is dying.
//          Also logs a structured startup-diagnostics record (version, paths, PID, architecture,
//          DEBUG mode, log depth) so a crash can be correlated with the exact build and configuration
//          that produced it. Every path here is best-effort and self-contained: the crash logger must
//          never throw.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System.Diagnostics;
using System.Reflection;
using System.Runtime.InteropServices;
using Microsoft.Extensions.Logging;
using RdpAudit.Core.Config;
using RdpAudit.Core.Data;
using RdpAudit.Core.Models;

namespace RdpAudit.Service.Services;

/// <summary>Installs last-resort unhandled-exception handlers and emits startup diagnostics.</summary>
public sealed class CrashGuard
{
	private const string EventSource = "RdpAuditService";
	private const string EventLogName = "Application";

	private readonly IOperationLogWriter _opLog;
	private readonly ILogger<CrashGuard> _logger;
	private readonly string _fallbackDir;

	public CrashGuard(IOperationLogWriter opLog, ILogger<CrashGuard> logger)
	{
		_opLog = opLog;
		_logger = logger;
		string programData = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
		_fallbackDir = Path.Combine(programData, "RdpAudit", "crash");
	}

	/// <summary>Installs the global unhandled-exception and unobserved-task handlers exactly once.</summary>
	public void Install()
	{
		AppDomain.CurrentDomain.UnhandledException += OnUnhandledException;
		TaskScheduler.UnobservedTaskException += OnUnobservedTaskException;
	}

	/// <summary>Writes a structured startup-diagnostics record (build, paths, PID, arch, DEBUG, log
	/// depth). Best-effort; never throws.</summary>
	public void LogStartupDiagnostics(RdpAuditOptions options, string configPath)
	{
		try
		{
			Assembly asm = typeof(CrashGuard).Assembly;
			string version = asm.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion
				?? asm.GetName().Version?.ToString()
				?? "unknown";
			string exePath = ResolveProcessPath();
			string dbPath = SafeResolveDbPath(options);

			string details = string.Join("; ", new[]
			{
				$"Version={version}",
				$"ExePath={exePath}",
				$"DbPath={dbPath}",
				$"ConfigPath={configPath}",
				$"Pid={Environment.ProcessId}",
				$"Arch={RuntimeInformation.ProcessArchitecture}",
				$"OS={RuntimeInformation.OSDescription}",
				$"DebugMode={options.Diagnostics.DebugMode}",
				$"LogViewDepthDays={options.Logs.ResolveViewDepthDays()}",
				$"LogRetentionDays={options.Logs.ResolveRetentionDays()}",
			});

			_logger.LogInformation("Service startup diagnostics: {Details}", details);

			// Fire-and-forget durable record; the writer is best-effort and swallows failures.
			_ = _opLog.WriteAsync(new OperationLogEntry
			{
				Severity = OperationLogSeverity.Information,
				Source = "Service",
				Operation = "ServiceStartup",
				Message = $"Service started (v{version}, pid {Environment.ProcessId}).",
				DetailsJson = ToJson(details),
				Actor = "Service",
			});
		}
		catch (Exception ex)
		{
			_logger.LogWarning(ex, "Failed to log startup diagnostics");
		}
	}

	private void OnUnhandledException(object sender, UnhandledExceptionEventArgs e)
	{
		Exception? ex = e.ExceptionObject as Exception;
		RecordCrash("AppDomain.UnhandledException", ex, terminating: e.IsTerminating);
	}

	private void OnUnobservedTaskException(object? sender, UnobservedTaskExceptionEventArgs e)
	{
		// Mark observed so a stray faulted task does not, by itself, escalate to process termination.
		e.SetObserved();
		RecordCrash("TaskScheduler.UnobservedTaskException", e.Exception, terminating: false);
	}

	private void RecordCrash(string origin, Exception? ex, bool terminating)
	{
		string summary = $"{origin}: {ex?.GetType().FullName ?? "unknown"}: {ex?.Message ?? "(no message)"} (terminating={terminating})";

		// 1) Structured logger (file + Event Log sink) — synchronous, already configured.
		try
		{
			_logger.LogCritical(ex, "Unhandled fault ({Origin}, terminating={Terminating})", origin, terminating);
		}
		catch
		{
			// ignored — fall through to the lower-level sinks
		}

		// 2) Plain fallback file — survives even if logging/DI is torn down.
		WriteFallbackFile(summary, ex);

		// 3) Windows Event Log directly — independent of the Serilog pipeline.
		WriteEventLog(summary + Environment.NewLine + ex);

		// 4) Durable OperationLog when the database is reachable. Best-effort and bounded so we do not
		//    hang a terminating process; the writer self-swallows any failure.
		try
		{
			Task write = _opLog.WriteAsync(new OperationLogEntry
			{
				Severity = OperationLogSeverity.Critical,
				Source = "Service",
				Operation = "UnhandledException",
				Message = summary,
				Exception = ex,
				Actor = origin,
			});
			write.Wait(TimeSpan.FromSeconds(3));
		}
		catch
		{
			// ignored — the fallback file and Event Log already captured the fault
		}
	}

	private void WriteFallbackFile(string summary, Exception? ex)
	{
		try
		{
			Directory.CreateDirectory(_fallbackDir);
			string path = Path.Combine(_fallbackDir, $"crash-{DateTime.UtcNow:yyyyMMdd-HHmmss-fff}.log");
			string content = $"UTC: {DateTime.UtcNow:O}{Environment.NewLine}{summary}{Environment.NewLine}{Environment.NewLine}{ex}";
			File.WriteAllText(path, content);
		}
		catch
		{
			// ignored — last-resort sink; nothing else we can do
		}
	}

	private static void WriteEventLog(string message)
	{
		if (!OperatingSystem.IsWindows())
		{
			return;
		}

		try
		{
			if (!EventLog.SourceExists(EventSource))
			{
				// Creating a source requires admin; the service installer normally registers it. If it
				// is missing we silently skip rather than throw from the crash path.
				return;
			}

			using EventLog log = new(EventLogName) { Source = EventSource };
			string trimmed = message.Length > 31000 ? message[..31000] : message;
			log.WriteEntry(trimmed, EventLogEntryType.Error);
		}
		catch
		{
			// ignored — Event Log may be unavailable in some environments
		}
	}

	private static string ResolveProcessPath()
	{
		return Environment.ProcessPath
			?? AppContext.BaseDirectory.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
	}

	private static string SafeResolveDbPath(RdpAuditOptions options)
	{
		try
		{
			return Path.GetFullPath(options.Storage.ResolveDatabasePath());
		}
		catch
		{
			return "(unresolved)";
		}
	}

	private static string ToJson(string detail)
	{
		// Keep this dependency-free and trivially safe: wrap the already-formatted detail string.
		string escaped = detail.Replace("\\", "\\\\").Replace("\"", "\\\"");
		return $"{{\"detail\":\"{escaped}\"}}";
	}
}
