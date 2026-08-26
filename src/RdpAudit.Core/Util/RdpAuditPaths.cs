// File:    src/RdpAudit.Core/Util/RdpAuditPaths.cs
// Module:  RdpAudit.Core.Util
// Purpose: Single source of truth for every RdpAudit runtime path derived from
//          %ProgramData%\RdpAudit. All producers and consumers across Core,
//          Service and Configurator must resolve their paths here instead of
//          calling Environment.GetFolderPath(CommonApplicationData) and
//          concatenating "RdpAudit" locally; a one-off path spelled by hand in
//          another assembly is a defect waiting to drift when the layout changes.
//          The class is intentionally free of I/O side effects: constructing or
//          resolving paths never creates directories or files, which lets unit
//          tests build layouts under a fake root and guarantees the test suite
//          never touches the real %ProgramData%.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System.Globalization;

namespace RdpAudit.Core.Util;

/// <summary>Resolves the canonical RdpAudit on-disk layout. Construct with the default
/// machine root (production) or with an explicit root override (unit tests / custom
/// installs). Every property is computed once at construction; the instance is immutable.</summary>
public sealed class RdpAuditPaths
{
	private static readonly Lazy<RdpAuditPaths> LazyDefault = new(
		static () => new RdpAuditPaths(ResolveMachineProgramDataRoot()),
		LazyThreadSafetyMode.ExecutionAndPublication);

	/// <summary>Production layout backed by the machine's actual CommonApplicationData folder.</summary>
	public static RdpAuditPaths Default => LazyDefault.Value;

	/// <summary>Canonical root directory name under CommonApplicationData.</summary>
	public const string ProgramDataFolderName = "RdpAudit";

	/// <summary>Canonical logs subfolder name.</summary>
	public const string LogsFolderName = "logs";

	/// <summary>Canonical crash dump subfolder name (CrashGuard's last-resort dump folder).</summary>
	public const string CrashFolderName = "crash";

	/// <summary>Canonical backups subfolder name (see RdpAudit.Core.Backup.BackupLayout).</summary>
	public const string BackupsFolderName = "Backups";

	/// <summary>Canonical per-IP forensic actions shard root (see ShardPath.ActionsRootFolder).</summary>
	public const string ActionsRootFolderName = "actions";

	/// <summary>Default SQLite database file name.</summary>
	public const string DatabaseFileName = "rdpaudit.db";

	/// <summary>Default settings file name.</summary>
	public const string AppSettingsFileName = "appsettings.json";

	/// <summary>CrashGuard fallback crash report file name.</summary>
	public const string CrashReportFileName = "rdpaudit-service-crash.txt";

	/// <summary>Structured Serilog file prefix (day-rolling service-*.log).</summary>
	public const string ServiceLogFilePrefix = "service-";

	/// <summary>Serilog service log extension.</summary>
	public const string ServiceLogExtension = ".log";

	/// <summary>Persistent human-readable DEBUG mirror requested by operators.</summary>
	public const string DebugLogFileName = "RDPAudit_DEBUG_Log.txt";

	/// <summary>IPC accept-loop startup/fatal breadcrumb log.</summary>
	public const string IpcStartupLogFileName = "ipc-startup.log";

	/// <summary>Startup-sequence trace written by Program.TimedHostedService.</summary>
	public const string StartupSequenceLogFileName = "startup-sequence.log";

	/// <summary>EF Core migration failure marker file name.</summary>
	public const string MigrationFailureMarkerFileName = "migration-failure.marker.json";

	private readonly string _programDataDirectory;
	private readonly string _logDirectory;
	private readonly string _crashDirectory;
	private readonly string _backupsDirectory;
	private readonly string _actionsRootDirectory;
	private readonly string _appSettingsPath;
	private readonly string _databasePath;
	private readonly string _serviceLogPrefix;
	private readonly string _debugLogPath;
	private readonly string _ipcStartupLogPath;
	private readonly string _startupSequenceLogPath;
	private readonly string _crashReportPath;
	private readonly string _migrationFailureMarkerPath;

	/// <summary>Creates the layout rooted at <paramref name="programDataRoot"/>.
	/// The parameter is the RdpAudit product directory itself (typically
	/// <c>...\CommonApplicationData\RdpAudit</c>); unit tests may pass a temp folder.</summary>
	public RdpAuditPaths(string programDataRoot)
	{
		ArgumentException.ThrowIfNullOrWhiteSpace(programDataRoot);
		_programDataDirectory = Path.GetFullPath(programDataRoot);
		_logDirectory = Path.Combine(_programDataDirectory, LogsFolderName);
		_crashDirectory = Path.Combine(_programDataDirectory, CrashFolderName);
		_backupsDirectory = Path.Combine(_programDataDirectory, BackupsFolderName);
		_actionsRootDirectory = Path.Combine(_programDataDirectory, ActionsRootFolderName);
		_appSettingsPath = Path.Combine(_programDataDirectory, AppSettingsFileName);
		_databasePath = Path.Combine(_programDataDirectory, DatabaseFileName);
		_serviceLogPrefix = Path.Combine(_logDirectory, ServiceLogFilePrefix);
		_debugLogPath = Path.Combine(_logDirectory, DebugLogFileName);
		_ipcStartupLogPath = Path.Combine(_logDirectory, IpcStartupLogFileName);
		_startupSequenceLogPath = Path.Combine(_logDirectory, StartupSequenceLogFileName);
		_crashReportPath = Path.Combine(_crashDirectory, CrashReportFileName);
		_migrationFailureMarkerPath = Path.Combine(_programDataDirectory, MigrationFailureMarkerFileName);
	}

	/// <summary>Absolute <c>%ProgramData%\RdpAudit</c> root. All other properties sit under it.</summary>
	public string ProgramDataDirectory => _programDataDirectory;

	/// <summary>Absolute logs directory (<c>%ProgramData%\RdpAudit\logs</c>).</summary>
	public string LogDirectory => _logDirectory;

	/// <summary>Absolute crash dump directory (<c>%ProgramData%\RdpAudit\crash</c>).</summary>
	public string CrashDirectory => _crashDirectory;

	/// <summary>Absolute backups directory (<c>%ProgramData%\RdpAudit\Backups</c>).</summary>
	public string BackupsDirectory => _backupsDirectory;

	/// <summary>Absolute per-IP actions shard root (<c>%ProgramData%\RdpAudit\actions</c>).</summary>
	public string ActionsRootDirectory => _actionsRootDirectory;

	/// <summary>Absolute appsettings.json path.</summary>
	public string AppSettingsPath => _appSettingsPath;

	/// <summary>Absolute default SQLite database path.</summary>
	public string DatabasePath => _databasePath;

	/// <summary>Day-rolling structured Serilog file prefix (logs\service-).</summary>
	public string ServiceLogPrefix => _serviceLogPrefix;

	/// <summary>Absolute DEBUG mirror log path (logs\RDPAudit_DEBUG_Log.txt).</summary>
	public string DebugLogPath => _debugLogPath;

	/// <summary>Absolute IPC startup breadcrumb log path.</summary>
	public string IpcStartupLogPath => _ipcStartupLogPath;

	/// <summary>Absolute startup-sequence trace path.</summary>
	public string StartupSequenceLogPath => _startupSequenceLogPath;

	/// <summary>Absolute CrashGuard fallback report path (crash\rdpaudit-service-crash.txt).</summary>
	public string CrashReportPath => _crashReportPath;

	/// <summary>Absolute EF Core migration failure marker path.</summary>
	public string MigrationFailureMarkerPath => _migrationFailureMarkerPath;

	/// <summary>Resolves the machine CommonApplicationData\RdpAudit root for production use.</summary>
	private static string ResolveMachineProgramDataRoot()
	{
		string root = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
		return Path.Combine(root, ProgramDataFolderName);
	}
}

/// <summary>Abstraction over <see cref="RdpAuditPaths"/> for injectable path resolution.
/// Production code registers <see cref="DefaultRdpAuditPathsProvider"/>; tests register a
/// fake rooted at a temp directory so no test-run I/O ever lands in the real %ProgramData%.</summary>
public interface IRdpAuditPathsProvider
{
	/// <summary>The single layout used for every path resolution.</summary>
	RdpAuditPaths Paths { get; }
}

/// <summary>Production path provider backed by <see cref="RdpAuditPaths.Default"/>.</summary>
public sealed class DefaultRdpAuditPathsProvider : IRdpAuditPathsProvider
{
	/// <inheritdoc />
	public RdpAuditPaths Paths => RdpAuditPaths.Default;
}

/// <summary>Shared file-size-capped rotation for the diagnostics append-only logs
/// (ipc-startup.log, startup-sequence.log). When the file exceeds the size cap it is deleted
/// before the next append so the log restarts instead of growing unbounded. Pure until
/// <see cref="AppendLine"/> is invoked; callers keep their own best-effort try/catch policy.</summary>
public static class DiagnosticLogRotation
{
	/// <summary>Default per-file cap shared by the two diagnostics logs (512 KiB).</summary>
	public const long DefaultMaxBytes = 512 * 1024;

	/// <summary>Appends a line to <paramref name="filePath"/>, rotating the file away when
	/// it already exceeds <paramref name="maxBytes"/>. Creates the containing directory on
	/// first use. Throws on I/O failure; callers wrap with their own swallow policy.</summary>
	public static void AppendLine(string filePath, string line, long maxBytes = DefaultMaxBytes)
	{
		ArgumentException.ThrowIfNullOrWhiteSpace(filePath);
		ArgumentException.ThrowIfNullOrWhiteSpace(line);
		ArgumentOutOfRangeException.ThrowIfNegativeOrZero(maxBytes);

		string? dir = Path.GetDirectoryName(filePath);
		if (!string.IsNullOrEmpty(dir))
		{
			Directory.CreateDirectory(dir);
		}

		FileInfo fi = new(filePath);
		if (fi.Exists && fi.Length > maxBytes)
		{
			File.Delete(filePath);
		}

		File.AppendAllText(filePath, line + Environment.NewLine);
	}
}
