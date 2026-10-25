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

	/// <summary>Journal of faults the Configurator survived: unhandled UI-thread exceptions, unobserved
	/// task faults and exceptions that escaped an event handler. The Configurator is a separate process
	/// from the service, so its last-resort record sits beside the other diagnostics logs and never
	/// mixes with the service's DEBUG mirror or its crash report.</summary>
	public const string ConfiguratorUnhandledLogFileName = "configurator-unhandled.log";

	/// <summary>IPC accept-loop startup/fatal breadcrumb log.</summary>
	public const string IpcStartupLogFileName = "ipc-startup.log";

	/// <summary>Startup-sequence trace written by Program.TimedHostedService.</summary>
	public const string StartupSequenceLogFileName = "startup-sequence.log";

	/// <summary>Durable Zabbix push position: the acknowledged alert id, the sequence counter and
	/// the last accepted batch. Kept beside the other state because it describes delivery, not
	/// evidence, and it must survive a restart for the push to stay exactly-once.</summary>
	public const string ZabbixPushStateFileName = "zabbix-push-state.json";

	/// <summary>EF Core migration failure marker file name.</summary>
	public const string MigrationFailureMarkerFileName = "migration-failure.marker.json";

	/// <summary>Canonical subfolder name for store-integrity state: the durable store fingerprint and the
	/// anomaly marker. Deliberately a folder of its own under ProgramData and NOT inside the database: a
	/// fingerprint stored in the very file it describes could be rewritten together with the tampering it is
	/// supposed to reveal.</summary>
	public const string IntegrityFolderName = "integrity";

	/// <summary>Durable store fingerprint file name (JSON). Kept as the MIGRATION source for stores written
	/// before B19; the live chain lives in <see cref="StoreFingerprintChainFolderName"/>.</summary>
	public const string StoreFingerprintFileName = "store-fingerprint.json";

	/// <summary>Subfolder of <see cref="IntegrityFolderName"/> holding the fingerprint CHAIN: one JSON file per
	/// captured fingerprint, each carrying the digest of its predecessor (B19). A chain rather than a single
	/// rewritten document, so an entry removed from the middle breaks the linkage (ChainBroken) and a removed
	/// tail contradicts the sealed tip (Missing) instead of dissolving into "no data".</summary>
	public const string StoreFingerprintChainFolderName = "fingerprints";

	/// <summary>Prefix of one chain entry file: <c>fingerprint-0000000001.json</c>. Fixed width so the files
	/// sort in chain order in a directory listing.</summary>
	public const string StoreFingerprintChainEntryPrefix = "fingerprint-";

	/// <summary>Sealed tip file name: the protected record of how many chain entries should exist and what
	/// their head digest is. Written through <c>ISecretProtector</c> (DPAPI on Windows), so on this host it is
	/// a protected envelope rather than plain JSON. It is the second, independent store that makes a deleted
	/// chain tail visible; it is NOT unforgeable and no code or document claims otherwise.</summary>
	public const string StoreFingerprintSealedTipFileName = "store-fingerprint-sealed.json";

	/// <summary>Durable write-intent file name (B24): a marker written BEFORE a chain entry is appended and
	/// removed AFTER the sealed tip has been re-sealed, so a capture cut short between those two steps is
	/// distinguishable from a rollback. Deliberately a SIBLING of the tip and not a file inside
	/// <see cref="StoreFingerprintChainFolderName"/>: the chain reader lists that folder by entry prefix, and a
	/// marker in there would sit next to the entries it describes.</summary>
	public const string StoreFingerprintWriteIntentFileName = "store-fingerprint-intent.json";

	/// <summary>Marker file written when a start-up comparison found a store-integrity anomaly.</summary>
	public const string StoreIntegrityAnomalyMarkerFileName = "store-integrity-anomaly.json";

	/// <summary>Canonical web-UI folder name under the data root (IIS physical path plus shared secrets).</summary>
	public const string WebUiFolderName = "WebUI";

	/// <summary>Subfolder of the web-UI folder holding the static dashboard content served by IIS
	/// (the <c>wwwroot</c> content of the published web application).</summary>
	public const string WebUiWwwRootFolderName = "wwwroot";

	/// <summary>Subfolder of the web-UI folder holding secrets shared with the web proxy (bearer token).</summary>
	public const string WebUiSecretsFolderName = "secrets";

	/// <summary>Shared web-UI bearer token file name (a DPAPI protected envelope, never plaintext).</summary>
	public const string WebUiTokenFileName = "token.dat";

	private readonly string _programDataDirectory;
	private readonly string _logDirectory;
	private readonly string _crashDirectory;
	private readonly string _backupsDirectory;
	private readonly string _actionsRootDirectory;
	private readonly string _appSettingsPath;
	private readonly string _databasePath;
	private readonly string _serviceLogPrefix;
	private readonly string _debugLogPath;
	private readonly string _configuratorUnhandledLogPath;
	private readonly string _ipcStartupLogPath;
	private readonly string _startupSequenceLogPath;
	private readonly string _zabbixPushStatePath;
	private readonly string _crashReportPath;
	private readonly string _migrationFailureMarkerPath;
	private readonly string _integrityDirectory;
	private readonly string _storeFingerprintPath;
	private readonly string _storeFingerprintChainDirectory;
	private readonly string _storeFingerprintSealedTipPath;
	private readonly string _storeFingerprintWriteIntentPath;
	private readonly string _storeIntegrityAnomalyMarkerPath;
	private readonly string _webUiDirectory;
	private readonly string _webUiWwwRootDirectory;
	private readonly string _webUiSecretsDirectory;
	private readonly string _webUiTokenPath;

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
		_configuratorUnhandledLogPath = Path.Combine(_logDirectory, ConfiguratorUnhandledLogFileName);
		_ipcStartupLogPath = Path.Combine(_logDirectory, IpcStartupLogFileName);
		_startupSequenceLogPath = Path.Combine(_logDirectory, StartupSequenceLogFileName);
		_zabbixPushStatePath = Path.Combine(_programDataDirectory, ZabbixPushStateFileName);
		_crashReportPath = Path.Combine(_crashDirectory, CrashReportFileName);
		_migrationFailureMarkerPath = Path.Combine(_programDataDirectory, MigrationFailureMarkerFileName);
		_integrityDirectory = Path.Combine(_programDataDirectory, IntegrityFolderName);
		_storeFingerprintPath = Path.Combine(_integrityDirectory, StoreFingerprintFileName);
		_storeFingerprintChainDirectory = Path.Combine(_integrityDirectory, StoreFingerprintChainFolderName);
		_storeFingerprintSealedTipPath = Path.Combine(_integrityDirectory, StoreFingerprintSealedTipFileName);
		_storeFingerprintWriteIntentPath = Path.Combine(_integrityDirectory, StoreFingerprintWriteIntentFileName);
		_storeIntegrityAnomalyMarkerPath = Path.Combine(_integrityDirectory, StoreIntegrityAnomalyMarkerFileName);
		_webUiDirectory = Path.Combine(_programDataDirectory, WebUiFolderName);
		_webUiWwwRootDirectory = Path.Combine(_webUiDirectory, WebUiWwwRootFolderName);
		_webUiSecretsDirectory = Path.Combine(_webUiDirectory, WebUiSecretsFolderName);
		_webUiTokenPath = Path.Combine(_webUiSecretsDirectory, WebUiTokenFileName);
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

	/// <summary>Absolute Configurator last-resort fault journal path
	/// (logs\configurator-unhandled.log).</summary>
	public string ConfiguratorUnhandledLogPath => _configuratorUnhandledLogPath;

	/// <summary>Absolute IPC startup breadcrumb log path.</summary>
	public string IpcStartupLogPath => _ipcStartupLogPath;

	/// <summary>Absolute startup-sequence trace path.</summary>
	public string StartupSequenceLogPath => _startupSequenceLogPath;

	/// <summary>Absolute path of the Zabbix push position
	/// (<c>%ProgramData%\RdpAudit\zabbix-push-state.json</c>).</summary>
	public string ZabbixPushStatePath => _zabbixPushStatePath;

	/// <summary>Absolute CrashGuard fallback report path (crash\rdpaudit-service-crash.txt).</summary>
	public string CrashReportPath => _crashReportPath;

	/// <summary>Absolute EF Core migration failure marker path.</summary>
	public string MigrationFailureMarkerPath => _migrationFailureMarkerPath;

	/// <summary>Absolute store-integrity folder (<c>%ProgramData%\RdpAudit\integrity</c>).</summary>
	public string IntegrityDirectory => _integrityDirectory;

	/// <summary>Absolute durable store-fingerprint path (the pre-B19 single document; read once for
	/// migration, then left in place as history).</summary>
	public string StoreFingerprintPath => _storeFingerprintPath;

	/// <summary>Absolute folder holding the store-fingerprint chain (<c>integrity\fingerprints</c>).</summary>
	public string StoreFingerprintChainDirectory => _storeFingerprintChainDirectory;

	/// <summary>Absolute path of the sealed fingerprint-chain tip (a protected envelope).</summary>
	public string StoreFingerprintSealedTipPath => _storeFingerprintSealedTipPath;

	/// <summary>Absolute path of the durable fingerprint write intent (B24). Exists only between appending a
	/// chain entry and re-sealing the tip; its presence after a restart is what a capture interrupted between
	/// those two steps leaves behind.</summary>
	public string StoreFingerprintWriteIntentPath => _storeFingerprintWriteIntentPath;

	/// <summary>Absolute store-integrity anomaly marker path.</summary>
	public string StoreIntegrityAnomalyMarkerPath => _storeIntegrityAnomalyMarkerPath;

	/// <summary>Absolute web-UI folder (<c>%ProgramData%\RdpAudit\WebUI</c>): the IIS physical path and the
	/// parent of the proxy's secret store.</summary>
	public string WebUiDirectory => _webUiDirectory;

	/// <summary>Absolute static content root (<c>%ProgramData%\RdpAudit\WebUI\wwwroot</c>): the
	/// published static dashboard files served by IIS through the web application.</summary>
	public string WebUiWwwRootDirectory => _webUiWwwRootDirectory;

	/// <summary>Absolute web-UI secrets folder (<c>%ProgramData%\RdpAudit\WebUI\secrets</c>), read by the IIS
	/// application-pool identity and the service; hardened by the storage ACL policy.</summary>
	public string WebUiSecretsDirectory => _webUiSecretsDirectory;

	/// <summary>Absolute shared web-UI bearer token path (<c>%ProgramData%\RdpAudit\WebUI\secrets\token.dat</c>):
	/// a DPAPI protected envelope, never plaintext.</summary>
	public string WebUiTokenPath => _webUiTokenPath;

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
