// File:    src/RdpAudit.Configurator/Services/InstallUpdateLogger.cs
// Module:  RdpAudit.Configurator.Services
// Purpose: Persists every install / update step to %ProgramData%\RdpAudit\Logs\install-update-*.log
//          so the operator can attach a single self-contained log to a support ticket and so
//          subsequent diagnostics calls can replay what the previous attempt did. Captures the
//          full step list (including failure detail) and the final actionable verdict text.
//          Every line carries a UTC timestamp, never a localised one. Failure to create or
//          write the log file is swallowed — install/update must not regress because a log
//          sink is unavailable.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System.Globalization;
using System.Text;
using RdpAudit.Core.Util;

namespace RdpAudit.Configurator.Services;

/// <summary>One line in an install / update transcript.</summary>
public sealed record InstallUpdateLogEntry(DateTime UtcTimestamp, string Level, string Message);

/// <summary>Append-only logger writing %ProgramData%\RdpAudit\Logs\install-update-{utc}.log.</summary>
public sealed class InstallUpdateLogger
{
	private const string LogsSubfolder = "Logs";
	private const string FileNamePrefix = "install-update-";

	private readonly object _gate = new();
	private readonly List<InstallUpdateLogEntry> _entries = new();
	private readonly string _logFilePath;
	private bool _initialized;

	public InstallUpdateLogger(ServiceLayoutInfo layout, string operation)
	{
		ArgumentNullException.ThrowIfNull(layout);
		ArgumentException.ThrowIfNullOrWhiteSpace(operation);
		string utcStamp = DateTime.UtcNow.ToString("yyyyMMddTHHmmssZ", CultureInfo.InvariantCulture);
		string fileName = string.Format(CultureInfo.InvariantCulture,
			"{0}{1}-{2}.log", FileNamePrefix, operation, utcStamp);
		string logDir = Path.Combine(layout.ProgramDataDirectory, LogsSubfolder);
		_logFilePath = Path.Combine(logDir, fileName);
		Operation = operation;
	}

	/// <summary>Operation name passed at construction (e.g. "install", "update").</summary>
	public string Operation { get; }

	/// <summary>Path of the log file the entries are appended to. Always populated even if
	/// the directory could not be created — the operator still sees the intended path in the
	/// UI message so they can verify whether the failure was the file system itself.</summary>
	public string LogFilePath => _logFilePath;

	/// <summary>Append a single entry. Never throws.</summary>
	public void Log(string level, string message)
	{
		if (string.IsNullOrEmpty(message))
		{
			return;
		}

		InstallUpdateLogEntry entry = new(DateTime.UtcNow, level ?? "INFO", message);
		lock (_gate)
		{
			_entries.Add(entry);
		}

		AppendToFile(entry);
	}

	/// <summary>Convenience helpers — same shape as a step result.</summary>
	public void Info(string message) => Log("INFO", message);

	public void Warn(string message) => Log("WARN", message);

	public void Fail(string message) => Log("FAIL", message);

	/// <summary>Snapshot of the in-memory entries, oldest-first.</summary>
	public IReadOnlyList<InstallUpdateLogEntry> Snapshot()
	{
		lock (_gate)
		{
			return _entries.ToArray();
		}
	}

	private void AppendToFile(InstallUpdateLogEntry entry)
	{
		try
		{
			lock (_gate)
			{
				if (!_initialized)
				{
					string? dir = Path.GetDirectoryName(_logFilePath);
					if (!string.IsNullOrEmpty(dir))
					{
						Directory.CreateDirectory(dir);
					}

					string header = string.Format(CultureInfo.InvariantCulture,
						"# RdpAudit {0} log — {1}{2}",
						Operation, DateTime.UtcNow.ToString("u", CultureInfo.InvariantCulture), Environment.NewLine);
					File.AppendAllText(_logFilePath, header, Encoding.UTF8);
					_initialized = true;
				}

				string line = string.Format(CultureInfo.InvariantCulture,
					"{0:O} [{1}] {2}{3}",
					entry.UtcTimestamp, entry.Level, entry.Message, Environment.NewLine);
				File.AppendAllText(_logFilePath, line, Encoding.UTF8);
			}
		}
		catch (Exception)
		{
			// Logging failure must never break install/update.
		}
	}
}
