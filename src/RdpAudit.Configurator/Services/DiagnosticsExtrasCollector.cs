// File:    src/RdpAudit.Configurator/Services/DiagnosticsExtrasCollector.cs
// Module:  RdpAudit.Configurator.Services
// Purpose: Collects the deep-diagnostics bundle (ServiceDiagnosticsExtras) for the Service tab
//          "Copy diagnostics" report: DebugMode as actually persisted in appsettings.json (read
//          directly from disk, independent of IPC, so it is trustworthy even when the service is
//          unreachable), the detailed IPC round-trip outcome from IpcClient.SendDetailedAsync, the
//          tail of every log artifact the service produces -- %ProgramData%\RdpAudit\logs\ipc-startup.log,
//          %ProgramData%\RdpAudit\RDPAudit_DEBUG_Log.txt (root, not logs\ -- matches Program.ConfigureSerilog),
//          %ProgramData%\RdpAudit\logs\service-*.log -- and a listing of CrashGuard's crash folder with
//          the most recent crash file's full text. All file I/O is best-effort and swallows errors so
//          a missing/locked file never prevents the rest of the report from rendering.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System.Text.Json;
using RdpAudit.Core.Util;

namespace RdpAudit.Configurator.Services;

/// <summary>Best-effort collector for the Copy diagnostics report's deep-diagnostics bundle.</summary>
public static class DiagnosticsExtrasCollector
{
	private const int LogTailLines = 40;
	private const int MaxCrashExcerptChars = 8_000;

	/// <summary>Reads everything <see cref="ServiceDiagnosticsExtras"/> needs from disk plus the
	/// already-completed IPC probe result. Never throws — every source is wrapped so one missing
	/// file cannot blank out the rest of the report.</summary>
	public static ServiceDiagnosticsExtras Collect(
		string appSettingsPath,
		string programDataDirectory,
		string? ipcOutcome,
		string? ipcErrorDetail,
		string? ipcErrorType,
		long ipcDurationMs,
		int ipcTimeoutMs,
		bool ipcPipeConnected,
		bool ipcResponseReceived)
	{
		string logsDir = Path.Combine(programDataDirectory, "logs");
		string crashDir = Path.Combine(programDataDirectory, "crash");

		bool? diskDebugMode = ReadDiskDebugMode(appSettingsPath);

		IReadOnlyList<string> ipcStartupTail = ReadTail(Path.Combine(logsDir, "ipc-startup.log"));
		IReadOnlyList<string> debugLogTail = ReadTail(Path.Combine(programDataDirectory, "RDPAudit_DEBUG_Log.txt"));
		IReadOnlyList<string> serviceLogTail = ReadNewestMatchingTail(logsDir, "service-*.log");

		(IReadOnlyList<string> crashFiles, string? lastCrashExcerpt) = ReadCrashFolder(crashDir);

		return new ServiceDiagnosticsExtras(
			DiskDebugModeEnabled: diskDebugMode,
			IpcOutcome: ipcOutcome,
			IpcErrorDetail: ipcErrorDetail,
			IpcErrorType: ipcErrorType,
			IpcDurationMs: ipcDurationMs,
			IpcTimeoutMs: ipcTimeoutMs,
			IpcPipeConnected: ipcPipeConnected,
			IpcResponseReceived: ipcResponseReceived,
			IpcStartupLogTail: ipcStartupTail,
			DebugLogTail: debugLogTail,
			ServiceLogTail: serviceLogTail,
			CrashFiles: crashFiles,
			LastCrashExcerpt: lastCrashExcerpt);
	}

	/// <summary>Reads RdpAudit:Diagnostics:DebugMode straight from appsettings.json on disk. Returns
	/// null when the file is missing, locked, or the JSON cannot be parsed — the report then shows
	/// "(appsettings.json unreadable)" instead of a misleading false.</summary>
	private static bool? ReadDiskDebugMode(string appSettingsPath)
	{
		try
		{
			if (!File.Exists(appSettingsPath))
			{
				return null;
			}

			using FileStream stream = new(appSettingsPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
			using JsonDocument doc = JsonDocument.Parse(stream);
			if (doc.RootElement.TryGetProperty("RdpAudit", out JsonElement rdpAudit)
				&& rdpAudit.TryGetProperty("Diagnostics", out JsonElement diagnostics)
				&& diagnostics.TryGetProperty("DebugMode", out JsonElement debugMode)
				&& debugMode.ValueKind is JsonValueKind.True or JsonValueKind.False)
			{
				return debugMode.GetBoolean();
			}

			return null;
		}
		catch (Exception)
		{
			return null;
		}
	}

	/// <summary>Returns the last <see cref="LogTailLines"/> lines of <paramref name="path"/>, or an
	/// empty list when the file does not exist / cannot be read.</summary>
	private static IReadOnlyList<string> ReadTail(string path)
	{
		try
		{
			if (!File.Exists(path))
			{
				return Array.Empty<string>();
			}

			using FileStream stream = new(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
			using StreamReader reader = new(stream);
			List<string> all = new();
			string? line;
			while ((line = reader.ReadLine()) is not null)
			{
				all.Add(line);
			}

			return all.Count <= LogTailLines
				? all
				: all.GetRange(all.Count - LogTailLines, LogTailLines);
		}
		catch (Exception ex)
		{
			return new[] { "(failed to read log: " + ex.GetType().Name + ": " + ex.Message + ")" };
		}
	}

	/// <summary>Finds the most recently written file matching <paramref name="pattern"/> under
	/// <paramref name="dir"/> (the day-rolling Serilog file uses a date-stamped name) and returns
	/// its tail.</summary>
	private static IReadOnlyList<string> ReadNewestMatchingTail(string dir, string pattern)
	{
		try
		{
			if (!Directory.Exists(dir))
			{
				return Array.Empty<string>();
			}

			string? newest = Directory.EnumerateFiles(dir, pattern)
				.OrderByDescending(File.GetLastWriteTimeUtc)
				.FirstOrDefault();

			return newest is null ? Array.Empty<string>() : ReadTail(newest);
		}
		catch (Exception ex)
		{
			return new[] { "(failed to enumerate logs: " + ex.GetType().Name + ": " + ex.Message + ")" };
		}
	}

	/// <summary>Lists crash-folder file names newest-first, and returns the full text of the most
	/// recent one (bounded to <see cref="MaxCrashExcerptChars"/> so one huge dump cannot blow up the
	/// report / clipboard).</summary>
	private static (IReadOnlyList<string> Files, string? LastExcerpt) ReadCrashFolder(string crashDir)
	{
		try
		{
			if (!Directory.Exists(crashDir))
			{
				return (Array.Empty<string>(), null);
			}

			List<string> files = Directory.EnumerateFiles(crashDir)
				.OrderByDescending(File.GetLastWriteTimeUtc)
				.Select(Path.GetFileName)
				.Where(name => name is not null)
				.Select(name => name!)
				.ToList();

			if (files.Count == 0)
			{
				return (files, null);
			}

			string newestPath = Path.Combine(crashDir, files[0]);
			string text = File.ReadAllText(newestPath);
			string excerpt = text.Length > MaxCrashExcerptChars
				? text[..MaxCrashExcerptChars] + Environment.NewLine + "(truncated)"
				: text;

			return (files, excerpt);
		}
		catch (Exception ex)
		{
			return (new[] { "(failed to enumerate crash folder: " + ex.GetType().Name + ")" }, null);
		}
	}
}
