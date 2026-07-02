// File:    src/RdpAudit.Core/Util/ServiceDiagnosticsReport.cs
// Module:  RdpAudit.Core.Util
// Purpose: Plain-text "Copy diagnostics" report assembled from the three independent inputs
//          the Service tab already aggregates (SCM snapshot + installed/distribution binary
//          fingerprints + IPC runtime telemetry). Produces a single English block the
//          operator can paste straight into a support ticket. The high-level verdict line —
//          OK / Publish not installed / Installed path missing / Running old binary /
//          Service path mismatch / Hash mismatch / IPC connected to unexpected binary — is
//          derived solely from the inputs so it never disagrees with the Service tab labels.
//          Pure formatting; no I/O. Caller passes pre-read fingerprints and SCM data.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System.Globalization;
using System.Text;

namespace RdpAudit.Core.Util;

/// <summary>One of the verdicts surfaced in the Copy diagnostics report.</summary>
public enum ServiceDiagnosticsVerdict
{
	/// <summary>Distribution, installed binary, running binary, and IPC all agree.</summary>
	Ok,

	/// <summary>The publish folder is missing or empty — the Configurator has nothing to install.</summary>
	PublishNotInstalled,

	/// <summary>SCM has the service registered but the on-disk binary at the ImagePath is gone.</summary>
	InstalledPathMissing,

	/// <summary>The installed binary on disk has been updated but the host process is still
	/// running the previous image.</summary>
	RunningOldBinary,

	/// <summary>SCM ImagePath does not point at the configured install directory — typically a
	/// stale registration from a previous install location.</summary>
	ServicePathMismatch,

	/// <summary>The installed binary's SHA-256 differs from the distribution binary even though
	/// both files exist — the install directory is out of date.</summary>
	HashMismatch,

	/// <summary>IPC reports a runtime version that is not consistent with either the installed
	/// or distribution binary on disk — the talking process is not the one we shipped.</summary>
	IpcConnectedToUnexpectedBinary,

	/// <summary>The service is not installed at all — no SCM registration.</summary>
	NotInstalled,

	/// <summary>Distribution binary is not present on disk for comparison.</summary>
	DistributionMissing,
}

/// <summary>Snapshot of a running process used by the diagnostics report.</summary>
public sealed record RunningProcessFingerprint(
	int? ProcessId,
	string? MainModulePath,
	BinaryFingerprint? MainModuleFingerprint,
	DateTime? StartTimeUtc);

/// <summary>Aggregate diagnostic input for <see cref="ServiceDiagnosticsReportBuilder.Build"/>.</summary>
public sealed record ServiceDiagnosticsInput(
	string ConfiguratorVersion,
	ServiceLayoutInfo Layout,
	ServiceInstallationInfo Scm,
	BinaryFingerprint Distribution,
	BinaryFingerprint Installed,
	RunningProcessFingerprint Running,
	string? IpcRuntimeVersion,
	bool IpcConnected,
	// Optional deep-diagnostics bundle (IPC round-trip detail, DebugMode-on-disk vs UI, log-file
	// tails, crash folder listing). Null for callers that only need the legacy
	// SCM/binary/IPC-connected summary (e.g. existing unit tests) — the report simply omits the
	// extra sections in that case. (XML <param> doc comments are not valid on individual positional
	// record parameters in C#, hence plain // comments here; see the <summary> on
	// ServiceDiagnosticsExtras below for the documented type.)
	ServiceDiagnosticsExtras? Extras = null);

/// <summary>Deep-diagnostics bundle collected alongside the legacy <see cref="ServiceDiagnosticsInput"/>
/// fields so a single "Copy diagnostics" click gives enough detail to root-cause "service not
/// responding" reports without a second round of back-and-forth: the exact IPC failure mode
/// (SendDetailedAsync outcome), whether DebugMode on disk actually matches what the Settings tab
/// checkbox shows (the two can disagree when Save failed because IPC was already down), and the
/// tail of every log artifact IpcServerWorker / Program.ConfigureSerilog / CrashGuard produce.
/// Field notes (plain comments, not XML doc, since C# does not allow /// on individual positional
/// record parameters):
///   DiskDebugModeEnabled  - RdpAudit:Diagnostics:DebugMode read directly from appsettings.json on
///                           disk, independent of IPC, so it stays trustworthy even when the
///                           service cannot be reached.
///   IpcOutcome            - IpcCallOutcome.ToString() from the GetStatus probe (e.g.
///                           "ConnectFailed", "Timeout", "ServiceError", "Success"); null when no
///                           probe was attempted.
///   IpcErrorDetail        - Curated error text from IpcCallResult (service-supplied or transport
///                           description).
///   IpcErrorType          - Exception / category name for the IPC failure (e.g. "TimeoutException").
///   IpcPipeConnected      - True once NamedPipeClientStream.ConnectAsync succeeded -- distinguishes
///                           a stopped service (pipe refuses connections) from one that connected
///                           but did not answer in time.
///   IpcStartupLogTail     - Last lines of %ProgramData%\RdpAudit\logs\ipc-startup.log
///                           (IpcServerWorker startup / fatal breadcrumbs), oldest first. Empty
///                           when the file does not exist yet.
///   DebugLogTail          - Last lines of %ProgramData%\RdpAudit\RDPAudit_DEBUG_Log.txt (root,
///                           NOT logs\ -- matches Program.ConfigureSerilog). Empty when DEBUG mode
///                           has never actually been persisted to disk (see DiskDebugModeEnabled)
///                           or the service has not restarted since it was enabled.
///   ServiceLogTail        - Last lines of the day-rolling structured Serilog file under
///                           %ProgramData%\RdpAudit\logs\service-*.log -- present even when DEBUG
///                           mode is off, so a worker-fault / unhandled-exception entry is visible
///                           without enabling DEBUG first.
///   CrashFiles            - File names under %ProgramData%\RdpAudit\crash\ (CrashGuard's
///                           last-resort dump folder), most recent first.
///   LastCrashExcerpt      - Full text of the most recent crash file, if any.
/// </summary>
public sealed record ServiceDiagnosticsExtras(
	bool? DiskDebugModeEnabled,
	string? IpcOutcome,
	string? IpcErrorDetail,
	string? IpcErrorType,
	long IpcDurationMs,
	int IpcTimeoutMs,
	bool IpcPipeConnected,
	bool IpcResponseReceived,
	IReadOnlyList<string> IpcStartupLogTail,
	IReadOnlyList<string> DebugLogTail,
	IReadOnlyList<string> ServiceLogTail,
	IReadOnlyList<string> CrashFiles,
	string? LastCrashExcerpt);

/// <summary>The diagnostics report. <see cref="Verdict"/> drives the "OK / not installed /
/// running old binary / hash mismatch" headline label and the colour of the Service tab
/// state line; <see cref="ReportText"/> is the multi-line transcript copied to the
/// clipboard.</summary>
public sealed record ServiceDiagnosticsReport(
	ServiceDiagnosticsVerdict Verdict,
	string VerdictLabel,
	string ReportText);

/// <summary>Pure formatter for the Copy diagnostics block.</summary>
public static class ServiceDiagnosticsReportBuilder
{
	/// <summary>Builds the diagnostics report from pre-read inputs.</summary>
	public static ServiceDiagnosticsReport Build(ServiceDiagnosticsInput input)
	{
		ArgumentNullException.ThrowIfNull(input);

		ServiceDiagnosticsVerdict verdict = ResolveVerdict(input);
		string verdictLabel = FormatVerdictLabel(verdict);
		string text = FormatReport(input, verdict, verdictLabel);
		return new ServiceDiagnosticsReport(verdict, verdictLabel, text);
	}

	private static ServiceDiagnosticsVerdict ResolveVerdict(ServiceDiagnosticsInput input)
	{
		if (!input.Distribution.Exists)
		{
			// Without a distribution we cannot fully diagnose, but flag the most actionable
			// missing piece. If SCM has the service installed AND the installed path is
			// missing we still surface InstalledPathMissing, since it is the more dangerous
			// condition.
			if (input.Scm.Installed && !input.Installed.Exists)
			{
				return ServiceDiagnosticsVerdict.InstalledPathMissing;
			}

			return input.Scm.Installed
				? ServiceDiagnosticsVerdict.DistributionMissing
				: ServiceDiagnosticsVerdict.PublishNotInstalled;
		}

		if (!input.Scm.Installed)
		{
			return ServiceDiagnosticsVerdict.NotInstalled;
		}

		if (!input.Installed.Exists)
		{
			return ServiceDiagnosticsVerdict.InstalledPathMissing;
		}

		string? scmExe = input.Scm.ResolveExecutablePath();
		if (!string.IsNullOrEmpty(scmExe)
			&& !PathsLookEquivalent(scmExe!, input.Layout.ExpectedServiceExecutable)
			&& !PathsLookEquivalent(scmExe!, Path.Combine(input.Layout.InstallDirectory, ServiceLayout.ServiceExeName)))
		{
			return ServiceDiagnosticsVerdict.ServicePathMismatch;
		}

		if (!HashEquivalent(input.Installed, input.Distribution))
		{
			return ServiceDiagnosticsVerdict.HashMismatch;
		}

		// Compare the running process binary against the installed one when we have data.
		BinaryFingerprint? running = input.Running.MainModuleFingerprint;
		if (running is { Exists: true } && !HashEquivalent(running, input.Installed))
		{
			return ServiceDiagnosticsVerdict.RunningOldBinary;
		}

		if (!string.IsNullOrWhiteSpace(input.IpcRuntimeVersion)
			&& !VersionEquivalent(input.IpcRuntimeVersion!, input.Installed.FileVersion)
			&& !VersionEquivalent(input.IpcRuntimeVersion!, input.Installed.ProductVersion))
		{
			// IPC reports a version that doesn't match the installed binary at all — talking to
			// a different process than what's on disk.
			if (string.IsNullOrWhiteSpace(input.Installed.FileVersion))
			{
				// installed binary has no version metadata, treat as RunningOldBinary
				return ServiceDiagnosticsVerdict.RunningOldBinary;
			}

			return ServiceDiagnosticsVerdict.IpcConnectedToUnexpectedBinary;
		}

		return ServiceDiagnosticsVerdict.Ok;
	}

	private static bool HashEquivalent(BinaryFingerprint a, BinaryFingerprint b)
	{
		if (string.IsNullOrEmpty(a.Sha256) || string.IsNullOrEmpty(b.Sha256))
		{
			return a.Length == b.Length
				&& string.Equals(a.FileVersion, b.FileVersion, StringComparison.Ordinal);
		}

		return string.Equals(a.Sha256, b.Sha256, StringComparison.OrdinalIgnoreCase);
	}

	private static bool PathsLookEquivalent(string a, string b)
	{
		try
		{
			string ap = Path.GetFullPath(a).TrimEnd(Path.DirectorySeparatorChar);
			string bp = Path.GetFullPath(b).TrimEnd(Path.DirectorySeparatorChar);
			return string.Equals(ap, bp, StringComparison.OrdinalIgnoreCase);
		}
		catch (Exception)
		{
			return string.Equals(a, b, StringComparison.OrdinalIgnoreCase);
		}
	}

	private static bool VersionEquivalent(string a, string? b)
	{
		if (string.IsNullOrEmpty(b))
		{
			return false;
		}

		if (string.Equals(a, b, StringComparison.Ordinal))
		{
			return true;
		}

		if (Version.TryParse(a, out Version? va) && Version.TryParse(b, out Version? vb))
		{
			int cmp = va.Major == vb.Major ? 0 : 1;
			cmp += va.Minor == vb.Minor ? 0 : 1;
			cmp += (va.Build < 0 ? 0 : va.Build) == (vb.Build < 0 ? 0 : vb.Build) ? 0 : 1;
			cmp += (va.Revision < 0 ? 0 : va.Revision) == (vb.Revision < 0 ? 0 : vb.Revision) ? 0 : 1;
			return cmp == 0;
		}

		return false;
	}

	private static string FormatVerdictLabel(ServiceDiagnosticsVerdict verdict) => verdict switch
	{
		ServiceDiagnosticsVerdict.Ok => "OK",
		ServiceDiagnosticsVerdict.PublishNotInstalled => "Publish not installed",
		ServiceDiagnosticsVerdict.InstalledPathMissing => "Installed path missing",
		ServiceDiagnosticsVerdict.RunningOldBinary => "Running old binary",
		ServiceDiagnosticsVerdict.ServicePathMismatch => "Service path mismatch",
		ServiceDiagnosticsVerdict.HashMismatch => "Hash mismatch",
		ServiceDiagnosticsVerdict.IpcConnectedToUnexpectedBinary => "IPC connected to unexpected binary",
		ServiceDiagnosticsVerdict.NotInstalled => "Not installed",
		ServiceDiagnosticsVerdict.DistributionMissing => "Distribution missing",
		_ => "Unknown",
	};

	private static string FormatReport(
		ServiceDiagnosticsInput input,
		ServiceDiagnosticsVerdict verdict,
		string verdictLabel)
	{
		StringBuilder sb = new();
		sb.Append("RdpAudit diagnostics — ").AppendLine(DateTime.UtcNow.ToString("u", CultureInfo.InvariantCulture));
		sb.Append("Verdict: ").AppendLine(verdictLabel);
		if (verdict != ServiceDiagnosticsVerdict.Ok)
		{
			sb.AppendLine(VerdictExplanation(verdict));
		}

		sb.AppendLine();
		sb.AppendLine("[Configurator]");
		sb.Append("  Version: ").AppendLine(input.ConfiguratorVersion);
		sb.Append("  Configurator dir: ").AppendLine(input.Layout.ConfiguratorDirectory);
		sb.AppendLine();

		sb.AppendLine("[Distribution]");
		AppendBinary(sb, input.Distribution);
		sb.AppendLine();

		sb.AppendLine("[Installed]");
		AppendBinary(sb, input.Installed);
		sb.AppendLine();

		sb.AppendLine("[SCM]");
		sb.Append("  Name: ").AppendLine(input.Scm.ServiceName ?? "(none)");
		sb.Append("  DisplayName: ").AppendLine(input.Scm.DisplayName ?? "(none)");
		sb.Append("  State: ").AppendLine(input.Scm.StateName ?? "(unknown)");
		sb.Append("  StartMode: ").AppendLine(input.Scm.StartMode ?? "(unknown)");
		sb.Append("  ImagePath: ").AppendLine(input.Scm.ImagePath ?? "(none)");
		sb.Append("  ProcessId: ").AppendLine(input.Scm.ProcessId?.ToString(CultureInfo.InvariantCulture) ?? "(none)");
		sb.AppendLine();

		sb.AppendLine("[Running process]");
		sb.Append("  PID: ").AppendLine(input.Running.ProcessId?.ToString(CultureInfo.InvariantCulture) ?? "(none)");
		sb.Append("  MainModule: ").AppendLine(input.Running.MainModulePath ?? "(unavailable)");
		if (input.Running.MainModuleFingerprint is BinaryFingerprint runningFp)
		{
			sb.Append("  Version: ").AppendLine(runningFp.FileVersion ?? "(unknown)");
			sb.Append("  SHA-256: ").AppendLine(runningFp.Sha256 ?? "(unknown)");
			sb.Append("  Length: ").AppendLine(runningFp.Length.ToString(CultureInfo.InvariantCulture));
		}

		sb.Append("  StartTimeUtc: ").AppendLine(
			input.Running.StartTimeUtc?.ToString("u", CultureInfo.InvariantCulture) ?? "(unknown)");
		sb.AppendLine();

		sb.AppendLine("[IPC]");
		sb.Append("  Connected: ").AppendLine(input.IpcConnected ? "yes" : "no");
		sb.Append("  RuntimeVersion: ").AppendLine(input.IpcRuntimeVersion ?? "(unreachable)");

		if (input.Extras is ServiceDiagnosticsExtras extras)
		{
			AppendExtras(sb, extras);
		}

		return sb.ToString();
	}

	/// <summary>Appends the deep-diagnostics sections (IPC failure detail, DebugMode disk/UI
	/// consistency, log tails, crash folder) so a single Copy diagnostics click is enough to
	/// root-cause a "service not responding" report without asking the operator to go hunting
	/// through %ProgramData%\RdpAudit\logs manually.</summary>
	private static void AppendExtras(StringBuilder sb, ServiceDiagnosticsExtras extras)
	{
		sb.AppendLine();
		sb.AppendLine("[IPC call detail]");
		sb.Append("  Outcome: ").AppendLine(extras.IpcOutcome ?? "(no probe attempted)");
		sb.Append("  PipeConnected: ").AppendLine(extras.IpcPipeConnected ? "yes" : "no");
		sb.Append("  ResponseReceived: ").AppendLine(extras.IpcResponseReceived ? "yes" : "no");
		sb.Append("  DurationMs: ").AppendLine(extras.IpcDurationMs.ToString(CultureInfo.InvariantCulture));
		sb.Append("  TimeoutMs: ").AppendLine(extras.IpcTimeoutMs.ToString(CultureInfo.InvariantCulture));
		if (!string.IsNullOrEmpty(extras.IpcErrorType) || !string.IsNullOrEmpty(extras.IpcErrorDetail))
		{
			sb.Append("  ErrorType: ").AppendLine(extras.IpcErrorType ?? "(none)");
			sb.Append("  ErrorDetail: ").AppendLine(extras.IpcErrorDetail ?? "(none)");
		}

		sb.AppendLine();
		sb.AppendLine("[Diagnostics config]");
		sb.Append("  DebugMode (on disk, appsettings.json): ").AppendLine(
			extras.DiskDebugModeEnabled is bool disk ? (disk ? "true" : "false") : "(appsettings.json unreadable)");
		if (extras.DiskDebugModeEnabled == true && extras.DebugLogTail.Count == 0)
		{
			sb.AppendLine("  Note: DebugMode is enabled on disk but RDPAudit_DEBUG_Log.txt is empty/missing -- " +
				"the service has likely not restarted since the setting was saved, or ConfigureSerilog's " +
				"debugMode read failed. Restart the service and re-check.");
		}

		AppendLogTail(sb, "ipc-startup.log (logs\\ipc-startup.log)", extras.IpcStartupLogTail);
		AppendLogTail(sb, "RDPAudit_DEBUG_Log.txt (RDPAudit_DEBUG_Log.txt, root)", extras.DebugLogTail);
		AppendLogTail(sb, "service-*.log (logs\\service-*.log, structured)", extras.ServiceLogTail);

		sb.AppendLine();
		sb.AppendLine("[Crash folder] (%ProgramData%\\RdpAudit\\crash)");
		if (extras.CrashFiles.Count == 0)
		{
			sb.AppendLine("  (empty -- no AppDomain.UnhandledException / UnobservedTaskException recorded)");
		}
		else
		{
			sb.Append("  Files (most recent first): ").AppendLine(string.Join(", ", extras.CrashFiles));
			if (!string.IsNullOrEmpty(extras.LastCrashExcerpt))
			{
				sb.AppendLine("  --- most recent crash file ---");
				sb.AppendLine(extras.LastCrashExcerpt);
				sb.AppendLine("  --- end crash file ---");
			}
		}
	}

	private static void AppendLogTail(StringBuilder sb, string label, IReadOnlyList<string> tail)
	{
		sb.AppendLine();
		sb.Append("[Log tail] ").AppendLine(label);
		if (tail.Count == 0)
		{
			sb.AppendLine("  (file not found or empty)");
			return;
		}

		foreach (string line in tail)
		{
			sb.Append("  | ").AppendLine(line);
		}
	}

	private static void AppendBinary(StringBuilder sb, BinaryFingerprint fp)
	{
		sb.Append("  Path: ").AppendLine(fp.Path);
		sb.Append("  Exists: ").AppendLine(fp.Exists ? "yes" : "no");
		sb.Append("  FileVersion: ").AppendLine(fp.FileVersion ?? "(unknown)");
		sb.Append("  ProductVersion: ").AppendLine(fp.ProductVersion ?? "(unknown)");
		sb.Append("  Length: ").AppendLine(fp.Length.ToString(CultureInfo.InvariantCulture));
		sb.Append("  LastWriteTimeUtc: ").AppendLine(
			fp.LastWriteTimeUtc?.ToString("u", CultureInfo.InvariantCulture) ?? "(unknown)");
		sb.Append("  SHA-256: ").AppendLine(fp.Sha256 ?? "(unknown)");
	}

	private static string VerdictExplanation(ServiceDiagnosticsVerdict verdict) => verdict switch
	{
		ServiceDiagnosticsVerdict.PublishNotInstalled =>
			"The publish folder is missing or empty. Run publish.ps1 next to the Configurator and retry.",
		ServiceDiagnosticsVerdict.InstalledPathMissing =>
			"SCM has the service registered but the binary at ImagePath is gone — the service cannot start until Install / Update is re-run.",
		ServiceDiagnosticsVerdict.RunningOldBinary =>
			"The installed binary on disk has been updated but the hosting process is still running the previous image. Restart the service to load the new image.",
		ServiceDiagnosticsVerdict.ServicePathMismatch =>
			"SCM ImagePath does not point at the configured install directory. Use Uninstall + Install to re-register at the correct path.",
		ServiceDiagnosticsVerdict.HashMismatch =>
			"Installed binary SHA-256 differs from the distribution. Use Update installed files to bring the install directory back in sync.",
		ServiceDiagnosticsVerdict.IpcConnectedToUnexpectedBinary =>
			"IPC reports a runtime version that does not match the installed binary on disk — the talking process is not the one we shipped.",
		ServiceDiagnosticsVerdict.NotInstalled =>
			"The Windows service is not registered with SCM. Use Install service to register it.",
		ServiceDiagnosticsVerdict.DistributionMissing =>
			"The publish/Service distribution is missing — Update is not possible until publish.ps1 re-emits it.",
		_ => string.Empty,
	};
}
