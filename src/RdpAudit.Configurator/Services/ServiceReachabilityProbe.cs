// File:    src/RdpAudit.Configurator/Services/ServiceReachabilityProbe.cs
// Module:  RdpAudit.Configurator.Services
// Purpose: Turns an unreachable / failed IPC call into an honest, actionable diagnostic. When a call
//          does not succeed the UI used to say "Start the service (as administrator)" regardless of
//          why — even while the service was running and merely busy with a long firewall repair. This
//          probe consults the authoritative SCM snapshot (Win32_Service via WmiServiceInfoReader) plus
//          the IPC call outcome to decide between "service is stopped / not installed", "operation in
//          progress (service reachable but slow)", and "service-side command error", and renders the
//          real Windows service status (state, PID, image path, executable ProductVersion) so the
//          operator sees ground truth instead of a guess.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System.Diagnostics;
using System.Globalization;
using System.Runtime.Versioning;
using RdpAudit.Configurator.Ipc;
using RdpAudit.Core.Ipc;
using RdpAudit.Core.Util;

namespace RdpAudit.Configurator.Services;

/// <summary>Builds operator-facing diagnostics for an unreachable / failed IPC call.</summary>
[SupportedOSPlatform("windows")]
public sealed class ServiceReachabilityProbe
{
	private readonly WmiServiceInfoReader _reader;

	public ServiceReachabilityProbe(string serviceName = IpcConstants.PipeName)
		=> _reader = new WmiServiceInfoReader(serviceName);

	/// <summary>Reads the SCM snapshot and composes a multi-line diagnostic for the supplied failed
	/// call outcome. Never throws; any WMI failure is surfaced inline.</summary>
	public async Task<ServiceReachabilityDiagnostic> DescribeAsync<T>(IpcCallResult<T> call, CancellationToken ct = default)
	{
		ServiceInstallationInfo info;
		try
		{
			info = await _reader.ReadAsync(ct).ConfigureAwait(false);
		}
		catch (Exception ex)
		{
			info = new ServiceInstallationInfo(IpcConstants.PipeName, false, null, null, null, null, null, null, null, null, null, "WMI read raised " + ex.GetType().Name);
		}

		string headline = BuildHeadline(call.Outcome, info);
		string detail = BuildDetail(call, info);
		return new ServiceReachabilityDiagnostic(headline, detail, info);
	}

	private static string BuildHeadline(IpcCallOutcome outcome, ServiceInstallationInfo info)
	{
		return outcome switch
		{
			IpcCallOutcome.Timeout when info.IsRunning =>
				"Operation in progress — the service is running but did not respond within the timeout. Retry shortly.",
			IpcCallOutcome.Timeout =>
				"The service did not respond within the timeout and SCM does not report it Running. Start the service (as administrator) and retry.",
			IpcCallOutcome.ConnectFailed when info.IsRunning =>
				"The service is running per SCM but its IPC pipe did not accept a connection — it may still be starting. Retry shortly.",
			IpcCallOutcome.ConnectFailed when info.IsStopped =>
				"The service is Stopped. Start the service (as administrator) and retry.",
			IpcCallOutcome.ConnectFailed when !info.Installed =>
				"The RdpAudit service is not installed. Install/publish and start it (as administrator), then retry.",
			IpcCallOutcome.ConnectFailed =>
				"The service IPC pipe is not reachable. Start the service (as administrator) and retry.",
			IpcCallOutcome.ServiceError =>
				"The service is reachable but the command failed. See the error detail below and the service log.",
			IpcCallOutcome.TransportError =>
				"The connection to the service broke mid-transfer. Retry; if it persists, restart the service.",
			_ => "The service did not return a result.",
		};
	}

	private string BuildDetail<T>(IpcCallResult<T> call, ServiceInstallationInfo info)
	{
		string state = info.Installed
			? (info.StateName ?? (info.StateCode?.ToString(CultureInfo.InvariantCulture) ?? "unknown"))
			: "not installed";
		string exe = info.ResolveExecutablePath() ?? "(unknown)";
		string version = ResolveExecutableVersion(info.ResolveExecutablePath());

		return string.Join(
			"\r\n",
			"IPC call diagnostics:",
			"  " + call.TraceLine,
			string.IsNullOrEmpty(call.Error) ? "  error=(none)" : "  error=" + call.ErrorType + ": " + call.Error,
			"Windows service (SCM):",
			"  name=" + info.ServiceName + "  installed=" + info.Installed.ToString(CultureInfo.InvariantCulture),
			"  state=" + state + "  pid=" + (info.ProcessId?.ToString(CultureInfo.InvariantCulture) ?? "(none)"),
			"  startMode=" + (info.StartMode ?? "(unknown)"),
			"  imagePath=" + (info.ImagePath ?? "(unknown)"),
			"  executable=" + exe,
			"  executableProductVersion=" + version,
			info.Diagnostic is null ? "  scmDiagnostic=(none)" : "  scmDiagnostic=" + info.Diagnostic);
	}

	private static string ResolveExecutableVersion(string? exePath)
	{
		if (string.IsNullOrWhiteSpace(exePath))
		{
			return "(unknown)";
		}

		try
		{
			if (!File.Exists(exePath))
			{
				return "(file not found)";
			}

			FileVersionInfo info = FileVersionInfo.GetVersionInfo(exePath);
			return info.ProductVersion ?? info.FileVersion ?? "(no version info)";
		}
		catch (Exception ex)
		{
			return "(version read failed: " + ex.GetType().Name + ")";
		}
	}
}

/// <summary>Composed reachability diagnostic: a one-line headline plus a copyable multi-line detail
/// block, and the raw SCM snapshot for callers that want to branch on it.</summary>
public sealed record ServiceReachabilityDiagnostic(string Headline, string Detail, ServiceInstallationInfo Scm);
