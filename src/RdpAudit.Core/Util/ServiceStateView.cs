// File:    src/RdpAudit.Core/Util/ServiceStateView.cs
// Module:  RdpAudit.Core.Util
// Purpose: Aggregates the three independent inputs the Service tab depends on -
//          authoritative SCM state, optional IPC telemetry, and on-disk binary
//          fingerprints (installed / distribution) - into a single immutable view
//          that drives the UI: rendered status lines, button enablement, and
//          high-signal diagnostics. SCM is the source of truth for installed and
//          run state. IPC is the source of truth for runtime telemetry. The
//          distribution folder is the source of truth for what publish.ps1 most
//          recently emitted. None of the three can substitute for another.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

namespace RdpAudit.Core.Util;

/// <summary>High-level installation lifecycle of the RdpAudit service.</summary>
public enum InstalledBinaryState
{
	/// <summary>The service is not registered with SCM. Install action is the only
	/// path forward.</summary>
	NotInstalled,

	/// <summary>SCM has the service registered but <see cref="ServiceInstallationInfo.ImagePath"/>
	/// points at a file that no longer exists on disk. The service cannot start.</summary>
	InstalledPathMissing,

	/// <summary>SCM has the service registered, the installed binary exists, and the
	/// distribution publish folder is missing. Update is not possible until publish.ps1
	/// re-emits the distribution.</summary>
	DistributionMissing,

	/// <summary>The installed binary and the distribution binary describe the same content
	/// (same length, SHA-256, file version, product version).</summary>
	InstalledCurrent,

	/// <summary>The installed binary differs from the distribution binary in a way that an
	/// Update action can resolve (different content, length, or version on disk).</summary>
	UpdateAvailable,

	/// <summary>The hosting process is running an older binary than what SCM has registered
	/// as the install path (binary on disk has been swapped while the process is still
	/// holding the previous image in memory). A Restart is needed.</summary>
	RunningOlderBinary,
}

/// <summary>Unified state model for the Service tab. Pure record; all decisions live in
/// <see cref="ServiceStateViewBuilder"/> so they can be exercised in unit tests.</summary>
public sealed record ServiceStateView(
	ServiceInstallationInfo Scm,
	BinaryFingerprint Installed,
	BinaryFingerprint Distribution,
	string? RuntimeVersion,
	bool IpcConnected,
	InstalledBinaryState BinaryState,
	string ProcessLine,
	string DiagnosticLine,
	string InstallStateLine);

/// <summary>Builds a <see cref="ServiceStateView"/> from the three inputs.</summary>
public static class ServiceStateViewBuilder
{
	/// <summary>Builds the aggregated view. <paramref name="runtimeVersion"/> and
	/// <paramref name="ipcConnected"/> describe what the Configurator was able to learn from
	/// the live service via the IPC <c>GetStatus</c> command. The two are independent of
	/// SCM: a running service that has not yet started its IPC server still appears as
	/// Running on SCM, and an unreachable IPC does not imply the service has stopped.</summary>
	public static ServiceStateView Build(
		ServiceInstallationInfo scm,
		BinaryFingerprint installed,
		BinaryFingerprint distribution,
		string? runtimeVersion,
		bool ipcConnected)
	{
		ArgumentNullException.ThrowIfNull(scm);
		ArgumentNullException.ThrowIfNull(installed);
		ArgumentNullException.ThrowIfNull(distribution);

		InstalledBinaryState binaryState = ResolveBinaryState(scm, installed, distribution, runtimeVersion);
		string processLine = FormatProcessLine(scm, ipcConnected);
		string diagnosticLine = FormatDiagnosticLine(scm, installed, distribution, runtimeVersion, ipcConnected, binaryState);
		string installStateLine = FormatInstallStateLine(binaryState, installed, distribution, runtimeVersion);

		return new ServiceStateView(
			Scm: scm,
			Installed: installed,
			Distribution: distribution,
			RuntimeVersion: runtimeVersion,
			IpcConnected: ipcConnected,
			BinaryState: binaryState,
			ProcessLine: processLine,
			DiagnosticLine: diagnosticLine,
			InstallStateLine: installStateLine);
	}

	private static InstalledBinaryState ResolveBinaryState(
		ServiceInstallationInfo scm,
		BinaryFingerprint installed,
		BinaryFingerprint distribution,
		string? runtimeVersion)
	{
		if (!scm.Installed)
		{
			return InstalledBinaryState.NotInstalled;
		}

		if (!installed.Exists)
		{
			return InstalledBinaryState.InstalledPathMissing;
		}

		if (!distribution.Exists)
		{
			return InstalledBinaryState.DistributionMissing;
		}

		if (!installed.IsContentIdentical(distribution))
		{
			return InstalledBinaryState.UpdateAvailable;
		}

		// Both installed and distribution match on disk. If IPC reports a runtime version that
		// differs from the installed file version, the hosting process is still running an
		// older image (binary was swapped while the service is up).
		if (!string.IsNullOrWhiteSpace(runtimeVersion)
			&& !string.IsNullOrWhiteSpace(installed.FileVersion)
			&& !VersionEquivalent(runtimeVersion, installed.FileVersion!)
			&& !VersionEquivalent(runtimeVersion, installed.ProductVersion))
		{
			return InstalledBinaryState.RunningOlderBinary;
		}

		return InstalledBinaryState.InstalledCurrent;
	}

	private static string FormatProcessLine(ServiceInstallationInfo scm, bool ipcConnected)
	{
		if (!scm.Installed)
		{
			return "Process: Not installed (SCM)";
		}

		string state = scm.StateName ?? StateNameFromCode(scm.StateCode) ?? "Unknown";
		if (scm.IsRunning)
		{
			string pid = scm.ProcessId is int p
				? p.ToString(System.Globalization.CultureInfo.InvariantCulture)
				: "details unavailable";
			string image = scm.ResolveExecutablePath() ?? "image path unknown";
			string ipc = ipcConnected ? "  IPC: Connected" : "  IPC: Disconnected";
			return $"Process: Running  PID {pid}  exe {image}{ipc}";
		}

		if (scm.IsPaused)
		{
			return $"Process: Paused (state: {state})";
		}

		if (scm.IsTransitioning)
		{
			return $"Process: Transitioning (state: {state})";
		}

		return $"Process: Stopped (state: {state})";
	}

	private static string FormatDiagnosticLine(
		ServiceInstallationInfo scm,
		BinaryFingerprint installed,
		BinaryFingerprint distribution,
		string? runtimeVersion,
		bool ipcConnected,
		InstalledBinaryState state)
	{
		if (ipcConnected && !scm.Installed)
		{
			return "WARNING: IPC connected but SCM service name/path could not be resolved. "
				+ "Verify service name matches '" + scm.ServiceName + "' and pipe name 'RdpAuditService'.";
		}

		if (scm.IsRunning && !ipcConnected)
		{
			return "Note: SCM reports the service is running but IPC GetStatus failed. "
				+ "Telemetry numbers above may be stale.";
		}

		if (state == InstalledBinaryState.RunningOlderBinary)
		{
			return $"WARNING: hosting process reports version {runtimeVersion} but installed binary on disk is {installed.FileVersion}. "
				+ "Restart the service to load the new image.";
		}

		if (state == InstalledBinaryState.InstalledPathMissing)
		{
			return $"WARNING: SCM ImagePath '{scm.ImagePath}' does not exist on disk. The service cannot start until the path is repaired.";
		}

		if (state == InstalledBinaryState.UpdateAvailable)
		{
			string installedV = installed.FileVersion ?? "(unknown)";
			string distV = distribution.FileVersion ?? "(unknown)";
			return $"Update available: installed {installedV} differs from distribution {distV}. Use 'Update installed files' to copy the new binaries.";
		}

		if (scm.Win32ExitCode is int code && code != 0 && !scm.IsRunning)
		{
			return $"SCM Win32 exit code {code.ToString(System.Globalization.CultureInfo.InvariantCulture)} reported for the last start attempt.";
		}

		if (!string.IsNullOrWhiteSpace(scm.Diagnostic))
		{
			return scm.Diagnostic!;
		}

		return string.Empty;
	}

	private static string FormatInstallStateLine(
		InstalledBinaryState state,
		BinaryFingerprint installed,
		BinaryFingerprint distribution,
		string? runtimeVersion)
	{
		string installedV = installed.FileVersion ?? "(unknown)";
		string distV = distribution.FileVersion ?? "(unknown)";
		string runtimeV = string.IsNullOrWhiteSpace(runtimeVersion) ? "(unreachable)" : runtimeVersion;

		string label = state switch
		{
			InstalledBinaryState.NotInstalled        => "Not installed",
			InstalledBinaryState.InstalledPathMissing => "Installed path missing",
			InstalledBinaryState.DistributionMissing => "Distribution missing",
			InstalledBinaryState.InstalledCurrent    => "Installed current",
			InstalledBinaryState.UpdateAvailable     => "Update available",
			InstalledBinaryState.RunningOlderBinary  => "Running older binary",
			_ => "Unknown",
		};

		return $"State: {label}  |  Runtime {runtimeV}  Installed {installedV}  Distribution {distV}";
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

		// Treat trailing ".0" segments as equivalent so "1.2.0" matches "1.2.0.0".
		if (Version.TryParse(a, out Version? va) && Version.TryParse(b, out Version? vb))
		{
			int major = va.Major == vb.Major ? 0 : 1;
			int minor = va.Minor == vb.Minor ? 0 : 1;
			int build = (va.Build < 0 ? 0 : va.Build) == (vb.Build < 0 ? 0 : vb.Build) ? 0 : 1;
			int rev = (va.Revision < 0 ? 0 : va.Revision) == (vb.Revision < 0 ? 0 : vb.Revision) ? 0 : 1;
			return major + minor + build + rev == 0;
		}

		return false;
	}

	private static string? StateNameFromCode(int? code) => code switch
	{
		1 => "STOPPED",
		2 => "START_PENDING",
		3 => "STOP_PENDING",
		4 => "RUNNING",
		5 => "CONTINUE_PENDING",
		6 => "PAUSE_PENDING",
		7 => "PAUSED",
		_ => null,
	};
}
