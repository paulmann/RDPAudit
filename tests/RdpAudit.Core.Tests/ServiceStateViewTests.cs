// File:    tests/RdpAudit.Core.Tests/ServiceStateViewTests.cs
// Module:  RdpAudit.Core.Tests
// Purpose: Stage 2 — locks the Service tab state aggregator. Covers every state model
//          transition the user-reported symptoms revealed: SCM running but IPC unreachable,
//          IPC connected but SCM not installed, installed-path-missing, distribution-missing,
//          update-available, running-older-binary, and the locale-stable Process line.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using RdpAudit.Core.Util;
using Xunit;

namespace RdpAudit.Core.Tests;

public class ServiceStateViewTests
{
	private static ServiceInstallationInfo Installed(int stateCode, int? processId = 1234,
		string? imagePath = "\"C:\\Program Files\\RdpAudit\\Service\\RdpAudit.Service.exe\"") =>
		new(
			ServiceName: "RdpAuditService",
			Installed: true,
			DisplayName: "RDP Monitor",
			StateCode: stateCode,
			StateName: stateCode == 4 ? "Running" : "Stopped",
			ProcessId: processId,
			ImagePath: imagePath,
			StartMode: "Auto",
			Status: "OK",
			Win32ExitCode: 0,
			ServiceSpecificExitCode: 0,
			Diagnostic: null);

	private static ServiceInstallationInfo NotInstalled() => new(
		ServiceName: "RdpAuditService",
		Installed: false,
		DisplayName: null,
		StateCode: null,
		StateName: null,
		ProcessId: null,
		ImagePath: null,
		StartMode: null,
		Status: null,
		Win32ExitCode: null,
		ServiceSpecificExitCode: null,
		Diagnostic: null);

	private static BinaryFingerprint Fingerprint(string path, string? version = "1.2.0.0", string? sha = "DEADBEEF",
		long length = 1024, bool exists = true) =>
		new(
			Path: path,
			Exists: exists,
			FileVersion: exists ? version : null,
			ProductVersion: exists ? version : null,
			Length: exists ? length : 0,
			LastWriteTimeUtc: exists ? new DateTime(2026, 5, 26, 12, 0, 0, DateTimeKind.Utc) : null,
			Sha256: exists ? sha : null);

	[Fact]
	public void NotInstalled_BinaryStateIsNotInstalled_ProcessLineSaysNotInstalled()
	{
		ServiceStateView view = ServiceStateViewBuilder.Build(
			scm: NotInstalled(),
			installed: Fingerprint(@"C:\nope\RdpAudit.Service.exe", exists: false),
			distribution: Fingerprint(@"D:\publish\Service\RdpAudit.Service.exe"),
			runtimeVersion: null,
			ipcConnected: false);

		Assert.Equal(InstalledBinaryState.NotInstalled, view.BinaryState);
		Assert.Contains("Not installed", view.ProcessLine, StringComparison.Ordinal);
	}

	[Fact]
	public void InstalledRunning_IpcConnected_ProcessLineHasRunningPidAndImagePath()
	{
		ServiceStateView view = ServiceStateViewBuilder.Build(
			scm: Installed(stateCode: 4, processId: 5678),
			installed: Fingerprint(@"C:\Program Files\RdpAudit\Service\RdpAudit.Service.exe"),
			distribution: Fingerprint(@"D:\publish\Service\RdpAudit.Service.exe"),
			runtimeVersion: "1.2.0",
			ipcConnected: true);

		Assert.Equal(InstalledBinaryState.InstalledCurrent, view.BinaryState);
		Assert.Contains("Running", view.ProcessLine, StringComparison.Ordinal);
		Assert.Contains("PID 5678", view.ProcessLine, StringComparison.Ordinal);
		Assert.Contains("RdpAudit.Service.exe", view.ProcessLine, StringComparison.Ordinal);
		Assert.Contains("IPC: Connected", view.ProcessLine, StringComparison.Ordinal);
		Assert.DoesNotContain("Not running", view.ProcessLine, StringComparison.OrdinalIgnoreCase);
	}

	[Fact]
	public void InstalledRunning_IpcUnreachable_StillShowsRunningWithStaleTelemetryNote()
	{
		ServiceStateView view = ServiceStateViewBuilder.Build(
			scm: Installed(stateCode: 4, processId: 5678),
			installed: Fingerprint(@"C:\Program Files\RdpAudit\Service\RdpAudit.Service.exe"),
			distribution: Fingerprint(@"D:\publish\Service\RdpAudit.Service.exe"),
			runtimeVersion: null,
			ipcConnected: false);

		Assert.Contains("Running", view.ProcessLine, StringComparison.Ordinal);
		Assert.Contains("IPC: Disconnected", view.ProcessLine, StringComparison.Ordinal);
		Assert.Contains("telemetry numbers", view.DiagnosticLine, StringComparison.OrdinalIgnoreCase);
	}

	[Fact]
	public void IpcConnectedButScmReportsNotInstalled_EmitsHighSignalDiagnostic()
	{
		ServiceStateView view = ServiceStateViewBuilder.Build(
			scm: NotInstalled(),
			installed: Fingerprint(@"C:\nope.exe", exists: false),
			distribution: Fingerprint(@"D:\publish\Service\RdpAudit.Service.exe"),
			runtimeVersion: "1.2.0",
			ipcConnected: true);

		Assert.Contains("IPC connected but SCM service name/path could not be resolved",
			view.DiagnosticLine, StringComparison.Ordinal);
		Assert.Contains("RdpAuditService", view.DiagnosticLine, StringComparison.Ordinal);
	}

	[Fact]
	public void InstalledButImageMissing_StateIsInstalledPathMissing()
	{
		ServiceStateView view = ServiceStateViewBuilder.Build(
			scm: Installed(stateCode: 1, processId: null, imagePath: "\"C:\\Program Files\\RdpAudit\\Service\\RdpAudit.Service.exe\""),
			installed: Fingerprint(@"C:\Program Files\RdpAudit\Service\RdpAudit.Service.exe", exists: false),
			distribution: Fingerprint(@"D:\publish\Service\RdpAudit.Service.exe"),
			runtimeVersion: null,
			ipcConnected: false);

		Assert.Equal(InstalledBinaryState.InstalledPathMissing, view.BinaryState);
		Assert.Contains("WARNING", view.DiagnosticLine, StringComparison.OrdinalIgnoreCase);
	}

	[Fact]
	public void DistributionMissing_StateIsDistributionMissing()
	{
		ServiceStateView view = ServiceStateViewBuilder.Build(
			scm: Installed(stateCode: 4, processId: 5678),
			installed: Fingerprint(@"C:\Program Files\RdpAudit\Service\RdpAudit.Service.exe"),
			distribution: Fingerprint(@"D:\publish\Service\RdpAudit.Service.exe", exists: false),
			runtimeVersion: "1.2.0",
			ipcConnected: true);

		Assert.Equal(InstalledBinaryState.DistributionMissing, view.BinaryState);
	}

	[Fact]
	public void InstalledAndDistributionDiffer_StateIsUpdateAvailable()
	{
		ServiceStateView view = ServiceStateViewBuilder.Build(
			scm: Installed(stateCode: 4, processId: 5678),
			installed: Fingerprint(@"C:\Program Files\RdpAudit\Service\RdpAudit.Service.exe",
				version: "1.0.0.0", sha: "AAA"),
			distribution: Fingerprint(@"D:\publish\Service\RdpAudit.Service.exe",
				version: "1.2.0.0", sha: "BBB"),
			runtimeVersion: "1.0.0.0",
			ipcConnected: true);

		Assert.Equal(InstalledBinaryState.UpdateAvailable, view.BinaryState);
		Assert.Contains("Update available", view.DiagnosticLine, StringComparison.OrdinalIgnoreCase);
		Assert.Contains("1.0.0.0", view.DiagnosticLine, StringComparison.Ordinal);
		Assert.Contains("1.2.0.0", view.DiagnosticLine, StringComparison.Ordinal);
	}

	[Fact]
	public void RuntimeVersionLagsInstalledFile_StateIsRunningOlderBinary()
	{
		ServiceStateView view = ServiceStateViewBuilder.Build(
			scm: Installed(stateCode: 4, processId: 5678),
			installed: Fingerprint(@"C:\Program Files\RdpAudit\Service\RdpAudit.Service.exe",
				version: "1.2.0.0", sha: "AAA"),
			distribution: Fingerprint(@"D:\publish\Service\RdpAudit.Service.exe",
				version: "1.2.0.0", sha: "AAA"),
			runtimeVersion: "1.0.0",
			ipcConnected: true);

		Assert.Equal(InstalledBinaryState.RunningOlderBinary, view.BinaryState);
		Assert.Contains("Restart", view.DiagnosticLine, StringComparison.OrdinalIgnoreCase);
	}

	[Fact]
	public void InstalledCurrent_AndRuntimeMatches_NoWarningDiagnostic()
	{
		ServiceStateView view = ServiceStateViewBuilder.Build(
			scm: Installed(stateCode: 4, processId: 5678),
			installed: Fingerprint(@"C:\Program Files\RdpAudit\Service\RdpAudit.Service.exe",
				version: "1.2.0.0", sha: "AAA"),
			distribution: Fingerprint(@"D:\publish\Service\RdpAudit.Service.exe",
				version: "1.2.0.0", sha: "AAA"),
			runtimeVersion: "1.2.0",
			ipcConnected: true);

		Assert.Equal(InstalledBinaryState.InstalledCurrent, view.BinaryState);
		Assert.Equal(string.Empty, view.DiagnosticLine);
	}

	[Fact]
	public void InstallStateLine_DescribesAllThreeVersions()
	{
		ServiceStateView view = ServiceStateViewBuilder.Build(
			scm: Installed(stateCode: 4, processId: 5678),
			installed: Fingerprint(@"C:\Program Files\RdpAudit\Service\RdpAudit.Service.exe",
				version: "1.0.0.0", sha: "AAA"),
			distribution: Fingerprint(@"D:\publish\Service\RdpAudit.Service.exe",
				version: "1.2.0.0", sha: "BBB"),
			runtimeVersion: "1.0.0",
			ipcConnected: true);

		Assert.Contains("Runtime 1.0.0", view.InstallStateLine, StringComparison.Ordinal);
		Assert.Contains("Installed 1.0.0.0", view.InstallStateLine, StringComparison.Ordinal);
		Assert.Contains("Distribution 1.2.0.0", view.InstallStateLine, StringComparison.Ordinal);
		Assert.Contains("Update available", view.InstallStateLine, StringComparison.Ordinal);
	}
}
