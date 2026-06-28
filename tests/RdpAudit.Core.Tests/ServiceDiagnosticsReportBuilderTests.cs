// File:    tests/RdpAudit.Core.Tests/ServiceDiagnosticsReportBuilderTests.cs
// Module:  RdpAudit.Core.Tests
// Purpose: Locks the verdict resolution rules for the Service tab Copy diagnostics report.
//          Each test arranges a single concrete mismatch (or none) and asserts the resulting
//          ServiceDiagnosticsVerdict so the headline label the operator sees can never silently
//          regress to "OK" when the inputs are out of sync.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using RdpAudit.Core.Util;
using Xunit;

namespace RdpAudit.Core.Tests;

/// <summary>Verdict-resolution coverage for <see cref="ServiceDiagnosticsReportBuilder"/>.</summary>
public class ServiceDiagnosticsReportBuilderTests
{
	private const string InstallDir = "C:\\Program Files\\RdpAudit\\Service";
	private const string DistDir = "C:\\publish\\Service";
	private const string ExeName = "RdpAudit.Service.exe";

	[Fact]
	public void Build_AllInSync_VerdictIsOk()
	{
		BinaryFingerprint dist = MakeFingerprint(Path.Combine(DistDir, ExeName), "ABCD", "1.1.0");
		BinaryFingerprint installed = MakeFingerprint(Path.Combine(InstallDir, ExeName), "ABCD", "1.1.0");
		ServiceDiagnosticsInput input = MakeInput(
			dist, installed,
			scmInstalled: true,
			scmImagePath: "\"" + Path.Combine(InstallDir, ExeName) + "\"",
			runtimeVersion: "1.1.0",
			ipcConnected: true,
			running: new RunningProcessFingerprint(1234, Path.Combine(InstallDir, ExeName), installed, DateTime.UtcNow));

		ServiceDiagnosticsReport report = ServiceDiagnosticsReportBuilder.Build(input);

		Assert.Equal(ServiceDiagnosticsVerdict.Ok, report.Verdict);
		Assert.Equal("OK", report.VerdictLabel);
	}

	[Fact]
	public void Build_DistributionMissing_VerdictIsPublishNotInstalled()
	{
		BinaryFingerprint dist = MakeMissing(Path.Combine(DistDir, ExeName));
		BinaryFingerprint installed = MakeMissing(Path.Combine(InstallDir, ExeName));
		ServiceDiagnosticsInput input = MakeInput(
			dist, installed,
			scmInstalled: false,
			scmImagePath: null,
			runtimeVersion: null,
			ipcConnected: false,
			running: new RunningProcessFingerprint(null, null, null, null));

		ServiceDiagnosticsReport report = ServiceDiagnosticsReportBuilder.Build(input);

		Assert.Equal(ServiceDiagnosticsVerdict.PublishNotInstalled, report.Verdict);
		Assert.Equal("Publish not installed", report.VerdictLabel);
	}

	[Fact]
	public void Build_InstalledPathMissing_TakesPrecedenceOverDistributionMissing()
	{
		BinaryFingerprint dist = MakeMissing(Path.Combine(DistDir, ExeName));
		BinaryFingerprint installed = MakeMissing(Path.Combine(InstallDir, ExeName));
		ServiceDiagnosticsInput input = MakeInput(
			dist, installed,
			scmInstalled: true,
			scmImagePath: "\"" + Path.Combine(InstallDir, ExeName) + "\"",
			runtimeVersion: null,
			ipcConnected: false,
			running: new RunningProcessFingerprint(null, null, null, null));

		ServiceDiagnosticsReport report = ServiceDiagnosticsReportBuilder.Build(input);

		Assert.Equal(ServiceDiagnosticsVerdict.InstalledPathMissing, report.Verdict);
	}

	[Fact]
	public void Build_HashMismatch_WhenInstalledDiffersFromDistribution()
	{
		BinaryFingerprint dist = MakeFingerprint(Path.Combine(DistDir, ExeName), "AAAA", "1.1.0");
		BinaryFingerprint installed = MakeFingerprint(Path.Combine(InstallDir, ExeName), "BBBB", "1.0.0");
		ServiceDiagnosticsInput input = MakeInput(
			dist, installed,
			scmInstalled: true,
			scmImagePath: "\"" + Path.Combine(InstallDir, ExeName) + "\"",
			runtimeVersion: "1.0.0",
			ipcConnected: true,
			running: new RunningProcessFingerprint(1234, Path.Combine(InstallDir, ExeName), installed, DateTime.UtcNow));

		ServiceDiagnosticsReport report = ServiceDiagnosticsReportBuilder.Build(input);

		Assert.Equal(ServiceDiagnosticsVerdict.HashMismatch, report.Verdict);
	}

	[Fact]
	public void Build_RunningOldBinary_WhenRunningHashDiffersFromInstalled()
	{
		BinaryFingerprint dist = MakeFingerprint(Path.Combine(DistDir, ExeName), "ABCD", "1.1.0");
		BinaryFingerprint installed = MakeFingerprint(Path.Combine(InstallDir, ExeName), "ABCD", "1.1.0");
		BinaryFingerprint running = MakeFingerprint(Path.Combine(InstallDir, ExeName), "OLD0", "1.0.0");
		ServiceDiagnosticsInput input = MakeInput(
			dist, installed,
			scmInstalled: true,
			scmImagePath: "\"" + Path.Combine(InstallDir, ExeName) + "\"",
			runtimeVersion: "1.0.0",
			ipcConnected: true,
			running: new RunningProcessFingerprint(1234, Path.Combine(InstallDir, ExeName), running, DateTime.UtcNow));

		ServiceDiagnosticsReport report = ServiceDiagnosticsReportBuilder.Build(input);

		Assert.Equal(ServiceDiagnosticsVerdict.RunningOldBinary, report.Verdict);
	}

	[Fact]
	public void Build_ServicePathMismatch_WhenScmImagePointsAtForeignPath()
	{
		BinaryFingerprint dist = MakeFingerprint(Path.Combine(DistDir, ExeName), "ABCD", "1.1.0");
		BinaryFingerprint installed = MakeFingerprint("D:\\elsewhere\\Service\\" + ExeName, "ABCD", "1.1.0");
		ServiceDiagnosticsInput input = MakeInput(
			dist, installed,
			scmInstalled: true,
			scmImagePath: "\"D:\\elsewhere\\Service\\" + ExeName + "\"",
			runtimeVersion: "1.1.0",
			ipcConnected: true,
			running: new RunningProcessFingerprint(1234, "D:\\elsewhere\\Service\\" + ExeName, installed, DateTime.UtcNow));

		ServiceDiagnosticsReport report = ServiceDiagnosticsReportBuilder.Build(input);

		Assert.Equal(ServiceDiagnosticsVerdict.ServicePathMismatch, report.Verdict);
	}

	[Fact]
	public void Build_NotInstalled_WhenScmReportsNotInstalled()
	{
		BinaryFingerprint dist = MakeFingerprint(Path.Combine(DistDir, ExeName), "ABCD", "1.1.0");
		BinaryFingerprint installed = MakeMissing(Path.Combine(InstallDir, ExeName));
		ServiceDiagnosticsInput input = MakeInput(
			dist, installed,
			scmInstalled: false,
			scmImagePath: null,
			runtimeVersion: null,
			ipcConnected: false,
			running: new RunningProcessFingerprint(null, null, null, null));

		ServiceDiagnosticsReport report = ServiceDiagnosticsReportBuilder.Build(input);

		Assert.Equal(ServiceDiagnosticsVerdict.NotInstalled, report.Verdict);
	}

	[Fact]
	public void Build_IpcConnectedToUnexpectedBinary_WhenIpcVersionDoesNotMatchInstalledFile()
	{
		BinaryFingerprint dist = MakeFingerprint(Path.Combine(DistDir, ExeName), "ABCD", "1.1.0");
		BinaryFingerprint installed = MakeFingerprint(Path.Combine(InstallDir, ExeName), "ABCD", "1.1.0");
		ServiceDiagnosticsInput input = MakeInput(
			dist, installed,
			scmInstalled: true,
			scmImagePath: "\"" + Path.Combine(InstallDir, ExeName) + "\"",
			runtimeVersion: "9.9.9", // utterly unexpected
			ipcConnected: true,
			running: new RunningProcessFingerprint(1234, Path.Combine(InstallDir, ExeName), installed, DateTime.UtcNow));

		ServiceDiagnosticsReport report = ServiceDiagnosticsReportBuilder.Build(input);

		Assert.Equal(ServiceDiagnosticsVerdict.IpcConnectedToUnexpectedBinary, report.Verdict);
	}

	[Fact]
	public void Build_ReportText_IncludesVerdictAndAllSections()
	{
		BinaryFingerprint dist = MakeFingerprint(Path.Combine(DistDir, ExeName), "ABCD", "1.1.0");
		BinaryFingerprint installed = MakeFingerprint(Path.Combine(InstallDir, ExeName), "ABCD", "1.1.0");
		ServiceDiagnosticsInput input = MakeInput(
			dist, installed,
			scmInstalled: true,
			scmImagePath: "\"" + Path.Combine(InstallDir, ExeName) + "\"",
			runtimeVersion: "1.1.0",
			ipcConnected: true,
			running: new RunningProcessFingerprint(1234, Path.Combine(InstallDir, ExeName), installed, DateTime.UtcNow));

		ServiceDiagnosticsReport report = ServiceDiagnosticsReportBuilder.Build(input);

		Assert.Contains("Verdict: OK", report.ReportText, StringComparison.Ordinal);
		Assert.Contains("[Distribution]", report.ReportText, StringComparison.Ordinal);
		Assert.Contains("[Installed]", report.ReportText, StringComparison.Ordinal);
		Assert.Contains("[SCM]", report.ReportText, StringComparison.Ordinal);
		Assert.Contains("[Running process]", report.ReportText, StringComparison.Ordinal);
		Assert.Contains("[IPC]", report.ReportText, StringComparison.Ordinal);
	}

	private static BinaryFingerprint MakeFingerprint(string path, string sha, string version)
	{
		return new BinaryFingerprint(
			Path: path,
			Exists: true,
			FileVersion: version,
			ProductVersion: version,
			Length: 1024,
			LastWriteTimeUtc: new DateTime(2026, 5, 26, 12, 0, 0, DateTimeKind.Utc),
			Sha256: sha);
	}

	private static BinaryFingerprint MakeMissing(string path)
	{
		return new BinaryFingerprint(
			Path: path,
			Exists: false,
			FileVersion: null,
			ProductVersion: null,
			Length: 0,
			LastWriteTimeUtc: null,
			Sha256: null);
	}

	private static ServiceDiagnosticsInput MakeInput(
		BinaryFingerprint dist,
		BinaryFingerprint installed,
		bool scmInstalled,
		string? scmImagePath,
		string? runtimeVersion,
		bool ipcConnected,
		RunningProcessFingerprint running)
	{
		ServiceLayoutInfo layout = new(
			ConfiguratorDirectory: "C:\\publish\\Configurator",
			DistributionDirectory: DistDir,
			DistributionExists: dist.Exists,
			ExpectedServiceExecutable: Path.Combine(DistDir, ExeName),
			ServiceExecutableExists: dist.Exists,
			InstallDirectory: InstallDir,
			ProgramDataDirectory: "C:\\ProgramData\\RdpAudit",
			AppSettingsPath: "C:\\ProgramData\\RdpAudit\\appsettings.json",
			DefaultDatabasePath: "C:\\ProgramData\\RdpAudit\\rdpaudit.db");

		ServiceInstallationInfo scm = new(
			ServiceName: "RdpAuditService",
			Installed: scmInstalled,
			DisplayName: "RDP Monitor",
			StateCode: scmInstalled ? 4 : null,
			StateName: scmInstalled ? "Running" : null,
			ProcessId: scmInstalled ? running.ProcessId : null,
			ImagePath: scmImagePath,
			StartMode: scmInstalled ? "Auto" : null,
			Status: scmInstalled ? "OK" : null,
			Win32ExitCode: 0,
			ServiceSpecificExitCode: 0,
			Diagnostic: null);

		return new ServiceDiagnosticsInput(
			ConfiguratorVersion: "1.1.0",
			Layout: layout,
			Scm: scm,
			Distribution: dist,
			Installed: installed,
			Running: running,
			IpcRuntimeVersion: runtimeVersion,
			IpcConnected: ipcConnected);
	}
}
