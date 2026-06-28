// File:    tests/RdpAudit.Core.Tests/ToolsDiagnosticsFormattingTests.cs
// Module:  RdpAudit.Core.Tests
// Purpose: Pins the pure Tools Diag formatting / metadata mapping that the Configurator's Tools Diag
//          tab relies on. Exercises ToolProbeResultMapper (ExternalCommandResult -> ToolProbeResultDto,
//          the firewall BackendCommandAttempt projection, the skipped-probe shape and the locale hint)
//          and ToolsDiagnosticsReportBuilder (the copyable transcript). All inputs are fake runner /
//          attempt objects so the suite runs on Linux CI without ever spawning a Windows command.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System;
using RdpAudit.Core.Firewall;
using RdpAudit.Core.Ipc.Contracts;
using RdpAudit.Core.Util;
using Xunit;

namespace RdpAudit.Core.Tests;

public class ToolsDiagnosticsFormattingTests
{
	private static ExternalCommandResult Result(
		int exit = 0, string stdout = "", string stderr = "", bool timedOut = false, bool englishConsole = true) =>
		new(
			CommandLabel: "qwinsta",
			Executable: "cmd.exe",
			ExitCode: exit,
			StdOut: stdout,
			StdErr: stderr,
			TimedOut: timedOut,
			Duration: TimeSpan.FromMilliseconds(33),
			EnglishConsoleMode: englishConsole);

	[Fact]
	public void Map_CarriesRunnerMetadataAndPassVerdict()
	{
		ToolProbeResultDto dto = ToolProbeResultMapper.Map(
			Result(stdout: "SESSIONNAME STATE"), "qwinsta", "qwinsta.exe", "EnglishConsole");

		Assert.Equal("qwinsta", dto.ToolName);
		Assert.Equal("cmd.exe", dto.Executable);
		Assert.Equal("qwinsta.exe", dto.Arguments);
		Assert.Equal("EnglishConsole", dto.RunnerMode);
		Assert.Equal(0, dto.ExitCode);
		Assert.Equal(33, dto.DurationMs);
		Assert.False(dto.TimedOut);
		Assert.True(dto.Passed);
		Assert.Contains("SESSIONNAME", dto.StdoutPreview, StringComparison.Ordinal);
	}

	[Fact]
	public void Map_NonZeroExit_FailsAndKeepsStderr()
	{
		ToolProbeResultDto dto = ToolProbeResultMapper.Map(
			Result(exit: 1, stderr: "Access is denied.", englishConsole: false), "netsh", "netsh.exe ...", "EnglishConsole");

		Assert.False(dto.Passed);
		Assert.Equal(1, dto.ExitCode);
		Assert.Contains("Access is denied.", dto.StderrPreview, StringComparison.Ordinal);
	}

	[Fact]
	public void Map_FallsBackToEnglishConsoleModeLabelWhenRunnerModeBlank()
	{
		ToolProbeResultDto dto = ToolProbeResultMapper.Map(
			Result(englishConsole: true), "qwinsta", "qwinsta.exe", runnerMode: string.Empty);

		Assert.Equal("EnglishConsole", dto.RunnerMode);
	}

	[Fact]
	public void Map_FlattensControlCharactersInPreviews()
	{
		ToolProbeResultDto dto = ToolProbeResultMapper.Map(
			Result(stdout: "line1\r\nline2\tcol"), "qwinsta", "qwinsta.exe", "EnglishConsole");

		Assert.DoesNotContain('\n', dto.StdoutPreview);
		Assert.DoesNotContain('\r', dto.StdoutPreview);
		Assert.DoesNotContain('\t', dto.StdoutPreview);
	}

	[Fact]
	public void DetectLocaleHint_FlagsNonAsciiOutput()
	{
		Assert.Contains("localized", ToolProbeResultMapper.DetectLocaleHint("Состояние"), StringComparison.Ordinal);
		Assert.Equal("ASCII-only output", ToolProbeResultMapper.DetectLocaleHint("STATE Active"));
		Assert.Equal(string.Empty, ToolProbeResultMapper.DetectLocaleHint(string.Empty));
	}

	[Fact]
	public void Skipped_ProducesFailWithNote()
	{
		ToolProbeResultDto dto = ToolProbeResultMapper.Skipped("qwinsta", "qwinsta.exe", "Skipped on non-Windows host.");

		Assert.Equal("Skipped", dto.RunnerMode);
		Assert.False(dto.Passed);
		Assert.Equal(-1, dto.ExitCode);
		Assert.Equal("Skipped on non-Windows host.", dto.Note);
	}

	[Fact]
	public void FromBackendAttempt_ProjectsCommandExitAndPreviews()
	{
		BackendCommandAttempt attempt = new(
			CommandLabel: "netsh add rule",
			Executable: "netsh.exe",
			Arguments: "advfirewall firewall add rule name=RdpAudit-Block-1.2.3.4",
			RunnerMode: BackendRunnerMode.Direct,
			ExitCode: 1,
			TimedOut: false,
			DurationMs: 12,
			StdoutPreview: "The parameter is incorrect.",
			StderrPreview: string.Empty,
			ScannerBackend: "NetshText");

		ToolProbeResultDto dto = ToolProbeResultMapper.FromBackendAttempt(attempt, "create temporary block rule", note: "verifier note");

		Assert.Equal("create temporary block rule", dto.ToolName);
		Assert.Equal("netsh.exe", dto.Executable);
		Assert.Equal("Direct", dto.RunnerMode);
		Assert.Equal(1, dto.ExitCode);
		Assert.False(dto.Passed);
		// stdout-on-empty-stderr: the only failure signal survives the projection.
		Assert.Contains("parameter is incorrect", dto.StdoutPreview, StringComparison.Ordinal);
		Assert.Equal("verifier note", dto.Note);
	}

	[Fact]
	public void BackendAttempt_BuildDiagnostic_FoldsStdoutWhenStderrEmptyAndExitNonZero()
	{
		BackendCommandAttempt attempt = new(
			CommandLabel: "netsh add rule",
			Executable: "netsh.exe",
			Arguments: "add rule",
			RunnerMode: BackendRunnerMode.Direct,
			ExitCode: 1,
			TimedOut: false,
			DurationMs: 5,
			StdoutPreview: "Ok.",
			StderrPreview: string.Empty);

		string diag = attempt.BuildDiagnostic();
		Assert.Contains("exit=1", diag, StringComparison.Ordinal);
		Assert.Contains("stdout=\"Ok.\"", diag, StringComparison.Ordinal);
	}

	[Fact]
	public void ReportBuilder_RendersEveryProbeWithMetadata()
	{
		ToolProbeResultDto pass = ToolProbeResultMapper.Map(
			Result(stdout: "SESSIONNAME"), "qwinsta", "qwinsta.exe", "EnglishConsole");
		ToolProbeResultDto fail = ToolProbeResultMapper.Map(
			Result(exit: 1, stderr: "boom", englishConsole: false), "powershell Get-NetFirewallRule (JSON)", "ConvertTo-Json", "PowerShellJson");

		string text = ToolsDiagnosticsReportBuilder.Build(new[] { pass, fail }, DateTime.UtcNow);

		Assert.Contains("RdpAudit Tools Diag", text, StringComparison.Ordinal);
		Assert.Contains("Probes: 2", text, StringComparison.Ordinal);
		Assert.Contains("qwinsta", text, StringComparison.Ordinal);
		Assert.Contains("PASS", text, StringComparison.Ordinal);
		Assert.Contains("FAIL", text, StringComparison.Ordinal);
		Assert.Contains("Runner mode: EnglishConsole", text, StringComparison.Ordinal);
		Assert.Contains("Runner mode: PowerShellJson", text, StringComparison.Ordinal);
		Assert.Contains("Exit code: 1", text, StringComparison.Ordinal);
	}

	[Fact]
	public void ReportBuilder_TemporaryProbe_RendersStepsRuleNameAndVerdict()
	{
		ToolProbeResultDto create = ToolProbeResultMapper.FromBackendAttempt(
			new BackendCommandAttempt(
				"netsh add rule", "netsh.exe", "add rule name=RdpAudit-ToolsDiag-TempProbe-203.0.113.10",
				BackendRunnerMode.Direct, 0, false, 9, "Ok.", string.Empty, "NetshText"),
			"create temporary block rule");

		TemporaryFirewallProbeDto dto = new()
		{
			Status = IpcResultStatus.Success,
			GeneratedUtc = DateTime.UtcNow,
			TestIp = "203.0.113.10",
			RuleName = "RdpAudit-ToolsDiag-TempProbe-203.0.113.10",
			RuleHandle = "RdpAudit-ToolsDiag-TempProbe-203.0.113.10",
			ScannerBackend = "NetshText",
			CreatedVerifiedAndCleanedUp = true,
			Steps = { create },
		};

		string text = ToolsDiagnosticsReportBuilder.BuildTemporaryProbe(dto);

		Assert.Contains("temporary firewall rule probe", text, StringComparison.Ordinal);
		Assert.Contains("203.0.113.10", text, StringComparison.Ordinal);
		Assert.Contains("RdpAudit-ToolsDiag-TempProbe-203.0.113.10", text, StringComparison.Ordinal);
		Assert.Contains("Scanner backend: NetshText", text, StringComparison.Ordinal);
		Assert.Contains("Created+verified+cleaned up: YES", text, StringComparison.Ordinal);
		Assert.Contains("create temporary block rule", text, StringComparison.Ordinal);
	}
}
