// File:    tests/RdpAudit.Core.Tests/ExternalCommandResultTests.cs
// Module:  RdpAudit.Core.Tests
// Purpose: Validates the Stage-3 ExternalCommandResult diagnostic summary builder. The
//          summary is the canonical single-line representation of a captured external-command
//          invocation — it appears in service logs, UI status bars and clipboard exports.
//          The tests pin its shape so future log-analysis tools can rely on it.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System;
using RdpAudit.Core.Util;
using Xunit;

namespace RdpAudit.Core.Tests;

public class ExternalCommandResultTests
{
	[Fact]
	public void Success_ZeroExitCode_NoTimeout_IsTrue()
	{
		ExternalCommandResult r = new(
			CommandLabel: "qwinsta",
			Executable: "cmd.exe",
			ExitCode: 0,
			StdOut: "SESSIONNAME...",
			StdErr: string.Empty,
			TimedOut: false,
			Duration: TimeSpan.FromMilliseconds(42),
			EnglishConsoleMode: true);

		Assert.True(r.Success);
	}

	[Fact]
	public void Success_NonZeroExitCode_IsFalse()
	{
		ExternalCommandResult r = new(
			CommandLabel: "netsh add rule",
			Executable: "netsh.exe",
			ExitCode: 1,
			StdOut: string.Empty,
			StdErr: "Access denied.",
			TimedOut: false,
			Duration: TimeSpan.FromMilliseconds(7),
			EnglishConsoleMode: false);

		Assert.False(r.Success);
	}

	[Fact]
	public void Success_TimedOut_IsFalseEvenWithZeroExit()
	{
		ExternalCommandResult r = new(
			CommandLabel: "qwinsta",
			Executable: "cmd.exe",
			ExitCode: 0,
			StdOut: string.Empty,
			StdErr: string.Empty,
			TimedOut: true,
			Duration: TimeSpan.FromSeconds(15),
			EnglishConsoleMode: true);

		Assert.False(r.Success);
	}

	[Fact]
	public void BuildDiagnosticSummary_IncludesLabelExitMsAndEnglishConsoleFlag()
	{
		ExternalCommandResult r = new(
			CommandLabel: "qwinsta",
			Executable: "cmd.exe",
			ExitCode: 0,
			StdOut: "SESSIONNAME...",
			StdErr: string.Empty,
			TimedOut: false,
			Duration: TimeSpan.FromMilliseconds(42),
			EnglishConsoleMode: true);

		string summary = r.BuildDiagnosticSummary();
		Assert.Contains("qwinsta", summary, StringComparison.Ordinal);
		Assert.Contains("exit=0", summary, StringComparison.Ordinal);
		Assert.Contains("ms=42", summary, StringComparison.Ordinal);
		Assert.Contains("(en-console)", summary, StringComparison.Ordinal);
		Assert.DoesNotContain("(timed-out)", summary, StringComparison.Ordinal);
	}

	[Fact]
	public void BuildDiagnosticSummary_IncludesTimedOutFlag()
	{
		ExternalCommandResult r = new(
			CommandLabel: "auditpol /get",
			Executable: "cmd.exe",
			ExitCode: -1,
			StdOut: string.Empty,
			StdErr: string.Empty,
			TimedOut: true,
			Duration: TimeSpan.FromSeconds(15),
			EnglishConsoleMode: true);

		string summary = r.BuildDiagnosticSummary();
		Assert.Contains("(timed-out)", summary, StringComparison.Ordinal);
	}

	[Fact]
	public void BuildDiagnosticSummary_FlattensMultilineStderr()
	{
		ExternalCommandResult r = new(
			CommandLabel: "netsh add rule",
			Executable: "netsh.exe",
			ExitCode: 1,
			StdOut: string.Empty,
			StdErr: "Access denied.\r\nDetails: insufficient privilege\n",
			TimedOut: false,
			Duration: TimeSpan.FromMilliseconds(7),
			EnglishConsoleMode: false);

		string summary = r.BuildDiagnosticSummary();
		Assert.DoesNotContain('\n', summary);
		Assert.DoesNotContain('\r', summary);
		Assert.Contains("Access denied.", summary, StringComparison.Ordinal);
	}

	[Fact]
	public void BuildDiagnosticSummary_BoundedTo240CharsForStderr()
	{
		string huge = new('X', 1024);
		ExternalCommandResult r = new(
			CommandLabel: "x",
			Executable: "x.exe",
			ExitCode: 1,
			StdOut: string.Empty,
			StdErr: huge,
			TimedOut: false,
			Duration: TimeSpan.Zero,
			EnglishConsoleMode: false);

		string summary = r.BuildDiagnosticSummary();
		// Truncated stderr must end with the ellipsis sentinel.
		Assert.Contains("…", summary, StringComparison.Ordinal);
		// And the summary itself must be well under the raw 1024-char payload length.
		Assert.True(summary.Length < 400);
	}

	[Fact]
	public void BuildDiagnosticSummary_DoesNotIncludeStdoutWhenSuccess()
	{
		ExternalCommandResult r = new(
			CommandLabel: "qwinsta",
			Executable: "cmd.exe",
			ExitCode: 0,
			StdOut: "lots of session rows here",
			StdErr: string.Empty,
			TimedOut: false,
			Duration: TimeSpan.Zero,
			EnglishConsoleMode: true);

		string summary = r.BuildDiagnosticSummary();
		Assert.DoesNotContain("stdout=", summary, StringComparison.Ordinal);
	}

	[Fact]
	public void BuildDiagnosticSummary_DirectMode_DoesNotEmitEnglishConsoleFlag()
	{
		ExternalCommandResult r = new(
			CommandLabel: "logoff 12",
			Executable: "logoff.exe",
			ExitCode: 0,
			StdOut: string.Empty,
			StdErr: string.Empty,
			TimedOut: false,
			Duration: TimeSpan.FromMilliseconds(2),
			EnglishConsoleMode: false);

		string summary = r.BuildDiagnosticSummary();
		Assert.DoesNotContain("(en-console)", summary, StringComparison.Ordinal);
	}
}
