// File:    tests/RdpAudit.Core.Tests/BackendCommandAttemptTests.cs
// Module:  RdpAudit.Core.Tests
// Purpose: Guards BackendCommandAttempt.RenderCommandLine against the historic duplicated-verb defect
//          where naively concatenating CommandLabel + Arguments produced
//          "New-NetFirewallRule -Group RdpAudit New-NetFirewallRule -Name ...". The rendered command
//          line must be built from the structured Executable / Arguments vector actually used for
//          execution and must never duplicate the leading verb.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using RdpAudit.Core.Firewall;
using Xunit;

namespace RdpAudit.Core.Tests;

/// <summary>Invariants on BackendCommandAttempt command-line rendering.</summary>
public class BackendCommandAttemptTests
{
	private static BackendCommandAttempt Make(string label, string exe, string args)
	{
		return new BackendCommandAttempt(
			CommandLabel: label,
			Executable: exe,
			Arguments: args,
			RunnerMode: BackendRunnerMode.PowerShellJson,
			ExitCode: 0,
			TimedOut: false,
			DurationMs: 12,
			StdoutPreview: string.Empty,
			StderrPreview: string.Empty);
	}

	[Fact]
	public void RenderCommandLine_JoinsExecutableAndArguments()
	{
		BackendCommandAttempt a = Make(
			"New-NetFirewallRule -Group RdpAudit",
			"powershell.exe",
			"New-NetFirewallRule -Name RdpAudit-Block-1.2.3.4 -Group RdpAudit -RemoteAddress 1.2.3.4");

		Assert.Equal(
			"powershell.exe New-NetFirewallRule -Name RdpAudit-Block-1.2.3.4 -Group RdpAudit -RemoteAddress 1.2.3.4",
			a.RenderCommandLine());
	}

	[Fact]
	public void RenderCommandLine_DoesNotDuplicateLeadingVerb()
	{
		BackendCommandAttempt a = Make(
			"New-NetFirewallRule -Group RdpAudit",
			"powershell.exe",
			"New-NetFirewallRule -Name RdpAudit-Block-1.2.3.4 -Group RdpAudit");

		string rendered = a.RenderCommandLine();

		// The defect produced "New-NetFirewallRule -Group RdpAudit New-NetFirewallRule -Name ...".
		Assert.DoesNotContain("New-NetFirewallRule -Group RdpAudit New-NetFirewallRule", rendered, StringComparison.Ordinal);
		int firstVerb = rendered.IndexOf("New-NetFirewallRule", StringComparison.Ordinal);
		int lastVerb = rendered.LastIndexOf("New-NetFirewallRule", StringComparison.Ordinal);
		Assert.Equal(firstVerb, lastVerb);
	}

	[Fact]
	public void RenderCommandLine_FallsBackToArgumentsWhenExecutableEmpty()
	{
		BackendCommandAttempt a = Make("label", string.Empty, "netsh advfirewall firewall add rule");
		Assert.Equal("netsh advfirewall firewall add rule", a.RenderCommandLine());
	}

	[Fact]
	public void RenderCommandLine_FallsBackToExecutableWhenArgumentsEmpty()
	{
		BackendCommandAttempt a = Make("label", "powershell.exe", string.Empty);
		Assert.Equal("powershell.exe", a.RenderCommandLine());
	}

	[Fact]
	public void RenderCommandLine_FallsBackToLabelWhenExecutableAndArgumentsEmpty()
	{
		BackendCommandAttempt a = Make("only-label", string.Empty, string.Empty);
		Assert.Equal("only-label", a.RenderCommandLine());
	}
}
