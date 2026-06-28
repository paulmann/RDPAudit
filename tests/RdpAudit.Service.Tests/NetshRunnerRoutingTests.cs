// File:    tests/RdpAudit.Service.Tests/NetshRunnerRoutingTests.cs
// Module:  RdpAudit.Service.Tests
// Purpose: Stage-3 regression suite for the production NetshRunner. Verifies that the parse-
//          dependent "show allprofiles state" probe is routed through the centralized English
//          console runner (so the "ON"/"OFF" tokens are emitted in stable Latin script), while
//          every other invocation — including mutating add-rule / delete-rule — uses direct
//          argument-list execution (no shell wrapping). Uses a fake IExternalCommandRunner so
//          the test stays fully host-independent.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using RdpAudit.Core.Util;
using RdpAudit.Service.Firewall;
using Xunit;

namespace RdpAudit.Service.Tests;

public class NetshRunnerRoutingTests
{
	[Fact]
	public async Task ShowAllProfilesState_GoesThroughEnglishConsole()
	{
		FakeExternalCommandRunner fake = new()
		{
			NextResult = MakeResult("netsh advfirewall show allprofiles state", englishConsole: true,
				stdOut: "Domain Profile Settings:\nState                                 ON\n"),
		};
		NetshRunner sut = new(fake, TimeSpan.FromSeconds(5));

		NetshResult result = await sut.RunAsync(
			NetshCommandBuilder.BuildShowAllProfilesStateArgs(),
			CancellationToken.None);

		Assert.Equal(1, fake.EnglishConsoleCalls);
		Assert.Equal(0, fake.DirectCalls);
		Assert.Equal(TrustedEnglishConsoleTool.NetshShowAllProfilesState, fake.LastEnglishConsoleTool);
		Assert.True(result.Success);
		Assert.Contains("ON", result.StdOut, StringComparison.Ordinal);
	}

	[Fact]
	public async Task AddRule_UsesDirectArgumentList()
	{
		FakeExternalCommandRunner fake = new()
		{
			NextResult = MakeResult("netsh advfirewall firewall add rule", englishConsole: false),
		};
		NetshRunner sut = new(fake, TimeSpan.FromSeconds(5));

		await sut.RunAsync(
			NetshCommandBuilder.BuildAddRuleArgs("RdpAudit-Block-1.2.3.4", "1.2.3.4", description: null),
			CancellationToken.None);

		Assert.Equal(0, fake.EnglishConsoleCalls);
		Assert.Equal(1, fake.DirectCalls);
		Assert.Equal("netsh.exe", fake.LastDirectExecutable);
		Assert.NotNull(fake.LastDirectArguments);
		Assert.Contains("name=RdpAudit-Block-1.2.3.4", fake.LastDirectArguments!);
		Assert.Contains("dir=in", fake.LastDirectArguments!);
		Assert.Contains("remoteip=1.2.3.4", fake.LastDirectArguments!);
	}

	[Fact]
	public async Task DeleteRule_UsesDirectArgumentList()
	{
		FakeExternalCommandRunner fake = new()
		{
			NextResult = MakeResult("netsh advfirewall firewall delete rule", englishConsole: false),
		};
		NetshRunner sut = new(fake, TimeSpan.FromSeconds(5));

		await sut.RunAsync(
			NetshCommandBuilder.BuildDeleteRuleArgs("RdpAudit-Block-1.2.3.4"),
			CancellationToken.None);

		Assert.Equal(0, fake.EnglishConsoleCalls);
		Assert.Equal(1, fake.DirectCalls);
	}

	[Fact]
	public async Task ShowRuleByName_GoesThroughEnglishConsole()
	{
		// Single-rule "show rule name=<X> verbose" is the post-block verification query. The
		// NetshRuleScanner matches English field labels ("Rule Name:", "Enabled:", "Direction:",
		// "Action:"); on a localised host (e.g. ru-RU) direct netsh emits translated / mojibake
		// labels the scanner cannot match — the operator-reported "rule created but verification
		// fails" symptom. Routing it through the English console (chcp 437) keeps the keys in Latin
		// script regardless of host UI culture.
		FakeExternalCommandRunner fake = new()
		{
			NextResult = MakeResult("netsh advfirewall firewall show rule name=...", englishConsole: true),
		};
		NetshRunner sut = new(fake, TimeSpan.FromSeconds(5));

		await sut.RunAsync(
			NetshCommandBuilder.BuildShowRuleArgs("RdpAudit-Block-1.2.3.4"),
			CancellationToken.None);

		Assert.Equal(1, fake.EnglishConsoleCalls);
		Assert.Equal(0, fake.DirectCalls);
		Assert.Equal(TrustedEnglishConsoleTool.NetshShowNamedRuleVerbose, fake.LastEnglishConsoleTool);
		Assert.Equal("RdpAudit-Block-1.2.3.4", fake.LastEnglishConsoleArgs?.RuleName);
	}

	[Fact]
	public async Task ShowAllRulesByName_UsesDirectArgumentList()
	{
		// The "name=all" reconciliation dump is NOT a single-rule verification; it is routed by its
		// own callers through the dedicated NetshShowAllRulesVerbose tool, so the runner must leave it
		// on the direct path rather than treating it as a single named rule.
		FakeExternalCommandRunner fake = new()
		{
			NextResult = MakeResult("netsh advfirewall firewall show rule name=all", englishConsole: false),
		};
		NetshRunner sut = new(fake, TimeSpan.FromSeconds(5));

		await sut.RunAsync(
			NetshCommandBuilder.BuildShowAllRulesArgs(),
			CancellationToken.None);

		Assert.Equal(0, fake.EnglishConsoleCalls);
		Assert.Equal(1, fake.DirectCalls);
	}

	[Fact]
	public async Task ShowAllProfilesState_Timeout_MapsTo_NegativeOneExit()
	{
		FakeExternalCommandRunner fake = new()
		{
			NextResult = new ExternalCommandResult(
				CommandLabel: "netsh advfirewall show allprofiles state",
				Executable: "cmd.exe",
				ExitCode: 0,
				StdOut: string.Empty,
				StdErr: string.Empty,
				TimedOut: true,
				Duration: TimeSpan.FromSeconds(15),
				EnglishConsoleMode: true),
		};
		NetshRunner sut = new(fake, TimeSpan.FromSeconds(5));

		NetshResult result = await sut.RunAsync(
			NetshCommandBuilder.BuildShowAllProfilesStateArgs(),
			CancellationToken.None);

		Assert.Equal(-1, result.ExitCode);
		Assert.False(result.Success);
	}

	private static ExternalCommandResult MakeResult(
		string label,
		bool englishConsole,
		int exitCode = 0,
		string stdOut = "",
		string stdErr = "")
		=> new(
			CommandLabel: label,
			Executable: englishConsole ? "cmd.exe" : "netsh.exe",
			ExitCode: exitCode,
			StdOut: stdOut,
			StdErr: stdErr,
			TimedOut: false,
			Duration: TimeSpan.FromMilliseconds(1),
			EnglishConsoleMode: englishConsole);

	private sealed class FakeExternalCommandRunner : IExternalCommandRunner
	{
		public int EnglishConsoleCalls { get; private set; }
		public int DirectCalls { get; private set; }
		public TrustedEnglishConsoleTool LastEnglishConsoleTool { get; private set; }
		public EnglishConsoleArgs? LastEnglishConsoleArgs { get; private set; }
		public string? LastDirectExecutable { get; private set; }
		public IReadOnlyList<string>? LastDirectArguments { get; private set; }
		public ExternalCommandResult NextResult { get; set; } = new(
			CommandLabel: "fake",
			Executable: "fake.exe",
			ExitCode: 0,
			StdOut: string.Empty,
			StdErr: string.Empty,
			TimedOut: false,
			Duration: TimeSpan.Zero,
			EnglishConsoleMode: false);

		public Task<ExternalCommandResult> RunEnglishConsoleAsync(
			TrustedEnglishConsoleTool tool,
			EnglishConsoleArgs? args,
			TimeSpan timeout,
			CancellationToken ct)
		{
			EnglishConsoleCalls++;
			LastEnglishConsoleTool = tool;
			LastEnglishConsoleArgs = args;
			return Task.FromResult(NextResult);
		}

		public Task<ExternalCommandResult> RunDirectAsync(
			string commandLabel,
			string executable,
			IReadOnlyList<string> arguments,
			TimeSpan timeout,
			CancellationToken ct)
		{
			DirectCalls++;
			LastDirectExecutable = executable;
			LastDirectArguments = arguments;
			return Task.FromResult(NextResult);
		}
	}
}
