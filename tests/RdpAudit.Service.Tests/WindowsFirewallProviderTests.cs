// File:    tests/RdpAudit.Service.Tests/WindowsFirewallProviderTests.cs
// Module:  RdpAudit.Service.Tests
// Purpose: Unit tests for the WindowsFirewallProvider. Verifies that the provider validates
//          inputs, refuses reserved addresses by policy, drives netsh idempotently via the
//          ArgumentList path, and surfaces controlled DTOs instead of raw exceptions.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using RdpAudit.Core.Config;
using RdpAudit.Core.Firewall;
using RdpAudit.Core.Util;
using RdpAudit.Service.Firewall;
using Xunit;

namespace RdpAudit.Service.Tests;

public class WindowsFirewallProviderTests
{
	private static IOptionsMonitor<RdpAuditOptions> CreateOptions(RdpAuditOptions? opts = null)
	{
		opts ??= new RdpAuditOptions();
		return new StaticOptionsMonitor<RdpAuditOptions>(opts);
	}

	private static NetshResult NetshSuccess() => new(0, string.Empty, string.Empty);

	private static NetshResult NetshShowRule(string stdOut) => new(0, stdOut, string.Empty);

	// Minimal verbose `show rule` dump that satisfies the v1.2.4 post-block verification gate:
	// an enabled, inbound, block rule. Mirrors the locale-stable English keys netsh emits.
	private static string EnabledInboundBlockDump(string ruleName)
		=> "Rule Name:                            " + ruleName + "\n"
			+ "----------------------------------------------------------------------\n"
			+ "Enabled:                              Yes\n"
			+ "Direction:                            In\n"
			+ "Profiles:                             Domain,Private,Public\n"
			+ "LocalIP:                              Any\n"
			+ "RemoteIP:                             Any\n"
			+ "Protocol:                             TCP\n"
			+ "Action:                               Block\n"
			+ "\n";

	[Fact]
	public async Task Block_ValidPublicAddress_AddsRuleAndReturnsSuccess()
	{
		FakeNetshRunner runner = new();
		// Script the v1.2.4 verify-after-block sequence: delete (idempotent cleanup), add, then the
		// post-add `show rule` query whose verbose dump confirms an enabled inbound block rule landed.
		runner.Responses.Enqueue(NetshSuccess());
		runner.Responses.Enqueue(NetshSuccess());
		runner.Responses.Enqueue(NetshShowRule(EnabledInboundBlockDump("RdpAudit-Block-203.0.113.10")));
		WindowsFirewallProvider provider = new(
			NullLogger<WindowsFirewallProvider>.Instance,
			CreateOptions(),
			runner,
			new FakeRdpPortProvider());

		FirewallActionResult result = await provider.BlockAsync(
			new FirewallBlockRequest("203.0.113.10", "RdpAudit-Block")
			{
				Reason = "unit-test",
				Duration = TimeSpan.FromMinutes(30),
			},
			CancellationToken.None);

		if (OperatingSystem.IsWindows())
		{
			Assert.Equal(FirewallActionStatus.Success, result.Status);
			Assert.Equal("RdpAudit-Block-203.0.113.10", result.RuleId);
			// 1 delete (idempotent prefix-cleanup) + 1 add + 1 verify (show rule).
			Assert.Equal(3, runner.Calls.Count);
			Assert.Contains("add", runner.Calls[1]);
			Assert.Contains("remoteip=203.0.113.10", runner.Calls[1]);
		}
		else
		{
			Assert.Equal(FirewallActionStatus.Unavailable, result.Status);
		}
	}

	[Fact]
	public async Task Block_InvalidIp_ReturnsInvalidRequest()
	{
		FakeNetshRunner runner = new();
		WindowsFirewallProvider provider = new(
			NullLogger<WindowsFirewallProvider>.Instance,
			CreateOptions(),
			runner,
			new FakeRdpPortProvider());

		FirewallActionResult result = await provider.BlockAsync(
			new FirewallBlockRequest("not-an-ip", "RdpAudit-Block"),
			CancellationToken.None);

		if (OperatingSystem.IsWindows())
		{
			Assert.Equal(FirewallActionStatus.InvalidRequest, result.Status);
			Assert.Empty(runner.Calls);
		}
		else
		{
			Assert.Equal(FirewallActionStatus.Unavailable, result.Status);
		}
	}

	[Fact]
	public async Task Block_LoopbackAddress_RefusedByPolicy()
	{
		FakeNetshRunner runner = new();
		WindowsFirewallProvider provider = new(
			NullLogger<WindowsFirewallProvider>.Instance,
			CreateOptions(new RdpAuditOptions { Firewall = new FirewallOptions { RefusePrivateAddressBlock = true } }),
			runner,
			new FakeRdpPortProvider());

		FirewallActionResult result = await provider.BlockAsync(
			new FirewallBlockRequest("127.0.0.1", "RdpAudit-Block"),
			CancellationToken.None);

		if (OperatingSystem.IsWindows())
		{
			Assert.Equal(FirewallActionStatus.Refused, result.Status);
			Assert.Empty(runner.Calls);
		}
		else
		{
			Assert.Equal(FirewallActionStatus.Unavailable, result.Status);
		}
	}

	[Fact]
	public async Task Block_LoopbackAddress_AllowedWhenPolicyDisabled()
	{
		FakeNetshRunner runner = new();
		// delete + add + verify; the verify dump confirms an enabled inbound block rule landed.
		runner.Responses.Enqueue(NetshSuccess());
		runner.Responses.Enqueue(NetshSuccess());
		runner.Responses.Enqueue(NetshShowRule(EnabledInboundBlockDump("RdpAudit-Block-10.0.0.1")));
		WindowsFirewallProvider provider = new(
			NullLogger<WindowsFirewallProvider>.Instance,
			CreateOptions(new RdpAuditOptions { Firewall = new FirewallOptions { RefusePrivateAddressBlock = false } }),
			runner,
			new FakeRdpPortProvider());

		FirewallActionResult result = await provider.BlockAsync(
			new FirewallBlockRequest("10.0.0.1", "RdpAudit-Block"),
			CancellationToken.None);

		if (OperatingSystem.IsWindows())
		{
			Assert.Equal(FirewallActionStatus.Success, result.Status);
		}
		else
		{
			Assert.Equal(FirewallActionStatus.Unavailable, result.Status);
		}
	}

	[Fact]
	public async Task Unblock_NoMatchingRule_ReturnsNotFound()
	{
		FakeNetshRunner runner = new();
		runner.Responses.Enqueue(new NetshResult(1, "No rules match the specified criteria.", string.Empty));
		WindowsFirewallProvider provider = new(
			NullLogger<WindowsFirewallProvider>.Instance,
			CreateOptions(),
			runner,
			new FakeRdpPortProvider());

		FirewallActionResult result = await provider.UnblockAsync(
			"203.0.113.10",
			"RdpAudit-Block",
			CancellationToken.None);

		if (OperatingSystem.IsWindows())
		{
			Assert.Equal(FirewallActionStatus.NotFound, result.Status);
		}
		else
		{
			Assert.Equal(FirewallActionStatus.Unavailable, result.Status);
		}
	}

	[Fact]
	public async Task Unblock_ProviderReturnsSuccess_FlipsStatusSuccess()
	{
		FakeNetshRunner runner = new();
		WindowsFirewallProvider provider = new(
			NullLogger<WindowsFirewallProvider>.Instance,
			CreateOptions(),
			runner,
			new FakeRdpPortProvider());

		FirewallActionResult result = await provider.UnblockAsync(
			"203.0.113.10",
			"RdpAudit-Block",
			CancellationToken.None);

		if (OperatingSystem.IsWindows())
		{
			Assert.Equal(FirewallActionStatus.Success, result.Status);
			Assert.Equal("RdpAudit-Block-203.0.113.10", result.RuleId);
			Assert.Single(runner.Calls);
			Assert.Contains("delete", runner.Calls[0]);
			Assert.Contains("name=RdpAudit-Block-203.0.113.10", runner.Calls[0]);
		}
		else
		{
			Assert.Equal(FirewallActionStatus.Unavailable, result.Status);
		}
	}

	[Fact]
	public async Task GetStatus_NonWindowsHost_ReportsUnreachable()
	{
		if (OperatingSystem.IsWindows())
		{
			return;
		}

		FakeNetshRunner runner = new();
		WindowsFirewallProvider provider = new(
			NullLogger<WindowsFirewallProvider>.Instance,
			CreateOptions(),
			runner,
			new FakeRdpPortProvider());

		FirewallStatusReport report = await provider.GetStatusAsync(CancellationToken.None);
		Assert.Equal(FirewallProviderStatus.Unreachable, report.Status);
		Assert.Equal("Windows", report.ProviderId);
	}

	[Fact]
	public async Task Block_AddRuleNonZeroExit_ReturnsUnavailable()
	{
		FakeNetshRunner runner = new();
		// delete (success) then add fails with a non-zero exit — the firewall service / netsh could
		// not run the add, so the provider must surface Unavailable without attempting verification.
		runner.Responses.Enqueue(NetshSuccess());
		runner.Responses.Enqueue(new NetshResult(1, string.Empty, "The requested operation requires elevation."));
		WindowsFirewallProvider provider = new(
			NullLogger<WindowsFirewallProvider>.Instance,
			CreateOptions(),
			runner,
			new FakeRdpPortProvider());

		FirewallActionResult result = await provider.BlockAsync(
			new FirewallBlockRequest("203.0.113.10", "RdpAudit-Block"),
			CancellationToken.None);

		if (OperatingSystem.IsWindows())
		{
			Assert.Equal(FirewallActionStatus.Unavailable, result.Status);
			// delete + add only; verification is never reached once the add fails.
			Assert.Equal(2, runner.Calls.Count);
		}
		else
		{
			Assert.Equal(FirewallActionStatus.Unavailable, result.Status);
		}
	}

	[Fact]
	public async Task Block_PowerShellRunnerWired_UsesNewNetFirewallRuleStampingGroup()
	{
		if (!OperatingSystem.IsWindows())
		{
			return;
		}

		FakeNetshRunner runner = new();
		// delete (idempotent prefix-cleanup) then the post-add verify dump. No netsh `add` should run
		// because the PowerShell create path succeeds and is preferred.
		runner.Responses.Enqueue(NetshSuccess());
		runner.Responses.Enqueue(NetshShowRule(EnabledInboundBlockDump("RdpAudit-Block-203.0.113.10")));
		CapturingCommandRunner ps = new();
		WindowsFirewallProvider provider = new(
			NullLogger<WindowsFirewallProvider>.Instance,
			CreateOptions(),
			runner,
			new FakeRdpPortProvider(),
			ps);

		FirewallActionResult result = await provider.BlockAsync(
			new FirewallBlockRequest("203.0.113.10", "RdpAudit-Block") { Reason = "unit-test" },
			CancellationToken.None);

		Assert.Equal(FirewallActionStatus.Success, result.Status);
		Assert.Equal(BackendRunnerMode.PowerShellJson, result.BackendAttempt!.RunnerMode);
		// The PowerShell create path is the supported way to stamp the firewall Group.
		Assert.Contains("New-NetFirewallRule", ps.LastScript, StringComparison.Ordinal);
		Assert.Contains("-Group 'RdpAudit'", ps.LastScript, StringComparison.Ordinal);
		Assert.Contains("-RemoteAddress '203.0.113.10'", ps.LastScript, StringComparison.Ordinal);
		// netsh `add` must NOT be invoked once the PowerShell create succeeds.
		Assert.DoesNotContain(runner.Calls, call => call.Contains("add"));
	}

	[Fact]
	public async Task Block_PowerShellCreateFails_FallsBackToNetshAddWithoutGroup()
	{
		if (!OperatingSystem.IsWindows())
		{
			return;
		}

		FakeNetshRunner runner = new();
		// delete + add (fallback) + verify.
		runner.Responses.Enqueue(NetshSuccess());
		runner.Responses.Enqueue(NetshSuccess());
		runner.Responses.Enqueue(NetshShowRule(EnabledInboundBlockDump("RdpAudit-Block-203.0.113.10")));
		CapturingCommandRunner ps = new() { ExitCode = 1, StdErr = "New-NetFirewallRule failed." };
		WindowsFirewallProvider provider = new(
			NullLogger<WindowsFirewallProvider>.Instance,
			CreateOptions(),
			runner,
			new FakeRdpPortProvider(),
			ps);

		FirewallActionResult result = await provider.BlockAsync(
			new FirewallBlockRequest("203.0.113.10", "RdpAudit-Block") { Reason = "unit-test" },
			CancellationToken.None);

		Assert.Equal(FirewallActionStatus.Success, result.Status);
		// PowerShell was tried, then the netsh add fallback ran — and it carries no group=/grouping=.
		IReadOnlyList<string>? addCall = runner.Calls.FirstOrDefault(c => c.Contains("add"));
		Assert.NotNull(addCall);
		Assert.DoesNotContain(addCall!, a => a.StartsWith("group=", StringComparison.OrdinalIgnoreCase));
		Assert.DoesNotContain(addCall!, a => a.StartsWith("grouping=", StringComparison.OrdinalIgnoreCase));
	}

	[Fact]
	public async Task Block_ScannerWired_VerifiesByTargetedExactName()
	{
		if (!OperatingSystem.IsWindows())
		{
			return;
		}

		FakeNetshRunner runner = new();
		// delete (idempotent prefix-cleanup) then the PowerShell create. No netsh verify `show rule`
		// should run — verification goes through the locale-independent scanner instead.
		runner.Responses.Enqueue(NetshSuccess());
		CapturingCommandRunner ps = new();
		FakeFirewallRuleScanner scanner = new();
		// The scanner returns the rule by its exact deterministic per-IP name — the targeted match.
		scanner.Result = new FirewallScanResult(
			Scannable: true,
			Rules: new[]
			{
				new DiscoveredBlockRule(
					RuleName: "RdpAudit-Block-203.0.113.10",
					Enabled: true,
					DirectionInbound: true,
					ActionBlock: true,
					Protocol: "Any",
					LocalPorts: Array.Empty<int>(),
					RemoteIps: new[] { "203.0.113.10" }),
			},
			Note: "test",
			Backend: FirewallScanBackend.PowerShellJson);
		WindowsFirewallProvider provider = new(
			NullLogger<WindowsFirewallProvider>.Instance,
			CreateOptions(),
			runner,
			new FakeRdpPortProvider(),
			ps,
			scanner);

		FirewallActionResult result = await provider.BlockAsync(
			new FirewallBlockRequest("203.0.113.10", "RdpAudit-Block") { Reason = "unit-test" },
			CancellationToken.None);

		Assert.Equal(FirewallActionStatus.Success, result.Status);
		Assert.Equal(1, scanner.Calls);
		Assert.Contains("targeted verify by name", result.VerifierReason, StringComparison.Ordinal);
		Assert.Contains("found", result.VerifierReason!, StringComparison.Ordinal);
		// The locale-fragile netsh `show rule` verify must NOT run when the scanner is wired.
		Assert.DoesNotContain(runner.Calls, call => call.Contains("show"));
	}

	[Fact]
	public async Task Block_ScannerWired_TargetedNameMissing_ReturnsUnavailable()
	{
		if (!OperatingSystem.IsWindows())
		{
			return;
		}

		FakeNetshRunner runner = new();
		runner.Responses.Enqueue(NetshSuccess());
		CapturingCommandRunner ps = new();
		FakeFirewallRuleScanner scanner = new();
		// Scanner is healthy and returns a DIFFERENT RdpAudit rule, but not the one we just created —
		// targeted verify by exact name must fail and the provider must report Unavailable.
		scanner.Result = new FirewallScanResult(
			Scannable: true,
			Rules: new[]
			{
				new DiscoveredBlockRule(
					RuleName: "RdpAudit-Block-198.51.100.7",
					Enabled: true,
					DirectionInbound: true,
					ActionBlock: true,
					Protocol: "Any",
					LocalPorts: Array.Empty<int>(),
					RemoteIps: new[] { "198.51.100.7" }),
			},
			Note: "test",
			Backend: FirewallScanBackend.PowerShellJson);
		WindowsFirewallProvider provider = new(
			NullLogger<WindowsFirewallProvider>.Instance,
			CreateOptions(),
			runner,
			new FakeRdpPortProvider(),
			ps,
			scanner);

		FirewallActionResult result = await provider.BlockAsync(
			new FirewallBlockRequest("203.0.113.10", "RdpAudit-Block") { Reason = "unit-test" },
			CancellationToken.None);

		Assert.Equal(FirewallActionStatus.Unavailable, result.Status);
		Assert.Contains("not found", result.VerifierReason, StringComparison.Ordinal);
	}

	[Fact]
	public async Task ListBlocks_ScannerWired_ReturnsPerIpRuleByGroup()
	{
		if (!OperatingSystem.IsWindows())
		{
			return;
		}

		FakeNetshRunner runner = new();
		FakeFirewallRuleScanner scanner = new();
		// The scanner matches by group, so the per-IP temp-probe rule is returned by its FULL name even
		// though the caller passes only the base prefix. This is the fix for the temp-probe "verify FAIL".
		scanner.Result = new FirewallScanResult(
			Scannable: true,
			Rules: new[]
			{
				new DiscoveredBlockRule(
					RuleName: "RdpAudit-ToolsDiag-TempProbe-78.37.40.185",
					Enabled: true,
					DirectionInbound: true,
					ActionBlock: true,
					Protocol: "Any",
					LocalPorts: Array.Empty<int>(),
					RemoteIps: new[] { "78.37.40.185" }),
			},
			Note: "test",
			Backend: FirewallScanBackend.PowerShellJson);
		WindowsFirewallProvider provider = new(
			NullLogger<WindowsFirewallProvider>.Instance,
			CreateOptions(),
			runner,
			new FakeRdpPortProvider(),
			powerShellRunner: null,
			scanner: scanner);

		IReadOnlyList<FirewallBlockEntry> entries =
			await provider.ListBlocksAsync("RdpAudit-ToolsDiag-TempProbe", CancellationToken.None);

		Assert.Single(entries);
		Assert.Equal("RdpAudit-ToolsDiag-TempProbe-78.37.40.185", entries[0].RuleId);
		Assert.Equal("78.37.40.185", entries[0].Ip);
		// No netsh `show rule` text query when the scanner is wired.
		Assert.DoesNotContain(runner.Calls, call => call.Contains("show"));
	}

	[Fact]
	public async Task Block_VerificationFindsNoRule_ReturnsUnavailable()
	{
		FakeNetshRunner runner = new();
		// delete + add both report success, but the post-add `show rule` query returns an empty dump
		// (a managing third-party firewall silently swallowed the write). The provider must not claim
		// success when the rule cannot be verified in the firewall store.
		runner.Responses.Enqueue(NetshSuccess());
		runner.Responses.Enqueue(NetshSuccess());
		runner.Responses.Enqueue(NetshShowRule(string.Empty));
		WindowsFirewallProvider provider = new(
			NullLogger<WindowsFirewallProvider>.Instance,
			CreateOptions(),
			runner,
			new FakeRdpPortProvider());

		FirewallActionResult result = await provider.BlockAsync(
			new FirewallBlockRequest("203.0.113.10", "RdpAudit-Block"),
			CancellationToken.None);

		if (OperatingSystem.IsWindows())
		{
			Assert.Equal(FirewallActionStatus.Unavailable, result.Status);
			// delete + add + verify.
			Assert.Equal(3, runner.Calls.Count);
		}
		else
		{
			Assert.Equal(FirewallActionStatus.Unavailable, result.Status);
		}
	}
}

internal sealed class CapturingCommandRunner : IExternalCommandRunner
{
	public string LastScript { get; private set; } = string.Empty;

	public int ExitCode { get; set; }

	public string StdErr { get; set; } = string.Empty;

	public Task<ExternalCommandResult> RunEnglishConsoleAsync(
		TrustedEnglishConsoleTool tool, EnglishConsoleArgs? args, TimeSpan timeout, CancellationToken ct) =>
		Task.FromResult(new ExternalCommandResult(tool.ToString(), "cmd.exe", 0, string.Empty, string.Empty, false, TimeSpan.Zero, true));

	public Task<ExternalCommandResult> RunDirectAsync(
		string commandLabel, string executable, IReadOnlyList<string> arguments, TimeSpan timeout, CancellationToken ct)
	{
		// Capture the -Command script (the last argument the provider passes to powershell.exe).
		LastScript = arguments.Count > 0 ? arguments[^1] : string.Empty;
		string stdOut = ExitCode == 0 ? "RdpAudit-Block-203.0.113.10" : string.Empty;
		return Task.FromResult(new ExternalCommandResult(
			commandLabel, executable, ExitCode, stdOut, StdErr, false, TimeSpan.FromMilliseconds(1), false));
	}
}

internal sealed class FakeFirewallRuleScanner : IFirewallRuleScanner
{
	public int Calls { get; private set; }

	public string? LastPrefix { get; private set; }

	public FirewallScanResult Result { get; set; } = new(
		Scannable: true,
		Rules: Array.Empty<DiscoveredBlockRule>(),
		Note: "test",
		Backend: FirewallScanBackend.PowerShellJson);

	public Task<FirewallScanResult> ScanRdpAuditBlockRulesAsync(string ruleNamePrefix, CancellationToken ct)
	{
		Calls++;
		LastPrefix = ruleNamePrefix;
		return Task.FromResult(Result);
	}
}

internal sealed class FakeRdpPortProvider : IRdpPortProvider
{
	private readonly int _port;

	public FakeRdpPortProvider(int port = 3389)
	{
		_port = port;
	}

	public int GetRdpPort() => _port;
}

internal sealed class StaticOptionsMonitor<T> : IOptionsMonitor<T>
{
	public StaticOptionsMonitor(T value)
	{
		CurrentValue = value;
	}

	public T CurrentValue { get; }

	public T Get(string? name) => CurrentValue;

	public IDisposable? OnChange(Action<T, string?> listener) => null;
}
