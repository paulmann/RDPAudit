// File:    tests/RdpAudit.Service.Tests/PowerShellFirewallScannerLatchTests.cs
// Module:  RdpAudit.Service.Tests
// Purpose: Locks the v2.1.0 PowerShell live-firewall scan latch contract: the first failed or
//          timed-out PowerShell probe latches the scanner onto the netsh text fallback, every scan
//          while latched is served WITHOUT spawning PowerShell, PowerShell is re-probed at most once
//          per the configured retry interval, a successful re-probe releases the latch, and the
//          current backend plus the latch switch count are published through the injected metrics
//          sink (the IPC GetStatus surface). The pure latch state machine is exercised directly,
//          then the full scanner orchestration runs through the public ScanRdpAuditBlockRulesAsync
//          with scripted runner / netsh / time fakes so the suite stays host-independent.
// Extends: Keep JSON fixtures in lock-step with PowerShellFirewallRuleParserTests.
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Moq;
using RdpAudit.Core.Config;
using RdpAudit.Core.Firewall;
using RdpAudit.Core.Util;
using RdpAudit.Service;
using RdpAudit.Service.Firewall;
using Xunit;

namespace RdpAudit.Service.Tests;

public class PowerShellFirewallScannerLatchTests
{
	private const string Prefix = "RdpAudit-Block";

	private const string OneRuleJson =
		"""
		{"Name":"RdpAudit-Block-1.2.3.4","Group":"RdpAudit","DisplayGroup":"RdpAudit",
		"Direction":"Inbound","Action":"Block","Enabled":"True","Protocol":"Any",
		"LocalPort":"Any","RemoteAddress":"1.2.3.4/32"}
		""";

	private const string UngroupedNamePrefixRuleJson =
		"""
		{"Name":"RdpAudit-Block-5.5.5.5","Group":null,"DisplayGroup":null,
		"Direction":"Inbound","Action":"Block","Enabled":"True","Protocol":"Any",
		"LocalPort":"Any","RemoteAddress":"5.5.5.5/32"}
		""";

	private static readonly DateTimeOffset T0 = new(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);

	// ── Latch state machine ─────────────────────────────────────────────────────

	[Fact]
	public void Latch_InitiallyReleased_ReturnsProbe()
	{
		FakeTimeProvider time = new(T0);
		PowerShellProbeLatch latch = new(time);

		Assert.False(latch.Latched);
		Assert.Null(latch.NextProbeAt);
		Assert.Equal(PowerShellProbeAction.Probe, latch.DecidePowerShellProbe(TimeSpan.FromMinutes(15)));
	}

	[Fact]
	public void Latch_AfterFailure_RequiresRetryIntervalBeforeReprobe()
	{
		FakeTimeProvider time = new(T0);
		PowerShellProbeLatch latch = new(time);

		latch.OnProbeFailure(TimeSpan.FromMinutes(15));

		Assert.True(latch.Latched);
		Assert.Equal(T0 + TimeSpan.FromMinutes(15), latch.NextProbeAt!.Value);
		Assert.Equal(PowerShellProbeAction.UseFallback, latch.DecidePowerShellProbe(TimeSpan.FromMinutes(15)));
	}

	[Fact]
	public void Latch_AfterIntervalElapsed_ExactlyOneCallerClaimsReprobeSlot()
	{
		FakeTimeProvider time = new(T0);
		PowerShellProbeLatch latch = new(time);
		latch.OnProbeFailure(TimeSpan.FromMinutes(15));
		time.Advance(TimeSpan.FromMinutes(15) + TimeSpan.FromSeconds(1));

		PowerShellProbeAction first = latch.DecidePowerShellProbe(TimeSpan.FromMinutes(15));
		PowerShellProbeAction second = latch.DecidePowerShellProbe(TimeSpan.FromMinutes(15));

		Assert.Equal(PowerShellProbeAction.ProbeAfterLatch, first);
		Assert.Equal(PowerShellProbeAction.UseFallback, second);
		Assert.True(latch.Latched);
		Assert.Equal(T0 + TimeSpan.FromMinutes(30) + TimeSpan.FromSeconds(1), latch.NextProbeAt!.Value);
	}

	[Fact]
	public void Latch_SuccessfulReprobe_ReleasesLatch()
	{
		FakeTimeProvider time = new(T0);
		PowerShellProbeLatch latch = new(time);
		latch.OnProbeFailure(TimeSpan.FromMinutes(15));

		latch.OnProbeSuccess();

		Assert.False(latch.Latched);
		Assert.Null(latch.NextProbeAt);
		Assert.Equal(PowerShellProbeAction.Probe, latch.DecidePowerShellProbe(TimeSpan.FromMinutes(15)));
	}

	[Fact]
	public void Latch_FailureWhileLatched_RearmsDeadlineFromNow()
	{
		FakeTimeProvider time = new(T0);
		PowerShellProbeLatch latch = new(time);
		latch.OnProbeFailure(TimeSpan.FromMinutes(15));
		time.Advance(TimeSpan.FromMinutes(20));

		latch.OnProbeFailure(TimeSpan.FromMinutes(15));

		Assert.True(latch.Latched);
		Assert.Equal(T0 + TimeSpan.FromMinutes(35), latch.NextProbeAt!.Value);
	}

	[Fact]
	public void Latch_ZeroInterval_IsSanitized_NotLatchedIntoHotLoop()
	{
		FakeTimeProvider time = new(T0);
		PowerShellProbeLatch latch = new(time);
		latch.OnProbeFailure(TimeSpan.Zero);

		Assert.True(latch.Latched);
		Assert.Equal(PowerShellProbeAction.UseFallback, latch.DecidePowerShellProbe(TimeSpan.Zero));
		Assert.NotNull(latch.NextProbeAt);
		Assert.True(latch.NextProbeAt!.Value > T0);
	}

	// ── Scanner orchestration ───────────────────────────────────────────────────

	[Fact]
	public async Task HappyPath_PowerShellSuccess_NoFallback_LatchStaysReleased()
	{
		BuildContext ctx = Build();

		FirewallScanResult result = await ctx.Scanner.ScanRdpAuditBlockRulesAsync(Prefix, CancellationToken.None);

		Assert.True(result.Scannable);
		Assert.Equal(FirewallScanBackend.PowerShellJson, result.Backend);
		DiscoveredBlockRule rule = Assert.Single(result.Rules);
		Assert.Contains("1.2.3.4", rule.RemoteIps);
		Assert.Single(ctx.Runner.DirectInvocations);
		Assert.Equal(0, ctx.Netsh.Calls);
		Assert.False(ctx.Latch.Latched);
		Assert.Equal(new FirewallScanBackend?[] { FirewallScanBackend.PowerShellJson }, ctx.Reported);
	}

	[Fact]
	public async Task FirstFailure_Latches_AndServesNetsh()
	{
		BuildContext ctx = Build();
		ctx.Runner.Enqueue(FailedResult);

		FirewallScanResult result = await ctx.Scanner.ScanRdpAuditBlockRulesAsync(Prefix, CancellationToken.None);

		Assert.Equal(FirewallScanBackend.NetshText, result.Backend);
		Assert.Single(ctx.Runner.DirectInvocations);
		Assert.Equal(1, ctx.Netsh.Calls);
		Assert.True(ctx.Latch.Latched);
		Assert.Contains("PowerShell scan failed or timed out", result.Note);
		Assert.Equal(new FirewallScanBackend?[] { FirewallScanBackend.NetshText }, ctx.Reported);
	}

	[Fact]
	public async Task WhileLatched_ScansServeNetsh_WithoutSpawningPowerShell()
	{
		BuildContext ctx = Build();
		ctx.Runner.Enqueue(FailedResult);
		await ctx.Scanner.ScanRdpAuditBlockRulesAsync(Prefix, CancellationToken.None);

		FirewallScanResult second = await ctx.Scanner.ScanRdpAuditBlockRulesAsync(Prefix, CancellationToken.None);

		Assert.Equal(FirewallScanBackend.NetshText, second.Backend);
		Assert.Single(ctx.Runner.DirectInvocations);
		Assert.Equal(2, ctx.Netsh.Calls);
		Assert.True(ctx.Latch.Latched);
	}

	[Fact]
	public async Task RetryIntervalElapsed_ReprobesPowerShell_AndRecovers()
	{
		BuildContext ctx = Build();
		ctx.Runner.Enqueue(FailedResult);
		await ctx.Scanner.ScanRdpAuditBlockRulesAsync(Prefix, CancellationToken.None);

		ctx.Time.Advance(TimeSpan.FromMinutes(16));
		ctx.Runner.Enqueue(SuccessResult);
		FirewallScanResult recovered = await ctx.Scanner.ScanRdpAuditBlockRulesAsync(Prefix, CancellationToken.None);

		Assert.Equal(FirewallScanBackend.PowerShellJson, recovered.Backend);
		Assert.Equal(2, ctx.Runner.DirectInvocations.Count);
		Assert.Equal(1, ctx.Netsh.Calls);
		Assert.False(ctx.Latch.Latched);

		// The scan AFTER recovery probes PowerShell again (normal path, no fallback).
		FirewallScanResult next = await ctx.Scanner.ScanRdpAuditBlockRulesAsync(Prefix, CancellationToken.None);
		Assert.Equal(FirewallScanBackend.PowerShellJson, next.Backend);
		Assert.Equal(3, ctx.Runner.DirectInvocations.Count);
		Assert.Equal(1, ctx.Netsh.Calls);
	}

	[Fact]
	public async Task RetryIntervalElapsed_ReprobeFailsAgain_LatchRearms_AndNetshServes()
	{
		BuildContext ctx = Build();
		ctx.Runner.Enqueue(FailedResult);
		await ctx.Scanner.ScanRdpAuditBlockRulesAsync(Prefix, CancellationToken.None);

		ctx.Time.Advance(TimeSpan.FromMinutes(16));
		ctx.Runner.Enqueue(FailedResult);
		FirewallScanResult reprobe = await ctx.Scanner.ScanRdpAuditBlockRulesAsync(Prefix, CancellationToken.None);

		Assert.Equal(FirewallScanBackend.NetshText, reprobe.Backend);
		Assert.True(ctx.Latch.Latched);
		Assert.Equal(2, ctx.Runner.DirectInvocations.Count);
		Assert.Equal(2, ctx.Netsh.Calls);

		// Still inside the freshly re-armed interval: netsh only, no third PowerShell spawn.
		FirewallScanResult third = await ctx.Scanner.ScanRdpAuditBlockRulesAsync(Prefix, CancellationToken.None);
		Assert.Equal(FirewallScanBackend.NetshText, third.Backend);
		Assert.Equal(2, ctx.Runner.DirectInvocations.Count);
		Assert.Equal(3, ctx.Netsh.Calls);
	}

	[Fact]
	public async Task TimeoutTreatedAsProbeFailure_Latches()
	{
		BuildContext ctx = Build();
		ctx.Runner.Enqueue(TimedOutResult);

		FirewallScanResult result = await ctx.Scanner.ScanRdpAuditBlockRulesAsync(Prefix, CancellationToken.None);

		Assert.Equal(FirewallScanBackend.NetshText, result.Backend);
		Assert.True(ctx.Latch.Latched);
		Assert.Equal(1, ctx.Netsh.Calls);
	}

	[Fact]
	public async Task RunnerExceptionTreatedAsProbeFailure_Latches()
	{
		BuildContext ctx = Build();
		ctx.Runner.ThrowOnEveryDirect = true;

		FirewallScanResult result = await ctx.Scanner.ScanRdpAuditBlockRulesAsync(Prefix, CancellationToken.None);

		Assert.Equal(FirewallScanBackend.NetshText, result.Backend);
		Assert.True(ctx.Latch.Latched);
		Assert.Equal(1, ctx.Netsh.Calls);
	}

	[Fact]
	public async Task ConfigTimeoutAndRetryInterval_AreReadFromOptionsMonitor()
	{
		BuildContext ctx = Build(new FirewallOptions
		{
			PowerShellScanTimeoutSeconds = 11,
			PowerShellRetryProbeIntervalMinutes = 7,
		});

		FirewallScanResult success = await ctx.Scanner.ScanRdpAuditBlockRulesAsync(Prefix, CancellationToken.None);
		Assert.Equal(FirewallScanBackend.PowerShellJson, success.Backend);
		Assert.Equal(TimeSpan.FromSeconds(11), ctx.Runner.DirectInvocations[0].Timeout);

		ctx.Runner.Enqueue(FailedResult);
		await ctx.Scanner.ScanRdpAuditBlockRulesAsync(Prefix, CancellationToken.None);
		Assert.Equal(TimeSpan.FromMinutes(7), ctx.Latch.NextProbeAt!.Value - ctx.Time.GetUtcNow());
	}

	[Fact]
	public async Task ConfigValuesBelowOne_FallBackToDefaults()
	{
		BuildContext ctx = Build(new FirewallOptions
		{
			PowerShellScanTimeoutSeconds = 0,
			PowerShellRetryProbeIntervalMinutes = -5,
		});

		FirewallScanResult success = await ctx.Scanner.ScanRdpAuditBlockRulesAsync(Prefix, CancellationToken.None);
		Assert.Equal(FirewallScanBackend.PowerShellJson, success.Backend);
		Assert.Equal(TimeSpan.FromSeconds(30), ctx.Runner.DirectInvocations[0].Timeout);

		ctx.Runner.Enqueue(FailedResult);
		await ctx.Scanner.ScanRdpAuditBlockRulesAsync(Prefix, CancellationToken.None);
		Assert.Equal(TimeSpan.FromMinutes(15), ctx.Latch.NextProbeAt!.Value - ctx.Time.GetUtcNow());
	}

	[Fact]
	public async Task NamePrefixFallback_StillDiscoversUngroupedRules_WithTwoProbeCalls()
	{
		BuildContext ctx = Build();
		ctx.Runner.Enqueue(() => ScriptedRunner.Success("[]"));
		ctx.Runner.Enqueue(() => ScriptedRunner.Success(UngroupedNamePrefixRuleJson));

		FirewallScanResult result = await ctx.Scanner.ScanRdpAuditBlockRulesAsync(Prefix, CancellationToken.None);

		Assert.Equal(FirewallScanBackend.PowerShellJson, result.Backend);
		DiscoveredBlockRule rule = Assert.Single(result.Rules);
		Assert.Contains("5.5.5.5", rule.RemoteIps);
		Assert.Equal(2, ctx.Runner.DirectInvocations.Count);
		Assert.False(ctx.Latch.Latched);
	}

	// ── Metrics sink semantics ───────────────────────────────────────────────────

	[Fact]
	public void ServiceMetrics_RecordFirewallScanBackend_CountsOnlyFallbackLatches()
	{
		ServiceMetrics metrics = new();

		Assert.Equal(0L, metrics.FirewallScanSwitchCount);
		Assert.Null(metrics.FirewallScanBackend);

		metrics.RecordFirewallScanBackend(FirewallScanBackend.PowerShellJson);
		Assert.Equal(0L, metrics.FirewallScanSwitchCount);
		Assert.Equal("PowerShellJson", metrics.FirewallScanBackend);

		// Fallback ENTERED: counts once.
		metrics.RecordFirewallScanBackend(FirewallScanBackend.NetshText);
		Assert.Equal(1L, metrics.FirewallScanSwitchCount);

		// Repeated netsh scans while latched: no additional count.
		metrics.RecordFirewallScanBackend(FirewallScanBackend.NetshText);
		Assert.Equal(1L, metrics.FirewallScanSwitchCount);

		// Recovery back to PowerShell: no count (recovery is not a latch event).
		metrics.RecordFirewallScanBackend(FirewallScanBackend.PowerShellJson);
		Assert.Equal(1L, metrics.FirewallScanSwitchCount);

		// A second failure latches again: second count.
		metrics.RecordFirewallScanBackend(FirewallScanBackend.NetshText);
		Assert.Equal(2L, metrics.FirewallScanSwitchCount);
		Assert.Equal("NetshText", metrics.FirewallScanBackend);
	}

	[Fact]
	public async Task EndToEnd_ScannerFeedsServiceMetricsSink_BackendAndSwitchCount()
	{
		ServiceMetrics metrics = new();
		BuildContext ctx = Build(reportBackend: metrics.RecordFirewallScanBackend);

		await ctx.Scanner.ScanRdpAuditBlockRulesAsync(Prefix, CancellationToken.None);
		Assert.Equal("PowerShellJson", metrics.FirewallScanBackend);
		Assert.Equal(0L, metrics.FirewallScanSwitchCount);

		ctx.Runner.Enqueue(FailedResult);
		await ctx.Scanner.ScanRdpAuditBlockRulesAsync(Prefix, CancellationToken.None);
		Assert.Equal("NetshText", metrics.FirewallScanBackend);
		Assert.Equal(1L, metrics.FirewallScanSwitchCount);

		// Latched scan: netsh only - the runner queue stays empty so the upcoming re-probe wins.
		await ctx.Scanner.ScanRdpAuditBlockRulesAsync(Prefix, CancellationToken.None);
		Assert.Equal("NetshText", metrics.FirewallScanBackend);
		Assert.Equal(1L, metrics.FirewallScanSwitchCount);

		ctx.Time.Advance(TimeSpan.FromMinutes(16));
		await ctx.Scanner.ScanRdpAuditBlockRulesAsync(Prefix, CancellationToken.None);
		Assert.Equal("PowerShellJson", metrics.FirewallScanBackend);
		Assert.Equal(1L, metrics.FirewallScanSwitchCount);
	}

	// ── Fixture helpers ─────────────────────────────────────────────────────────

	private static BuildContext Build(
		FirewallOptions? firewall = null,
		Action<FirewallScanBackend?>? reportBackend = null)
	{
		FakeTimeProvider time = new(T0);
		ScriptedRunner runner = new();
		FakeNetshScanner netsh = new();
		List<FirewallScanBackend?> reported = new();
		Action<FirewallScanBackend?> sink = reportBackend ?? (b => reported.Add(b));

		RdpAuditOptions options = new() { Firewall = firewall ?? new FirewallOptions() };
		Mock<IOptionsMonitor<RdpAuditOptions>> monitor = new();
		monitor.SetupGet(m => m.CurrentValue).Returns(options);

		PowerShellProbeLatch latch = new(time);
		PowerShellFirewallRuleScanner scanner = new(
			NullLogger<PowerShellFirewallRuleScanner>.Instance,
			runner,
			netsh,
			monitor.Object,
			latch,
			time,
			sink,
			isWindows: () => true);

		return new BuildContext(scanner, runner, netsh, reported, time, latch);
	}

	private static ExternalCommandResult SuccessResult() => ScriptedRunner.Success(OneRuleJson);

	private static ExternalCommandResult FailedResult() => new(
		"powershell Get-NetFirewallRule -Group RdpAudit (JSON)",
		"powershell.exe",
		ExitCode: 1,
		StdOut: string.Empty,
		StdErr: "scripted failure",
		TimedOut: false,
		Duration: TimeSpan.FromMilliseconds(30),
		EnglishConsoleMode: false);

	private static ExternalCommandResult TimedOutResult() => new(
		"powershell Get-NetFirewallRule -Group RdpAudit (JSON)",
		"powershell.exe",
		ExitCode: -1,
		StdOut: string.Empty,
		StdErr: string.Empty,
		TimedOut: true,
		Duration: TimeSpan.FromSeconds(30),
		EnglishConsoleMode: false);

	private sealed record BuildContext(
		PowerShellFirewallRuleScanner Scanner,
		ScriptedRunner Runner,
		FakeNetshScanner Netsh,
		List<FirewallScanBackend?> Reported,
		FakeTimeProvider Time,
		PowerShellProbeLatch Latch);

	private sealed class FakeTimeProvider : TimeProvider
	{
		private DateTimeOffset _now;

		public FakeTimeProvider(DateTimeOffset now)
		{
			_now = now;
		}

		public override DateTimeOffset GetUtcNow() => _now;

		public void Advance(TimeSpan delta) => _now = _now.Add(delta);
	}

	private sealed class ScriptedRunner : IExternalCommandRunner
	{
		private readonly Queue<Func<ExternalCommandResult>> _directScript = new();

		public List<RecordedInvocation> DirectInvocations { get; } = new();

		public bool ThrowOnEveryDirect { get; set; }

		public void Enqueue(Func<ExternalCommandResult> factory) => _directScript.Enqueue(factory);

		public Task<ExternalCommandResult> RunDirectAsync(
			string commandLabel,
			string executable,
			IReadOnlyList<string> arguments,
			TimeSpan timeout,
			CancellationToken ct)
		{
			DirectInvocations.Add(new RecordedInvocation(commandLabel, executable, arguments.ToArray(), timeout));
			if (ThrowOnEveryDirect)
			{
				throw new InvalidOperationException("scripted PowerShell probe failure");
			}

			ExternalCommandResult result = _directScript.Count > 0 ? _directScript.Dequeue().Invoke() : Success(OneRuleJson);
			return Task.FromResult(result);
		}

		public Task<ExternalCommandResult> RunEnglishConsoleAsync(
			TrustedEnglishConsoleTool tool,
			EnglishConsoleArgs? args,
			TimeSpan timeout,
			CancellationToken ct) =>
			Task.FromResult(Success(string.Empty));

		internal static ExternalCommandResult Success(string stdout) => new(
			"powershell Get-NetFirewallRule -Group RdpAudit (JSON)",
			"powershell.exe",
			ExitCode: 0,
			StdOut: stdout,
			StdErr: string.Empty,
			TimedOut: false,
			Duration: TimeSpan.FromMilliseconds(120),
			EnglishConsoleMode: false);

		public sealed record RecordedInvocation(
			string Label,
			string Executable,
			string[] Arguments,
			TimeSpan Timeout);
	}

	private sealed class FakeNetshScanner : IFirewallRuleScanner
	{
		public int Calls { get; private set; }

		public Task<FirewallScanResult> ScanRdpAuditBlockRulesAsync(string ruleNamePrefix, CancellationToken ct)
		{
			Calls++;
			return Task.FromResult(new FirewallScanResult(
				Scannable: true,
				Rules: Array.Empty<DiscoveredBlockRule>(),
				Note: "Enumerated via netsh verbose text parse (fake).",
				Backend: FirewallScanBackend.NetshText));
		}
	}
}
