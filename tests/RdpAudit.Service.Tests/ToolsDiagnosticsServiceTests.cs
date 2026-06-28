// File:    tests/RdpAudit.Service.Tests/ToolsDiagnosticsServiceTests.cs
// Module:  RdpAudit.Service.Tests
// Purpose: Exercises ToolsDiagnosticsService with fake runner / firewall provider implementations so
//          the read-only probe set and the temporary-firewall-rule create / verify / cleanup
//          orchestration are testable on Linux CI without spawning a Windows command. Pins the
//          stdout-on-empty-stderr capture, the per-step backend command detail, and the overall
//          create+verify+cleanup verdict.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using Microsoft.Extensions.Logging.Abstractions;
using RdpAudit.Core.Firewall;
using RdpAudit.Core.Ipc.Contracts;
using RdpAudit.Core.Util;
using RdpAudit.Service.Firewall;
using RdpAudit.Service.Services;
using Xunit;

namespace RdpAudit.Service.Tests;

public class ToolsDiagnosticsServiceTests
{
	[Fact]
	public async Task TemporaryProbe_HappyPath_CreatesVerifiesAndCleansUp()
	{
		FakeFirewallProvider provider = new();
		ToolsDiagnosticsService service = Build(provider);

		TemporaryFirewallProbeDto dto = await service.ExecuteTemporaryProbeAsync(
			"203.0.113.10", DateTime.UtcNow, CancellationToken.None);

		Assert.Equal(IpcResultStatus.Success, dto.Status);
		Assert.True(dto.CreatedVerifiedAndCleanedUp);
		// v1.3.9 — four explicit stages: create, targeted verify-present, cleanup, cleanup-verify-removed.
		Assert.Equal(4, dto.Steps.Count);
		Assert.True(dto.Steps[0].Passed); // create
		Assert.True(dto.Steps[1].Passed); // verify present
		Assert.True(dto.Steps[2].Passed); // cleanup
		Assert.True(dto.Steps[3].Passed); // cleanup verify (rule removed)
		Assert.Equal("create temporary block rule", dto.Steps[0].ToolName);
		Assert.Equal("verify temporary block rule present", dto.Steps[1].ToolName);
		Assert.Equal("clean up temporary block rule", dto.Steps[2].ToolName);
		Assert.Equal("verify temporary block rule removed", dto.Steps[3].ToolName);
		Assert.Equal("NetshText", dto.ScannerBackend);
		Assert.Contains("203.0.113.10", dto.RuleName, StringComparison.Ordinal);
		Assert.Contains("203.0.113.10", dto.ReportText, StringComparison.Ordinal);
	}

	[Fact]
	public async Task TemporaryProbe_CreateFailsWithEmptyStderr_CapturesStdoutAndStillCleansUp()
	{
		FakeFirewallProvider provider = new()
		{
			BlockResult = new FirewallActionResult
			{
				Status = FirewallActionStatus.Unavailable,
				ProviderId = "Windows",
				RuleId = "RdpAudit-ToolsDiag-TempProbe-203.0.113.10",
				RuleHandle = "RdpAudit-ToolsDiag-TempProbe-203.0.113.10",
				VerifierReason = "netsh add rule exited non-zero before verification.",
				// exit=1 with EMPTY stderr — the only failure signal is in stdout.
				BackendAttempt = new BackendCommandAttempt(
					"netsh add rule", "netsh.exe", "add rule",
					BackendRunnerMode.Direct, 1, false, 8, "The parameter is incorrect.", string.Empty, "NetshText"),
				Message = "netsh add rule returned exit=1. The parameter is incorrect.",
			},
		};
		ToolsDiagnosticsService service = Build(provider);

		TemporaryFirewallProbeDto dto = await service.ExecuteTemporaryProbeAsync(
			"203.0.113.10", DateTime.UtcNow, CancellationToken.None);

		Assert.False(dto.CreatedVerifiedAndCleanedUp);
		ToolProbeResultDto createStep = dto.Steps[0];
		Assert.False(createStep.Passed);
		Assert.Equal(1, createStep.ExitCode);
		// stdout-on-empty-stderr: failure text survives into the step preview.
		Assert.Contains("parameter is incorrect", createStep.StdoutPreview, StringComparison.Ordinal);
		// Verification is skipped on a failed create, but cleanup is always attempted.
		Assert.True(provider.UnblockCalled);
		Assert.Contains(dto.Steps, s => s.ToolName == "clean up temporary block rule");
	}

	[Fact]
	public async Task TemporaryProbe_CreatedButNotVerified_ReportsVerifyFailureAndCleansUp()
	{
		FakeFirewallProvider provider = new()
		{
			BlockResult = new FirewallActionResult
			{
				Status = FirewallActionStatus.Success,
				ProviderId = "Windows",
				RuleId = "RdpAudit-ToolsDiag-TempProbe-203.0.113.10",
				RuleHandle = "RdpAudit-ToolsDiag-TempProbe-203.0.113.10",
				BackendAttempt = new BackendCommandAttempt(
					"netsh add rule", "netsh.exe", "add rule",
					BackendRunnerMode.Direct, 0, false, 7, "Ok.", string.Empty, "NetshText"),
			},
			ListResult = Array.Empty<FirewallBlockEntry>(), // verification finds nothing
		};
		ToolsDiagnosticsService service = Build(provider);

		TemporaryFirewallProbeDto dto = await service.ExecuteTemporaryProbeAsync(
			"203.0.113.10", DateTime.UtcNow, CancellationToken.None);

		Assert.False(dto.CreatedVerifiedAndCleanedUp);
		ToolProbeResultDto verifyStep = dto.Steps[1];
		Assert.Equal("verify temporary block rule present", verifyStep.ToolName);
		Assert.False(verifyStep.Passed);
		Assert.True(provider.UnblockCalled);
	}

	[Fact]
	public async Task TemporaryProbe_CleanupLeavesRuleBehind_CleanupVerifyFails()
	{
		// ListResult is forced non-empty for EVERY list call, so the rule appears present both at
		// verify-present (passes) and after cleanup at verify-removed (fails — a stray rule lingers).
		FakeFirewallProvider provider = new()
		{
			ListResult = new[]
			{
				new FirewallBlockEntry
				{
					RuleId = NetshCommandBuilder.BuildRuleName("RdpAudit-ToolsDiag-TempProbe", "203.0.113.10"),
					Ip = "203.0.113.10",
					ProviderId = "Windows",
				},
			},
		};
		ToolsDiagnosticsService service = Build(provider);

		TemporaryFirewallProbeDto dto = await service.ExecuteTemporaryProbeAsync(
			"203.0.113.10", DateTime.UtcNow, CancellationToken.None);

		Assert.Equal(4, dto.Steps.Count);
		ToolProbeResultDto cleanupVerify = dto.Steps[3];
		Assert.Equal("verify temporary block rule removed", cleanupVerify.ToolName);
		Assert.False(cleanupVerify.Passed);
		Assert.Contains("STILL PRESENT", cleanupVerify.StdoutPreview, StringComparison.Ordinal);
		// Overall verdict must be false because the cleanup-verify stage did not confirm removal.
		Assert.False(dto.CreatedVerifiedAndCleanedUp);
	}

	[Fact]
	public async Task TemporaryProbe_VerificationTimesOut_IsInconclusiveNotProofOfAbsence()
	{
		// The list query throws a timeout during verification. This must produce a non-fatal,
		// TimedOut-aware step ("inconclusive") rather than being treated as proof the rule is absent.
		FakeFirewallProvider provider = new()
		{
			ListThrows = new TimeoutException("provider scan exceeded the budget"),
		};
		ToolsDiagnosticsService service = Build(provider);

		TemporaryFirewallProbeDto dto = await service.ExecuteTemporaryProbeAsync(
			"203.0.113.10", DateTime.UtcNow, CancellationToken.None);

		ToolProbeResultDto verifyStep = dto.Steps[1];
		Assert.Equal("verify temporary block rule present", verifyStep.ToolName);
		Assert.False(verifyStep.Passed);
		Assert.True(verifyStep.TimedOut);
		Assert.NotNull(verifyStep.Note);
		Assert.Contains("inconclusive", verifyStep.Note!, StringComparison.OrdinalIgnoreCase);
		Assert.False(dto.CreatedVerifiedAndCleanedUp);
	}

	[Fact]
	public async Task TemporaryProbe_InvalidIp_RefusedWithoutTouchingProvider()
	{
		FakeFirewallProvider provider = new();
		ToolsDiagnosticsService service = Build(provider);

		TemporaryFirewallProbeDto dto = await service.RunTemporaryFirewallRuleProbeAsync(
			"not-an-ip", CancellationToken.None);

		Assert.Equal(IpcResultStatus.InvalidRequest, dto.Status);
		Assert.False(provider.BlockCalled);
		Assert.False(provider.UnblockCalled);
	}

	[Fact]
	public async Task RunDiagnostics_OnNonWindows_SkipsWindowsProbesButStillReportsPortRead()
	{
		// On Linux CI this path is the real one; on Windows it would run live probes. Either way the
		// service must return a probe set and a non-empty transcript.
		FakeFirewallProvider provider = new();
		ToolsDiagnosticsService service = Build(provider, new FixedRdpPortProvider(3389));

		ToolsDiagnosticsDto dto = await service.RunDiagnosticsAsync(CancellationToken.None);

		Assert.Equal(IpcResultStatus.Success, dto.Status);
		Assert.NotEmpty(dto.Probes);
		Assert.False(string.IsNullOrWhiteSpace(dto.ReportText));
		Assert.Contains(dto.Probes, p => p.ToolName == "RDP listener port read");
	}

	private static ToolsDiagnosticsService Build(IFirewallProvider provider, IRdpPortProvider? port = null) =>
		new(
			NullLogger<ToolsDiagnosticsService>.Instance,
			new FakeRunner(),
			provider,
			port);

	private sealed class FixedRdpPortProvider : IRdpPortProvider
	{
		private readonly int _port;

		public FixedRdpPortProvider(int port) => _port = port;

		public int GetRdpPort() => _port;
	}

	private sealed class FakeRunner : IExternalCommandRunner
	{
		public Task<ExternalCommandResult> RunEnglishConsoleAsync(
			TrustedEnglishConsoleTool tool, EnglishConsoleArgs? args, TimeSpan timeout, CancellationToken ct) =>
			Task.FromResult(Ok(tool.ToString()));

		public Task<ExternalCommandResult> RunDirectAsync(
			string commandLabel, string executable, IReadOnlyList<string> arguments, TimeSpan timeout, CancellationToken ct) =>
			Task.FromResult(Ok(commandLabel));

		private static ExternalCommandResult Ok(string label) =>
			new(label, "fake.exe", 0, "ok", string.Empty, false, TimeSpan.FromMilliseconds(1), false);
	}

	private sealed class FakeFirewallProvider : IFirewallProvider
	{
		public bool BlockCalled { get; private set; }
		public bool UnblockCalled { get; private set; }

		public FirewallActionResult BlockResult { get; set; } = new()
		{
			Status = FirewallActionStatus.Success,
			ProviderId = "Windows",
			RuleId = "RdpAudit-ToolsDiag-TempProbe-203.0.113.10",
			RuleHandle = "RdpAudit-ToolsDiag-TempProbe-203.0.113.10",
			BackendAttempt = new BackendCommandAttempt(
				"netsh add rule", "netsh.exe", "add rule",
				BackendRunnerMode.Direct, 0, false, 9, "Ok.", string.Empty, "NetshText"),
			VerifierReason = "Enabled inbound block rule confirmed in the firewall store.",
		};

		/// <summary>When set, every <see cref="ListBlocksAsync"/> call returns this fixed result (used to
		/// force "verification finds nothing" or "rule still present after cleanup" scenarios). When null,
		/// the fake models a real provider: the temporary rule is reported present until
		/// <see cref="UnblockAsync"/> runs, then absent — so the create→verify→cleanup→cleanup-verify
		/// happy path resolves correctly.</summary>
		public IReadOnlyList<FirewallBlockEntry>? ListResult { get; set; }

		/// <summary>When set, <see cref="ListBlocksAsync"/> throws this exception, simulating a provider /
		/// scan timeout or transient failure during (cleanup-)verification.</summary>
		public Exception? ListThrows { get; set; }

		public string ProviderId => "Windows";

		public Task<FirewallStatusReport> GetStatusAsync(CancellationToken ct) =>
			Task.FromResult(new FirewallStatusReport { Status = FirewallProviderStatus.Available, ProviderId = ProviderId });

		public Task<FirewallActionResult> BlockAsync(FirewallBlockRequest request, CancellationToken ct)
		{
			BlockCalled = true;
			return Task.FromResult(BlockResult);
		}

		public Task<FirewallActionResult> UnblockAsync(string ip, string ruleName, CancellationToken ct)
		{
			UnblockCalled = true;
			return Task.FromResult(new FirewallActionResult
			{
				Status = FirewallActionStatus.Success,
				ProviderId = ProviderId,
				RuleId = NetshCommandBuilder.BuildRuleName(ruleName, ip),
				BackendAttempt = new BackendCommandAttempt(
					"netsh delete rule", "netsh.exe", "delete rule",
					BackendRunnerMode.Direct, 0, false, 4, "Deleted 1 rule(s).", string.Empty, "NetshText"),
				Message = "Block rule removed.",
			});
		}

		public Task<IReadOnlyList<FirewallBlockEntry>> ListBlocksAsync(string ruleName, CancellationToken ct)
		{
			if (ListThrows is { } ex)
			{
				throw ex;
			}

			if (ListResult is { } forced)
			{
				return Task.FromResult(forced);
			}

			// Model a real store: the temporary rule is present until cleanup runs, then gone.
			IReadOnlyList<FirewallBlockEntry> result = UnblockCalled
				? Array.Empty<FirewallBlockEntry>()
				: new[]
				{
					new FirewallBlockEntry
					{
						RuleId = NetshCommandBuilder.BuildRuleName(ruleName, "203.0.113.10"),
						Ip = "203.0.113.10",
						ProviderId = ProviderId,
					},
				};
			return Task.FromResult(result);
		}
	}
}
