// File:    src/RdpAudit.Service/Services/ToolsDiagnosticsService.cs
// Module:  RdpAudit.Service.Services
// Purpose: Orchestrates the read-only "Tools Diag" probe set and the explicit temporary-firewall-rule
//          probe for the Configurator's Tools Diag tab. Every external command is spawned through the
//          centralized IExternalCommandRunner — the parse-stable English console (chcp 437) for the
//          whitelisted parsed-stdout tools (qwinsta / quser / netsh show rule / show allprofiles) and
//          the direct argument-vector runner for command resolution (where.exe) and the PowerShell
//          Get-NetFirewallRule JSON probe. Each result is projected onto a ToolProbeResultDto carrying
//          full runner metadata (executable, arguments, runner mode, exit code, duration, timed-out
//          flag, bounded stdout / stderr previews, locale hint, pass/fail). The temporary probe reuses
//          the Windows firewall provider to create / verify / clean up a single rule for a supplied test
//          IP, surfacing each step's exact backend command. Nothing here mutates firewall state on the
//          read-only path; the temporary probe always attempts cleanup even when verification fails.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System.Globalization;
using System.Net;
using System.Runtime.Versioning;
using Microsoft.Extensions.Logging;
using RdpAudit.Core.Firewall;
using RdpAudit.Core.Ipc.Contracts;
using RdpAudit.Core.Util;
using RdpAudit.Service.Firewall;

namespace RdpAudit.Service.Services;

/// <summary>Runs the read-only Tools Diag probe set and the explicit temporary-firewall-rule probe.</summary>
public sealed class ToolsDiagnosticsService
{
	/// <summary>Deterministic base rule name used for the temporary probe so cleanup is unambiguous.</summary>
	internal const string TemporaryProbeRuleBase = "RdpAudit-ToolsDiag-TempProbe";

	private static readonly TimeSpan ProbeTimeout = TimeSpan.FromSeconds(20);

	private readonly ILogger<ToolsDiagnosticsService> _logger;
	private readonly IExternalCommandRunner _runner;
	private readonly IFirewallProvider _windowsProvider;
	private readonly IRdpPortProvider? _portProvider;

	public ToolsDiagnosticsService(
		ILogger<ToolsDiagnosticsService> logger,
		WindowsFirewallProvider windowsProvider,
		IRdpPortProvider? portProvider = null)
		: this(logger, BuildDefaultRunner(), windowsProvider, portProvider)
	{
	}

	internal ToolsDiagnosticsService(
		ILogger<ToolsDiagnosticsService> logger,
		IExternalCommandRunner runner,
		IFirewallProvider windowsProvider,
		IRdpPortProvider? portProvider)
	{
		ArgumentNullException.ThrowIfNull(logger);
		ArgumentNullException.ThrowIfNull(runner);
		ArgumentNullException.ThrowIfNull(windowsProvider);
		_logger = logger;
		_runner = runner;
		_windowsProvider = windowsProvider;
		_portProvider = portProvider;
	}

	/// <summary>Runs the full read-only probe set and returns the per-probe metadata plus a copyable
	/// transcript. Never creates or deletes firewall rules.</summary>
	public async Task<ToolsDiagnosticsDto> RunDiagnosticsAsync(CancellationToken ct)
	{
		DateTime generatedUtc = DateTime.UtcNow;
		List<ToolProbeResultDto> probes = new();

		if (!OperatingSystem.IsWindows())
		{
			probes.Add(ToolProbeResultMapper.Skipped(
				"qwinsta", "qwinsta.exe", "Skipped on non-Windows host."));
			probes.Add(ToolProbeResultMapper.Skipped(
				"quser", "quser.exe", "Skipped on non-Windows host."));
			probes.Add(ToolProbeResultMapper.Skipped(
				"netsh advfirewall firewall show rule name=all verbose",
				"netsh.exe advfirewall firewall show rule name=all verbose",
				"Skipped on non-Windows host."));
			probes.Add(ToolProbeResultMapper.Skipped(
				"netsh advfirewall show allprofiles state",
				"netsh.exe advfirewall show allprofiles state",
				"Skipped on non-Windows host."));
			probes.Add(ToolProbeResultMapper.Skipped(
				"command resolution (where)", "where.exe", "Skipped on non-Windows host."));
			probes.Add(ToolProbeResultMapper.Skipped(
				"powershell Get-NetFirewallRule (JSON)", "powershell.exe", "Skipped on non-Windows host."));
			probes.Add(BuildRdpPortProbe());

			return BuildDto(generatedUtc, probes, "Tools Diag ran on a non-Windows host; Windows commands were skipped.");
		}

		probes.Add(await RunEnglishConsoleProbeAsync(
			TrustedEnglishConsoleTool.Qwinsta, "qwinsta", ct).ConfigureAwait(false));
		probes.Add(await RunEnglishConsoleProbeAsync(
			TrustedEnglishConsoleTool.Quser, "quser", ct).ConfigureAwait(false));
		probes.Add(await RunEnglishConsoleProbeAsync(
			TrustedEnglishConsoleTool.NetshShowAllRulesVerbose,
			"netsh advfirewall firewall show rule name=all verbose", ct).ConfigureAwait(false));
		probes.Add(await RunEnglishConsoleProbeAsync(
			TrustedEnglishConsoleTool.NetshShowAllProfilesState,
			"netsh advfirewall show allprofiles state", ct).ConfigureAwait(false));
		probes.Add(await RunCommandResolutionProbeAsync(ct).ConfigureAwait(false));
		probes.Add(await RunPowerShellFirewallProbeAsync(ct).ConfigureAwait(false));
		probes.Add(BuildRdpPortProbe());

		return BuildDto(generatedUtc, probes, null);
	}

	/// <summary>Runs the explicit, user-triggered temporary-firewall-rule probe: create a temporary block
	/// rule for the supplied test IP, verify it landed, then clean it up. Each step reports its exact
	/// backend command, exit code, stdout / stderr, rule name and runner backend.</summary>
	public async Task<TemporaryFirewallProbeDto> RunTemporaryFirewallRuleProbeAsync(string testIp, CancellationToken ct)
	{
		DateTime generatedUtc = DateTime.UtcNow;

		if (string.IsNullOrWhiteSpace(testIp) || !IPAddress.TryParse(testIp.Trim(), out IPAddress? parsed))
		{
			return new TemporaryFirewallProbeDto
			{
				Status = IpcResultStatus.InvalidRequest,
				GeneratedUtc = generatedUtc,
				TestIp = testIp ?? string.Empty,
				CreatedVerifiedAndCleanedUp = false,
				Message = "A valid test IP address is required for the temporary firewall rule probe.",
				ReportText = "Temporary firewall rule probe refused: the supplied test IP is not a valid IP address.",
			};
		}

		string canonicalIp = parsed.ToString();

		if (!OperatingSystem.IsWindows())
		{
			return new TemporaryFirewallProbeDto
			{
				Status = IpcResultStatus.Unavailable,
				GeneratedUtc = generatedUtc,
				TestIp = canonicalIp,
				RuleName = NetshCommandBuilder.BuildRuleName(TemporaryProbeRuleBase, canonicalIp),
				CreatedVerifiedAndCleanedUp = false,
				Message = "The temporary firewall rule probe only runs on Windows hosts.",
				ReportText = "Temporary firewall rule probe skipped: not running on a Windows host.",
			};
		}

		return await ExecuteTemporaryProbeAsync(canonicalIp, generatedUtc, ct).ConfigureAwait(false);
	}

	/// <summary>Drives the create / verify / cleanup orchestration against the configured firewall
	/// provider. Split from the public entry point (which gates on the Windows host) so the
	/// orchestration is unit-testable cross-platform with a fake provider. The supplied IP is assumed to
	/// be already validated and canonicalized by the caller.</summary>
	internal async Task<TemporaryFirewallProbeDto> ExecuteTemporaryProbeAsync(
		string canonicalIp, DateTime generatedUtc, CancellationToken ct)
	{
		string ruleName = NetshCommandBuilder.BuildRuleName(TemporaryProbeRuleBase, canonicalIp);
		List<ToolProbeResultDto> steps = new();
		string? ruleHandle = null;
		string? scannerBackend = null;

		// Stage 1 — create the temporary block rule.
		FirewallActionResult create = await _windowsProvider.BlockAsync(
			new FirewallBlockRequest(canonicalIp, TemporaryProbeRuleBase)
			{
				Reason = "Tools Diag temporary probe",
			},
			ct).ConfigureAwait(false);
		ruleHandle = create.RuleHandle ?? create.RuleId;
		scannerBackend = create.BackendAttempt?.ScannerBackend;
		steps.Add(StepFor(create, "create temporary block rule"));

		bool created = create.Status == FirewallActionStatus.Success;

		// Stage 2 — targeted verify: prefer an exact-name / matcher lookup for THIS rule before any broad
		// scan, so a host with many firewall rules is not penalised by an expensive enumeration when the
		// canonical rule can be confirmed directly. Distinguishes a true "rule absent" from a provider /
		// scan timeout (the latter is reported as a non-fatal Note rather than a hard verification failure).
		bool verified = false;
		if (created)
		{
			verified = await VerifyTemporaryRuleAsync(
				canonicalIp, ruleName, ruleHandle, scannerBackend, steps, ct).ConfigureAwait(false);
		}

		// Stage 3 — always attempt cleanup, even when creation or verification failed, so the probe
		// never leaves a stray rule behind.
		FirewallActionResult cleanup = await _windowsProvider.UnblockAsync(
			canonicalIp, TemporaryProbeRuleBase, ct).ConfigureAwait(false);
		steps.Add(StepFor(cleanup, "clean up temporary block rule"));
		bool cleanedUp = cleanup.Status is FirewallActionStatus.Success or FirewallActionStatus.NotFound;

		// Stage 4 — cleanup verify: confirm the rule is actually gone from the firewall store. A cleanup
		// that reports success but leaves the rule behind (or a NotFound that masks a stale duplicate) is
		// surfaced here so the operator is never told "cleaned up" while a stray RdpAudit rule lingers.
		bool cleanupConfirmed = await VerifyTemporaryRuleAbsentAsync(
			canonicalIp, ruleName, ruleHandle, scannerBackend, steps, ct).ConfigureAwait(false);

		bool overall = created && verified && cleanedUp && cleanupConfirmed;
		TemporaryFirewallProbeDto dto = new()
		{
			Status = IpcResultStatus.Success,
			GeneratedUtc = generatedUtc,
			TestIp = canonicalIp,
			RuleName = ruleName,
			RuleHandle = ruleHandle,
			ScannerBackend = scannerBackend,
			CreatedVerifiedAndCleanedUp = overall,
			Steps = steps,
			Message = overall
				? "Temporary rule created, verified, cleaned up and confirmed removed successfully."
				: BuildTemporaryFailureNote(created, verified, cleanedUp, cleanupConfirmed),
		};
		dto.ReportText = ToolsDiagnosticsReportBuilder.BuildTemporaryProbe(dto);
		return dto;
	}

	/// <summary>Targeted-first verification that the temporary rule landed. Performs a single provider
	/// list (the provider already prefers a targeted PowerShell/netsh query), then attributes the result
	/// with <see cref="RdpAuditFirewallRuleMatcher"/> — exact canonical name first, then handle, then
	/// remote IP. Records the stage's duration and distinguishes a scan/provider timeout from a genuine
	/// absence. Returns true only when the rule is positively confirmed present.</summary>
	private async Task<bool> VerifyTemporaryRuleAsync(
		string canonicalIp,
		string ruleName,
		string? ruleHandle,
		string? scannerBackend,
		List<ToolProbeResultDto> steps,
		CancellationToken ct)
	{
		System.Diagnostics.Stopwatch sw = System.Diagnostics.Stopwatch.StartNew();
		try
		{
			IReadOnlyList<FirewallBlockEntry> entries =
				await _windowsProvider.ListBlocksAsync(TemporaryProbeRuleBase, ct).ConfigureAwait(false);
			sw.Stop();

			bool exactNameMatch = entries.Any(e =>
				string.Equals(e.RuleId, ruleName, StringComparison.OrdinalIgnoreCase));
			bool handleMatch = !string.IsNullOrEmpty(ruleHandle) && entries.Any(e =>
				string.Equals(e.RuleId, ruleHandle, StringComparison.OrdinalIgnoreCase));
			bool ipMatch = entries.Any(e =>
				string.Equals(e.Ip, canonicalIp, StringComparison.OrdinalIgnoreCase));
			bool verified = exactNameMatch || handleMatch || ipMatch;

			string criterion = exactNameMatch
				? "matched by exact canonical rule name (targeted)"
				: handleMatch
					? "matched by backend rule handle (targeted)"
					: ipMatch ? "matched by remote IP (broad)" : "no match";

			steps.Add(new ToolProbeResultDto
			{
				ToolName = "verify temporary block rule present",
				Executable = "(firewall provider list)",
				Arguments = ruleName,
				RunnerMode = scannerBackend ?? "Direct",
				ExitCode = verified ? 0 : 1,
				DurationMs = sw.ElapsedMilliseconds,
				TimedOut = false,
				StdoutPreview = string.Format(
					CultureInfo.InvariantCulture,
					"List returned {0} RdpAudit rule(s); matching rule {1} ({2}).",
					entries.Count,
					verified ? "found" : "NOT found",
					criterion),
				Passed = verified,
				Note = verified
					? "Temporary rule confirmed present in the firewall store."
					: "Temporary rule was not found in the firewall store after creation.",
			});
			return verified;
		}
		catch (OperationCanceledException) when (ct.IsCancellationRequested)
		{
			throw;
		}
		catch (Exception ex)
		{
			sw.Stop();
			// A provider/scan timeout or transient failure is NOT proof the rule is absent: the create
			// stage may well have succeeded locally. Surface it as a distinct, non-fatal diagnostic so the
			// operator can tell "rule definitely missing" apart from "couldn't read the store in time".
			bool timedOut = ex is TimeoutException or TaskCanceledException;
			_logger.LogWarning(ex, "Temporary probe verification raised an exception for {Ip}", canonicalIp);
			steps.Add(new ToolProbeResultDto
			{
				ToolName = "verify temporary block rule present",
				Executable = "(firewall provider list)",
				Arguments = ruleName,
				RunnerMode = scannerBackend ?? "Direct",
				ExitCode = -1,
				DurationMs = sw.ElapsedMilliseconds,
				TimedOut = timedOut,
				StderrPreview = ex.GetType().Name + ": " + ex.Message,
				Passed = false,
				Note = timedOut
					? "Verification scan timed out; this is inconclusive (the rule may have been created locally) rather than proof of absence."
					: "Verification query raised an exception.",
			});
			return false;
		}
	}

	/// <summary>Cleanup verification: confirms the temporary rule is no longer present after the unblock.
	/// Records duration and treats a scan timeout as inconclusive (non-fatal) rather than as a leaked
	/// rule. Returns true only when the rule is positively confirmed absent.</summary>
	private async Task<bool> VerifyTemporaryRuleAbsentAsync(
		string canonicalIp,
		string ruleName,
		string? ruleHandle,
		string? scannerBackend,
		List<ToolProbeResultDto> steps,
		CancellationToken ct)
	{
		System.Diagnostics.Stopwatch sw = System.Diagnostics.Stopwatch.StartNew();
		try
		{
			IReadOnlyList<FirewallBlockEntry> entries =
				await _windowsProvider.ListBlocksAsync(TemporaryProbeRuleBase, ct).ConfigureAwait(false);
			sw.Stop();

			bool stillPresent = entries.Any(e =>
				string.Equals(e.RuleId, ruleName, StringComparison.OrdinalIgnoreCase)
				|| (!string.IsNullOrEmpty(ruleHandle) && string.Equals(e.RuleId, ruleHandle, StringComparison.OrdinalIgnoreCase))
				|| string.Equals(e.Ip, canonicalIp, StringComparison.OrdinalIgnoreCase));

			steps.Add(new ToolProbeResultDto
			{
				ToolName = "verify temporary block rule removed",
				Executable = "(firewall provider list)",
				Arguments = ruleName,
				RunnerMode = scannerBackend ?? "Direct",
				ExitCode = stillPresent ? 1 : 0,
				DurationMs = sw.ElapsedMilliseconds,
				TimedOut = false,
				StdoutPreview = string.Format(
					CultureInfo.InvariantCulture,
					"Post-cleanup list returned {0} RdpAudit rule(s); temporary rule {1}.",
					entries.Count,
					stillPresent ? "STILL PRESENT" : "absent"),
				Passed = !stillPresent,
				Note = stillPresent
					? "Temporary rule was still present after cleanup; a stray rule may remain — re-run cleanup or remove it manually."
					: "Temporary rule confirmed removed from the firewall store.",
			});
			return !stillPresent;
		}
		catch (OperationCanceledException) when (ct.IsCancellationRequested)
		{
			throw;
		}
		catch (Exception ex)
		{
			sw.Stop();
			bool timedOut = ex is TimeoutException or TaskCanceledException;
			_logger.LogWarning(ex, "Temporary probe cleanup verification raised an exception for {Ip}", canonicalIp);
			steps.Add(new ToolProbeResultDto
			{
				ToolName = "verify temporary block rule removed",
				Executable = "(firewall provider list)",
				Arguments = ruleName,
				RunnerMode = scannerBackend ?? "Direct",
				ExitCode = -1,
				DurationMs = sw.ElapsedMilliseconds,
				TimedOut = timedOut,
				StderrPreview = ex.GetType().Name + ": " + ex.Message,
				Passed = false,
				Note = timedOut
					? "Cleanup-verification scan timed out; removal could not be confirmed (inconclusive)."
					: "Cleanup-verification query raised an exception.",
			});
			return false;
		}
	}

	private ToolProbeResultDto StepFor(FirewallActionResult action, string toolName)
	{
		if (action.BackendAttempt is { } attempt)
		{
			string? note = action.VerifierReason ?? action.Message;
			return ToolProbeResultMapper.FromBackendAttempt(attempt, toolName, note);
		}

		// Providers that did not capture a backend command (e.g. an early validation refusal) still
		// surface their status / message so the operator is not left with an opaque blank step.
		bool ok = action.Status is FirewallActionStatus.Success or FirewallActionStatus.NotFound;
		return new ToolProbeResultDto
		{
			ToolName = toolName,
			Executable = "(firewall provider)",
			Arguments = action.RuleId ?? string.Empty,
			RunnerMode = "Direct",
			ExitCode = ok ? 0 : 1,
			Passed = ok,
			StdoutPreview = action.Message ?? string.Empty,
			Note = action.VerifierReason ?? action.Status.ToString(),
		};
	}

	private async Task<ToolProbeResultDto> RunEnglishConsoleProbeAsync(
		TrustedEnglishConsoleTool tool, string toolName, CancellationToken ct)
	{
		try
		{
			ExternalCommandResult result = await _runner.RunEnglishConsoleAsync(
				tool, args: null, ProbeTimeout, ct).ConfigureAwait(false);
			return ToolProbeResultMapper.Map(result, toolName, result.CommandLabel, "EnglishConsole");
		}
		catch (OperationCanceledException)
		{
			throw;
		}
		catch (Exception ex)
		{
			_logger.LogWarning(ex, "Tools Diag probe {Tool} raised an exception", toolName);
			return ToolProbeResultMapper.Skipped(toolName, tool.ToString(), "Probe raised an exception: " + ex.GetType().Name);
		}
	}

	[SupportedOSPlatform("windows")]
	private async Task<ToolProbeResultDto> RunCommandResolutionProbeAsync(CancellationToken ct)
	{
		const string toolName = "command resolution (where)";
		try
		{
			ExternalCommandResult result = await _runner.RunDirectAsync(
				commandLabel: "where netsh qwinsta quser query powershell",
				executable: "where.exe",
				arguments: new[] { "netsh", "qwinsta", "quser", "query", "powershell" },
				timeout: ProbeTimeout,
				ct: ct).ConfigureAwait(false);
			// where.exe returns exit=1 when at least one name is unresolved; surface stdout regardless so
			// the operator sees which executables resolved (an empty stderr is normal in that case).
			return ToolProbeResultMapper.Map(
				result, toolName, "netsh qwinsta quser query powershell", "Direct",
				note: result.ExitCode == 0
					? "All probed executables resolved on PATH."
					: "where.exe exit was non-zero (at least one name did not resolve); resolved paths are in stdout.");
		}
		catch (OperationCanceledException)
		{
			throw;
		}
		catch (Exception ex)
		{
			_logger.LogWarning(ex, "Tools Diag command-resolution probe raised an exception");
			return ToolProbeResultMapper.Skipped(toolName, "where.exe", "Probe raised an exception: " + ex.GetType().Name);
		}
	}

	[SupportedOSPlatform("windows")]
	private async Task<ToolProbeResultDto> RunPowerShellFirewallProbeAsync(CancellationToken ct)
	{
		const string toolName = "powershell Get-NetFirewallRule (JSON)";
		// The exact backend command we run: the SAME locale-independent script the live scanner uses. It
		// is anchored on `Get-NetFirewallRule -Group 'RdpAudit'` — the precise query the operator verified
		// returns our rules — and projects each to an English-stable JSON object (Name/Group/Direction/
		// Action/Enabled/…); the parser then filters by name prefix OR group=RdpAudit. The earlier probe
		// label scanned every inbound rule and returned [] on the operator's host; this surfaces the real
		// command + parsed count.
		const string backendCommand =
			"powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -OutputFormat Text -Command "
			+ "\"Get-NetFirewallRule -Group 'RdpAudit' | Select Name,DisplayName,Group,DisplayGroup,Enabled,Direction,Action | ConvertTo-Json -Depth 4\"";
		try
		{
			ExternalCommandResult result = await _runner.RunDirectAsync(
				commandLabel: toolName,
				executable: "powershell.exe",
				arguments: new[]
				{
					"-NoProfile",
					"-NonInteractive",
					"-ExecutionPolicy", "Bypass",
					"-OutputFormat", "Text",
					"-Command", PowerShellFirewallRuleScanner.FirewallRulesJsonScript,
				},
				timeout: ProbeTimeout,
				ct: ct).ConfigureAwait(false);

			// Parse the emitted JSON and report how many RdpAudit rules matched so the operator sees the
			// scanner's actual finding (the root cause of the "[] returned" confusion) instead of just raw
			// stdout. Tolerates single-object and array JSON via the shared parser.
			int matched = -1;
			if (!result.TimedOut && result.ExitCode == 0 && !string.IsNullOrWhiteSpace(result.StdOut))
			{
				IReadOnlyList<DiscoveredBlockRule> rules = PowerShellFirewallRuleParser.DiscoverRdpAuditBlockRules(
					result.StdOut,
					NetshCommandBuilder.DefaultRulePrefix,
					NetshCommandBuilder.RdpAuditGroup);
				matched = rules.Count;
			}

			string note = matched >= 0
				? string.Format(
					CultureInfo.InvariantCulture,
					"Locale-independent firewall enumeration; parser matched {0} RdpAudit rule(s) by name prefix '{1}' OR group=RdpAudit.",
					matched,
					NetshCommandBuilder.DefaultRulePrefix)
				: "Locale-independent firewall enumeration; the JSON is parsed by name prefix OR group=RdpAudit (no usable JSON returned by this run).";

			return ToolProbeResultMapper.Map(result, toolName, backendCommand, "PowerShellJson", note: note);
		}
		catch (OperationCanceledException)
		{
			throw;
		}
		catch (Exception ex)
		{
			_logger.LogWarning(ex, "Tools Diag PowerShell firewall probe raised an exception");
			return ToolProbeResultMapper.Skipped(toolName, "powershell.exe", "Probe raised an exception: " + ex.GetType().Name);
		}
	}

	private ToolProbeResultDto BuildRdpPortProbe()
	{
		const string toolName = "RDP listener port read";
		if (_portProvider is null)
		{
			return ToolProbeResultMapper.Skipped(
				toolName, "(registry read)", "RDP port provider is not registered on this host.");
		}

		try
		{
			int port = _portProvider.GetRdpPort();
			bool fromRegistry = port != RdpConfigurationModel.DefaultRdpPort;
			return new ToolProbeResultDto
			{
				ToolName = toolName,
				Executable = "(registry read)",
				Arguments = @"HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp\PortNumber",
				RunnerMode = "Direct",
				ExitCode = 0,
				DurationMs = 0,
				TimedOut = false,
				StdoutPreview = string.Format(CultureInfo.InvariantCulture, "Resolved RDP listener port = {0}.", port),
				Passed = true,
				Note = fromRegistry
					? "Port read from the registry."
					: "Registry value absent or default; using the documented Microsoft default port.",
			};
		}
		catch (Exception ex)
		{
			_logger.LogWarning(ex, "Tools Diag RDP port read raised an exception");
			return ToolProbeResultMapper.Skipped(toolName, "(registry read)", "RDP port read raised an exception: " + ex.GetType().Name);
		}
	}

	private static ToolsDiagnosticsDto BuildDto(DateTime generatedUtc, List<ToolProbeResultDto> probes, string? message)
	{
		// Surface the running service build (SemVer + git SHA when the publish pipeline stamped one) so the
		// operator can confirm which commit produced the binary and compare it against the Configurator they
		// launched. A full installed-vs-Configurator SHA-mismatch warning needs an IPC handshake and is
		// deferred to a follow-up; surfacing the service SHA here is the low-risk first step.
		string serviceBuild = "Service build " + RuntimeVersionResolver.ResolveFull();
		string composedMessage = string.IsNullOrWhiteSpace(message)
			? serviceBuild
			: serviceBuild + " — " + message;
		return new ToolsDiagnosticsDto
		{
			Status = IpcResultStatus.Success,
			GeneratedUtc = generatedUtc,
			Probes = probes,
			ReportText = ToolsDiagnosticsReportBuilder.Build(probes, generatedUtc),
			Message = composedMessage,
		};
	}

	private static string BuildTemporaryFailureNote(bool created, bool verified, bool cleanedUp, bool cleanupConfirmed)
	{
		if (!created)
		{
			return "Temporary rule creation failed; see the create step for the exact backend command and output.";
		}

		if (!verified)
		{
			return "Temporary rule was created but could not be verified in the firewall store; cleanup was still attempted.";
		}

		if (!cleanedUp)
		{
			return "Temporary rule created and verified but cleanup did not confirm removal; check the cleanup step.";
		}

		return cleanupConfirmed
			? "Temporary rule created and verified."
			: "Temporary rule created, verified and cleanup reported success, but the post-cleanup scan could not confirm the rule is gone; check the cleanup-verify step.";
	}

	private static IExternalCommandRunner BuildDefaultRunner()
	{
		if (OperatingSystem.IsWindows())
		{
			return new ExternalCommandRunner();
		}

		// The service only constructs this on Windows in production; the cross-platform fallback keeps
		// the type constructible under Linux CI without ever spawning a Windows command.
		return new UnsupportedExternalCommandRunner();
	}

	/// <summary>Cross-platform no-op runner so <see cref="ToolsDiagnosticsService"/> is constructible on
	/// non-Windows hosts. Every method returns a "not supported on this host" result without spawning a
	/// process; the diagnostics path skips Windows probes on non-Windows hosts before reaching it.</summary>
	private sealed class UnsupportedExternalCommandRunner : IExternalCommandRunner
	{
		public Task<ExternalCommandResult> RunEnglishConsoleAsync(
			TrustedEnglishConsoleTool tool, EnglishConsoleArgs? args, TimeSpan timeout, CancellationToken ct) =>
			Task.FromResult(Unsupported(tool.ToString()));

		public Task<ExternalCommandResult> RunDirectAsync(
			string commandLabel, string executable, IReadOnlyList<string> arguments, TimeSpan timeout, CancellationToken ct) =>
			Task.FromResult(Unsupported(commandLabel));

		private static ExternalCommandResult Unsupported(string label) =>
			new(
				CommandLabel: label,
				Executable: string.Empty,
				ExitCode: -1,
				StdOut: string.Empty,
				StdErr: "External commands are only supported on Windows hosts.",
				TimedOut: false,
				Duration: TimeSpan.Zero,
				EnglishConsoleMode: false);
	}
}
