/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 1.4.2
// File   : WindowsFirewallProvider.cs
// Project: RdpAudit.Service (RdpAudit.Service.Firewall)
// Purpose: Real IFirewallProvider backed by netsh advfirewall + PowerShell New-NetFirewallRule.
//          Fixed: (a) TryPowerShellCreateAsync now logs PS exit/stderr at Warning on failure so
//          the operator can diagnose silent fallbacks; (b) UnblockAsync uses exit-code 1 as the
//          locale-independent NotFound signal instead of an English text match that failed on
//          Russian/Chinese/other Windows UI cultures.
// Depends: INetshRunner, IFirewallRuleScanner, IExternalCommandRunner, IRdpPortProvider,
//          NetshCommandBuilder, RdpAuditFirewallRuleMatcher
// Extends: Add new block scopes in NetshCommandBuilder.BuildAddRuleArgs and
//          BuildNewNetFirewallRuleScript; add new verification logic in the VerifyAfterBlock path.

using System.Globalization;
using System.Net;
using System.Runtime.Versioning;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using RdpAudit.Core.Config;
using RdpAudit.Core.Firewall;
using RdpAudit.Core.Util;

namespace RdpAudit.Service.Firewall;

/// <summary>Real <see cref="IFirewallProvider"/> implementation backed by netsh advfirewall.</summary>
public sealed class WindowsFirewallProvider : IFirewallProvider
{
	/// <summary>Hard timeout for the PowerShell New-NetFirewallRule create path.</summary>
	private static readonly TimeSpan PowerShellCreateTimeout = TimeSpan.FromSeconds(20);

	// ── Fields & DI ──────────────────────────────────────────────────────────────
	private readonly ILogger<WindowsFirewallProvider> _logger;
	private readonly IOptionsMonitor<RdpAuditOptions> _options;
	private readonly INetshRunner _runner;
	private readonly IRdpPortProvider _portProvider;
	private readonly IExternalCommandRunner? _powerShellRunner;
	private readonly IFirewallRuleScanner? _scanner;

	// ── Construction ─────────────────────────────────────────────────────────────
	[SupportedOSPlatform("windows")]
	public WindowsFirewallProvider(
		ILogger<WindowsFirewallProvider> logger,
		IOptionsMonitor<RdpAuditOptions> options,
		IFirewallRuleScanner scanner)
		: this(logger, options, new NetshRunner(), new RegistryRdpPortProvider(), new ExternalCommandRunner(), scanner)
	{
		ArgumentNullException.ThrowIfNull(scanner);
	}

	internal WindowsFirewallProvider(
		ILogger<WindowsFirewallProvider> logger,
		IOptionsMonitor<RdpAuditOptions> options,
		INetshRunner runner,
		IRdpPortProvider portProvider,
		IExternalCommandRunner? powerShellRunner = null,
		IFirewallRuleScanner? scanner = null)
	{
		ArgumentNullException.ThrowIfNull(logger);
		ArgumentNullException.ThrowIfNull(options);
		ArgumentNullException.ThrowIfNull(runner);
		ArgumentNullException.ThrowIfNull(portProvider);
		_logger = logger;
		_options = options;
		_runner = runner;
		_portProvider = portProvider;
		_powerShellRunner = powerShellRunner;
		_scanner = scanner;
	}

	// ── Public API ───────────────────────────────────────────────────────────────
	public string ProviderId => "Windows";

	public async Task<FirewallStatusReport> GetStatusAsync(CancellationToken ct)
	{
		ct.ThrowIfCancellationRequested();

		if (!OperatingSystem.IsWindows())
		{
			return new FirewallStatusReport
			{
				Status = FirewallProviderStatus.Unreachable,
				ProviderId = ProviderId,
				Message = "Windows Advanced Firewall is only available on Windows hosts.",
			};
		}

		NetshResult result;
		try
		{
			result = await _runner.RunAsync(NetshCommandBuilder.BuildShowAllProfilesStateArgs(), ct).ConfigureAwait(false);
		}
		catch (OperationCanceledException)
		{
			throw;
		}
		catch (Exception ex)
		{
			_logger.LogWarning(ex, "Failed to query firewall state via netsh");
			return new FirewallStatusReport
			{
				Status = FirewallProviderStatus.Unreachable,
				ProviderId = ProviderId,
				Message = "Failed to query firewall state.",
			};
		}

		if (!result.Success)
		{
			_logger.LogWarning("netsh show allprofiles state returned exit={Exit}", result.ExitCode);
			return new FirewallStatusReport
			{
				Status = FirewallProviderStatus.Unreachable,
				ProviderId = ProviderId,
				Message = "netsh returned non-zero status when querying firewall state.",
			};
		}

		bool anyOn = result.StdOut.Contains(" ON", StringComparison.OrdinalIgnoreCase);

		return new FirewallStatusReport
		{
			Status = anyOn ? FirewallProviderStatus.Available : FirewallProviderStatus.Disabled,
			ProviderId = ProviderId,
			Message = anyOn
				? "Windows Defender Firewall has at least one profile enabled."
				: "All Windows Defender Firewall profiles report OFF.",
		};
	}

	public async Task<FirewallActionResult> BlockAsync(FirewallBlockRequest request, CancellationToken ct)
	{
		ArgumentNullException.ThrowIfNull(request);
		ct.ThrowIfCancellationRequested();

		if (!OperatingSystem.IsWindows())
		{
			return FirewallActionResult.UnavailableFor(ProviderId, "Windows firewall provider only runs on Windows hosts.");
		}

		FirewallOptions cfg = _options.CurrentValue.Firewall;

		IPAddress address;
		try
		{
			address = NetshCommandBuilder.ParseAndValidateIp(request.Ip);
		}
		catch (ArgumentException ex)
		{
			_logger.LogWarning("Block refused for invalid IP: {Message}", ex.Message);
			return new FirewallActionResult
			{
				Status = FirewallActionStatus.InvalidRequest,
				ProviderId = ProviderId,
				Message = "IP address failed validation.",
			};
		}

		if (NetshCommandBuilder.IsReservedAddress(address) && cfg.RefusePrivateAddressBlock)
		{
			_logger.LogWarning("Block refused for reserved address {Ip}", address);
			return new FirewallActionResult
			{
				Status = FirewallActionStatus.Refused,
				ProviderId = ProviderId,
				Message = "Address is loopback / private / multicast and policy refuses blocking it.",
			};
		}

		string canonicalIp = address.ToString();
		string ruleName = NetshCommandBuilder.BuildRuleName(request.RuleName, canonicalIp);
		string description = BuildAuditDescription(request.Reason, request.Duration);

		FirewallBlockScope scope = cfg.BlockScope;
		int rdpPort = scope == FirewallBlockScope.RdpPortOnly ? _portProvider.GetRdpPort() : 0;

		IReadOnlyList<string> addArgs;
		try
		{
			addArgs = NetshCommandBuilder.BuildAddRuleArgs(ruleName, canonicalIp, description, scope, rdpPort);
		}
		catch (ArgumentOutOfRangeException ex)
		{
			_logger.LogWarning(ex, "Block refused: could not resolve a valid RDP port for RdpPortOnly scope");
			return new FirewallActionResult
			{
				Status = FirewallActionStatus.InvalidRequest,
				ProviderId = ProviderId,
				RuleId = ruleName,
				Message = "RdpPortOnly scope requires a resolved RDP listener port; resolution failed.",
			};
		}

		IReadOnlyList<string> deleteArgs = NetshCommandBuilder.BuildDeleteRuleArgs(ruleName);
		_logger.LogDebug("Firewall block: pre-delete netsh {Args} (rule={RuleName}, ip={Ip})",
			string.Join(' ', deleteArgs), ruleName, canonicalIp);
		NetshResult deleteResult = await _runner.RunAsync(deleteArgs, ct).ConfigureAwait(false);
		_logger.LogDebug("Firewall block: pre-delete netsh exit={Exit} (rule={RuleName})", deleteResult.ExitCode, ruleName);

		BackendCommandAttempt addAttempt;
		bool createdOk;
		BackendCommandAttempt? powerShellAttempt = await TryPowerShellCreateAsync(
			ruleName, canonicalIp, description, scope, rdpPort, ct).ConfigureAwait(false);

		if (powerShellAttempt is { Success: true })
		{
			addAttempt = powerShellAttempt;
			createdOk = true;
		}
		else
		{
			_logger.LogDebug("Firewall block: add netsh {Args} (rule={RuleName}, ip={Ip})",
				string.Join(' ', addArgs), ruleName, canonicalIp);
			NetshResult addResult = await _runner.RunAsync(addArgs, ct).ConfigureAwait(false);
			addAttempt = BuildAttempt(addResult, addArgs);
			createdOk = addResult.Success;
			_logger.LogDebug("Firewall block: add netsh exit={Exit} success={Success} (rule={RuleName})",
				addResult.ExitCode, createdOk, ruleName);

			if (!createdOk)
			{
				_logger.LogWarning(
					"Firewall block failed for {Ip}: exit={Exit} stderr={StdErr} (powerShellTried={PsTried})",
					canonicalIp,
					addResult.ExitCode,
					SanitizeForLog(addResult.StdErr),
					powerShellAttempt is not null);
				return new FirewallActionResult
				{
					Status = FirewallActionStatus.Unavailable,
					ProviderId = ProviderId,
					RuleId = ruleName,
					RuleHandle = ruleName,
					BackendAttempt = addAttempt,
					VerifierReason = powerShellAttempt is null
						? "netsh add rule exited non-zero before verification."
						: "PowerShell New-NetFirewallRule failed and the netsh add fallback also exited non-zero.",
					Message = BuildBackendFailureMessage("netsh add rule", addResult),
				};
			}
		}

		if (cfg.VerifyAfterBlock)
		{
			if (_scanner is not null)
			{
				FirewallScanResult scan;
				try
				{
					scan = await _scanner.ScanRdpAuditBlockRulesAsync(
						NetshCommandBuilder.NormalizeRulePrefix(request.RuleName), ct).ConfigureAwait(false);
				}
				catch (OperationCanceledException)
				{
					throw;
				}
				catch (Exception ex)
				{
					_logger.LogWarning(ex, "Targeted firewall verification scan raised an exception for {Ip}", canonicalIp);
					scan = new FirewallScanResult(Scannable: false, Rules: Array.Empty<DiscoveredBlockRule>(),
						Note: "Targeted verification scan threw: " + ex.GetType().Name, Backend: FirewallScanBackend.None);
				}

				FirewallRuleMatchResult verifyMatch = RdpAuditFirewallRuleMatcher.MatchDiscovered(
					scan.Rules,
					canonicalIp,
					NetshCommandBuilder.NormalizeRulePrefix(request.RuleName),
					NetshCommandBuilder.RdpAuditGroup);
				bool targetedFound = verifyMatch.VerifiedEnforced;

				if (!targetedFound)
				{
					_logger.LogWarning(
						"Firewall block could not be verified for {Ip}: rule {RuleName} not found by targeted group scan (backend={Backend}, scannable={Scannable}, rules={Count})",
						canonicalIp,
						ruleName,
						scan.Backend,
						scan.Scannable,
						scan.Rules.Count);
					return new FirewallActionResult
					{
						Status = FirewallActionStatus.Unavailable,
						ProviderId = ProviderId,
						RuleId = ruleName,
						RuleHandle = ruleName,
						BackendAttempt = addAttempt,
						VerifierReason = string.Format(
							CultureInfo.InvariantCulture,
							"targeted verify by name '{0}': not found; broad group scan: {1} rule(s) via {2} (scannable={3}).",
							ruleName,
							scan.Rules.Count,
							scan.Backend,
							scan.Scannable),
						Message = "Block rule reported success but could not be verified via Get-NetFirewallRule -Group RdpAudit; a managing third-party firewall may have rejected it.",
					};
				}

				_logger.LogInformation(
					"Firewall block rule installed and verified (targeted group scan): {RuleName} for {Ip} scope={Scope} port={Port} backend={Backend}",
					ruleName,
					canonicalIp,
					scope,
					rdpPort,
					scan.Backend);
				return new FirewallActionResult
				{
					Status = FirewallActionStatus.Success,
					ProviderId = ProviderId,
					RuleId = ruleName,
					RuleHandle = ruleName,
					BackendAttempt = addAttempt,
					VerifierReason = string.Format(
						CultureInfo.InvariantCulture,
						"targeted verify by name '{0}': found; matcher verify for {1}: {2} matching rule(s) (canonicalPresent={3}, duplicates={4}); broad group scan: {5} rule(s) via {6}.",
						ruleName,
						canonicalIp,
						verifyMatch.Matches.Count,
						verifyMatch.HasCanonicalRule,
						verifyMatch.HasDuplicates,
						scan.Rules.Count,
						scan.Backend),
					Message = verifyMatch.HasDuplicates
						? "Block rule installed and verified; duplicate rule(s) for this IP detected — canonicalization recommended."
						: "Block rule installed and verified.",
				};
			}

			IReadOnlyList<string> showArgs = NetshCommandBuilder.BuildShowRuleArgs(ruleName);
			NetshResult verify = await _runner.RunAsync(showArgs, ct).ConfigureAwait(false);

			bool confirmed = verify.Success
				&& NetshRuleScanner.ContainsEnabledInboundBlockRule(verify.StdOut);
			if (!confirmed)
			{
				_logger.LogWarning(
					"Firewall block could not be verified for {Ip}: rule {RuleName} not found after add (a managing third-party firewall may have rejected the write)",
					canonicalIp,
					ruleName);
				string verifierReason = verify.Success
					? "Verification query succeeded but no enabled inbound block rule was found in the store."
					: string.Format(CultureInfo.InvariantCulture, "Verification query exited {0}.", verify.ExitCode);
				return new FirewallActionResult
				{
					Status = FirewallActionStatus.Unavailable,
					ProviderId = ProviderId,
					RuleId = ruleName,
					RuleHandle = ruleName,
					BackendAttempt = BuildAttempt(verify, showArgs),
					VerifierReason = verifierReason,
					Message = "Block rule reported success but could not be verified in the firewall store; a managing third-party firewall may have rejected it.",
				};
			}
		}

		_logger.LogInformation(
			"Firewall block rule installed and verified: {RuleName} for {Ip} scope={Scope} port={Port}",
			ruleName,
			canonicalIp,
			scope,
			rdpPort);
		return new FirewallActionResult
		{
			Status = FirewallActionStatus.Success,
			ProviderId = ProviderId,
			RuleId = ruleName,
			RuleHandle = ruleName,
			BackendAttempt = addAttempt,
			VerifierReason = cfg.VerifyAfterBlock
				? "Enabled inbound block rule confirmed in the firewall store."
				: "Verification disabled by configuration.",
			Message = cfg.VerifyAfterBlock ? "Block rule installed and verified." : "Block rule installed.",
		};
	}

	// ── Core Logic ───────────────────────────────────────────────────────────────

	/// <summary>Attempts to create the block rule via PowerShell <c>New-NetFirewallRule -Group
	/// RdpAudit</c>. Returns null when no PowerShell runner is wired; returns a populated
	/// <see cref="BackendCommandAttempt"/> otherwise. A non-success attempt is non-fatal — the
	/// caller falls back to netsh.
	/// FIX Bug 2: PS exit code and stderr are now logged at Warning level when the PS path fails
	/// so the operator can diagnose why the fallback was triggered.</summary>
	private async Task<BackendCommandAttempt?> TryPowerShellCreateAsync(
		string ruleName,
		string canonicalIp,
		string? description,
		FirewallBlockScope scope,
		int rdpPort,
		CancellationToken ct)
	{
		if (_powerShellRunner is null)
		{
			return null;
		}

		string script;
		try
		{
			script = NetshCommandBuilder.BuildNewNetFirewallRuleScript(ruleName, canonicalIp, description, scope, rdpPort);
		}
		catch (ArgumentException ex)
		{
			_logger.LogWarning(ex, "Could not build New-NetFirewallRule script for {Ip}; using netsh fallback", canonicalIp);
			return null;
		}

		IReadOnlyList<string> psArgs = new[]
		{
			"-NoProfile",
			"-NonInteractive",
			"-ExecutionPolicy", "Bypass",
			"-OutputFormat", "Text",
			"-Command", script,
		};

		ExternalCommandResult result;
		try
		{
			result = await _powerShellRunner.RunDirectAsync(
				commandLabel: "powershell New-NetFirewallRule -Group RdpAudit",
				executable: "powershell.exe",
				arguments: psArgs,
				timeout: PowerShellCreateTimeout,
				ct: ct).ConfigureAwait(false);
		}
		catch (OperationCanceledException)
		{
			throw;
		}
		catch (Exception ex)
		{
			_logger.LogWarning(ex, "PowerShell New-NetFirewallRule raised an exception for {Ip}; using netsh fallback", canonicalIp);
			return null;
		}

		// FIX Bug 2: log the PS failure details at Warning so the operator knows the netsh
		// fallback was triggered and WHY — previously this was only visible at Debug level
		// and the silent fallback left rules without -Group RdpAudit, causing the scanner
		// to report 0 rules and verification to return Unavailable.
		if (result.TimedOut || result.ExitCode != 0)
		{
			_logger.LogWarning(
				"PowerShell New-NetFirewallRule failed for {Ip}: timedOut={TimedOut} exit={Exit} stderr={StdErr}; falling back to netsh (rule will lack -Group RdpAudit and may not be found by scanner)",
				canonicalIp,
				result.TimedOut,
				result.ExitCode,
				SanitizeForLog(result.StdErr));
		}

		return new BackendCommandAttempt(
			CommandLabel: "New-NetFirewallRule -Group RdpAudit",
			Executable: "powershell.exe",
			Arguments: "New-NetFirewallRule -Name " + ruleName + " -Group " + NetshCommandBuilder.RdpAuditGroup
				+ " -Direction Inbound -Action Block -Enabled True -Profile Any -RemoteAddress " + canonicalIp,
			RunnerMode: BackendRunnerMode.PowerShellJson,
			ExitCode: result.TimedOut ? -1 : result.ExitCode,
			TimedOut: result.TimedOut,
			DurationMs: (long)result.Duration.TotalMilliseconds,
			StdoutPreview: BackendCommandAttempt.BuildPreview(result.StdOut),
			StderrPreview: BackendCommandAttempt.BuildPreview(result.StdErr),
			ScannerBackend: "NewNetFirewallRule");
	}

	private static BackendCommandAttempt BuildAttempt(NetshResult result, IReadOnlyList<string> args)
	{
		BackendCommandAttempt baseAttempt = result.ToBackendAttempt();
		return baseAttempt with { Arguments = string.Join(' ', args) };
	}

	private static string BuildBackendFailureMessage(string action, NetshResult result)
	{
		string stderr = result.StdErr?.Trim() ?? string.Empty;
		string detail = stderr.Length > 0
			? stderr
			: BackendCommandAttempt.BuildPreview(result.StdOut, 240);
		string baseMsg = string.Format(CultureInfo.InvariantCulture, "{0} returned exit={1}.", action, result.ExitCode);
		return detail.Length > 0 ? baseMsg + " " + detail : baseMsg;
	}

	public async Task<FirewallActionResult> UnblockAsync(string ip, string ruleName, CancellationToken ct)
	{
		ArgumentException.ThrowIfNullOrWhiteSpace(ip);
		ArgumentException.ThrowIfNullOrWhiteSpace(ruleName);
		ct.ThrowIfCancellationRequested();

		if (!OperatingSystem.IsWindows())
		{
			return FirewallActionResult.UnavailableFor(ProviderId, "Windows firewall provider only runs on Windows hosts.");
		}

		IPAddress address;
		try
		{
			address = NetshCommandBuilder.ParseAndValidateIp(ip);
		}
		catch (ArgumentException ex)
		{
			_logger.LogWarning("Unblock refused for invalid IP: {Message}", ex.Message);
			return new FirewallActionResult
			{
				Status = FirewallActionStatus.InvalidRequest,
				ProviderId = ProviderId,
				Message = "IP address failed validation.",
			};
		}

		string canonicalIp = address.ToString();
		string fullRuleName = NetshCommandBuilder.BuildRuleName(ruleName, canonicalIp);

		IReadOnlyList<string> unblockArgs = NetshCommandBuilder.BuildDeleteRuleArgs(fullRuleName);
		_logger.LogDebug("Firewall unblock: netsh {Args} (rule={RuleName}, ip={Ip})",
			string.Join(' ', unblockArgs), fullRuleName, canonicalIp);
		NetshResult delResult = await _runner.RunAsync(unblockArgs, ct).ConfigureAwait(false);

		if (!delResult.Success)
		{
			// FIX Bug 4: use exit code 1 as the locale-independent NotFound signal.
			// The original check 'delResult.StdOut.Contains("No rules match")' failed on
			// Russian/Chinese/other Windows UI cultures where netsh emits translated text.
			// netsh advfirewall delete rule exits 1 when no rules match the name filter;
			// it exits with other non-zero codes for permission errors and parse failures.
			// The English text check is kept as a secondary signal for English-locale hosts.
			bool notFound = delResult.ExitCode == 1
				|| delResult.StdOut.Contains("No rules match", StringComparison.OrdinalIgnoreCase);
			_logger.LogDebug(
				"Firewall unblock returned exit={Exit} notFound={NotFound} for {RuleName}",
				delResult.ExitCode,
				notFound,
				fullRuleName);
			return new FirewallActionResult
			{
				Status = notFound ? FirewallActionStatus.NotFound : FirewallActionStatus.Unavailable,
				ProviderId = ProviderId,
				RuleId = fullRuleName,
				Message = notFound
					? "No matching firewall rule."
					: string.Format(CultureInfo.InvariantCulture, "netsh delete rule returned exit={0}.", delResult.ExitCode),
			};
		}

		_logger.LogInformation("Firewall block rule removed: {RuleName} for {Ip}", fullRuleName, canonicalIp);
		return new FirewallActionResult
		{
			Status = FirewallActionStatus.Success,
			ProviderId = ProviderId,
			RuleId = fullRuleName,
			Message = "Block rule removed.",
		};
	}

	public async Task<IReadOnlyList<FirewallBlockEntry>> ListBlocksAsync(string ruleName, CancellationToken ct)
	{
		ArgumentException.ThrowIfNullOrWhiteSpace(ruleName);
		ct.ThrowIfCancellationRequested();

		if (!OperatingSystem.IsWindows())
		{
			return Array.Empty<FirewallBlockEntry>();
		}

		string normalized = NetshCommandBuilder.NormalizeRulePrefix(ruleName);

		if (_scanner is not null)
		{
			FirewallScanResult scan = await _scanner
				.ScanRdpAuditBlockRulesAsync(normalized, ct).ConfigureAwait(false);

			List<FirewallBlockEntry> scanned = new(scan.Rules.Count);
			foreach (DiscoveredBlockRule rule in scan.Rules)
			{
				scanned.Add(new FirewallBlockEntry
				{
					RuleId = rule.RuleName,
					Ip = rule.RemoteIps.Count > 0 ? rule.RemoteIps[0] : string.Empty,
					ProviderId = ProviderId,
				});
			}

			return scanned;
		}

		NetshResult res = await _runner.RunAsync(
			NetshCommandBuilder.BuildShowRuleArgs(normalized),
			ct).ConfigureAwait(false);

		if (!res.Success)
		{
			return Array.Empty<FirewallBlockEntry>();
		}

		List<FirewallBlockEntry> entries = new();
		string? currentName = null;
		string? currentIp = null;
		foreach (string raw in res.StdOut.Split('\n'))
		{
			string line = raw.TrimEnd('\r').Trim();
			if (line.StartsWith("Rule Name:", StringComparison.OrdinalIgnoreCase))
			{
				if (currentName is not null && currentIp is not null)
				{
					entries.Add(new FirewallBlockEntry
					{
						RuleId = currentName,
						Ip = currentIp,
						ProviderId = ProviderId,
					});
				}
				currentName = line["Rule Name:".Length..].Trim();
				currentIp = null;
			}
			else if (line.StartsWith("RemoteIP:", StringComparison.OrdinalIgnoreCase))
			{
				currentIp = line["RemoteIP:".Length..].Trim();
			}
		}

		if (currentName is not null && currentIp is not null)
		{
			entries.Add(new FirewallBlockEntry
			{
				RuleId = currentName,
				Ip = currentIp,
				ProviderId = ProviderId,
			});
		}

		return entries;
	}

	internal static string BuildAuditDescription(string? reason, TimeSpan? duration)
	{
		string createdUtc = DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ", CultureInfo.InvariantCulture);
		string body = string.IsNullOrWhiteSpace(reason) ? "auto-block" : reason!;
		string expires = duration is { TotalSeconds: > 0 }
			? duration.Value.ToString("c", CultureInfo.InvariantCulture)
			: "permanent";

		return string.Format(
			CultureInfo.InvariantCulture,
			"RdpAudit; reason={0}; created={1}; duration={2}",
			body,
			createdUtc,
			expires);
	}

	// ── Error Handling & Retry ───────────────────────────────────────────────────
	private static string SanitizeForLog(string? value)
	{
		if (string.IsNullOrEmpty(value))
		{
			return string.Empty;
		}

		int len = Math.Min(value.Length, 512);
		Span<char> buf = stackalloc char[len];
		int written = 0;
		for (int i = 0; i < len; i++)
		{
			char c = value[i];
			buf[written++] = char.IsControl(c) ? ' ' : c;
		}
		return new string(buf[..written]).Trim();
	}
}
