// File:    src/RdpAudit.Service/Firewall/PowerShellFirewallRuleScanner.cs
// Module:  RdpAudit.Service.Firewall
// Purpose: Locale-independent IFirewallRuleScanner. Enumerates RdpAudit-owned inbound block rules by
//          running `Get-NetFirewallRule | … | ConvertTo-Json` and parsing the English-stable JSON
//          property names — instead of parsing the `netsh` verbose text dump, whose field labels are
//          translated into the host UI language and therefore yield zero matches on a non-English
//          host (the root cause of "RdpAudit-group inbound block rules: 0" on a Russian Windows
//          install even though the rules exist). The PowerShell command is invoked via an argument
//          vector (no shell, no string concatenation across the rule-name boundary). When the
//          PowerShell path is unavailable or fails, the scanner transparently falls back to the
//          netsh text scanner so a host without the NetSecurity module still degrades gracefully.
// Extends: RdpAudit.Service.Firewall.IFirewallRuleScanner
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System.Runtime.Versioning;
using Microsoft.Extensions.Logging;
using RdpAudit.Core.Firewall;
using RdpAudit.Core.Util;

namespace RdpAudit.Service.Firewall;

/// <summary>Locale-independent <see cref="IFirewallRuleScanner"/> backed by
/// <c>Get-NetFirewallRule | ConvertTo-Json</c>. Falls back to the netsh text scanner on failure.</summary>
public sealed class PowerShellFirewallRuleScanner : IFirewallRuleScanner
{
	/// <summary>Fixed PowerShell script that emits one JSON object per RdpAudit-owned rule.
	/// English-stable property names; no operator input is interpolated. Passed as a single
	/// argument-vector element so there is no shell-quoting surface.</summary>
	/// <remarks>
	/// IMPORTANT: enumeration is anchored on <c>Get-NetFirewallRule -Group 'RdpAudit'</c> — the exact
	/// query the operator confirmed returns our rules on a live ru-RU host. The earlier script scanned
	/// EVERY inbound rule (<c>-Direction Inbound -All</c>) and piped each through
	/// <c>Get-NetFirewallAddressFilter</c> / <c>Get-NetFirewallPortFilter</c>; on the live host that
	/// fragile per-rule enrichment collapsed the whole result to <c>[]</c> even though the rules exist.
	/// Here the address / port enrichment is best-effort (<c>-ErrorAction SilentlyContinue</c>) so a
	/// single failing filter can never zero out the rule list — a rule still reports its
	/// Name / Group / DisplayGroup / Direction / Action / Enabled even if its filters cannot be read.
	/// The parser then matches by name prefix OR group=RdpAudit.
	/// </remarks>
	internal const string FirewallRulesJsonScript =
		"$ErrorActionPreference='SilentlyContinue';"
		+ "$r=Get-NetFirewallRule -Group 'RdpAudit';"
		+ "if($null -eq $r){'[]'}else{"
		+ "$o=foreach($x in $r){"
		+ "$a=$x|Get-NetFirewallAddressFilter -ErrorAction SilentlyContinue;"
		+ "$p=$x|Get-NetFirewallPortFilter -ErrorAction SilentlyContinue;"
		+ "[pscustomobject]@{"
		+ "Name=$x.Name;DisplayName=$x.DisplayName;Group=$x.Group;DisplayGroup=$x.DisplayGroup;"
		+ "Direction=[string]$x.Direction;Action=[string]$x.Action;Enabled=[string]$x.Enabled;"
		+ "Protocol=[string]$p.Protocol;LocalPort=@($p.LocalPort);RemoteAddress=@($a.RemoteAddress)"
		+ "}};"
		+ "if($null -eq $o){'[]'}else{$o|ConvertTo-Json -Depth 4 -Compress}}";

	private static readonly TimeSpan ScanTimeout = TimeSpan.FromSeconds(30);

	private readonly ILogger<PowerShellFirewallRuleScanner> _logger;
	private readonly IExternalCommandRunner _runner;
	private readonly IFirewallRuleScanner _netshFallback;

	[SupportedOSPlatform("windows")]
	public PowerShellFirewallRuleScanner(ILogger<PowerShellFirewallRuleScanner> logger, ILogger<NetshFirewallRuleScanner> netshLogger)
		: this(logger, new ExternalCommandRunner(), new NetshFirewallRuleScanner(netshLogger))
	{
	}

	internal PowerShellFirewallRuleScanner(
		ILogger<PowerShellFirewallRuleScanner> logger,
		IExternalCommandRunner runner,
		IFirewallRuleScanner netshFallback)
	{
		ArgumentNullException.ThrowIfNull(logger);
		ArgumentNullException.ThrowIfNull(runner);
		ArgumentNullException.ThrowIfNull(netshFallback);
		_logger = logger;
		_runner = runner;
		_netshFallback = netshFallback;
	}

	/// <inheritdoc/>
	public async Task<FirewallScanResult> ScanRdpAuditBlockRulesAsync(string ruleNamePrefix, CancellationToken ct)
	{
		ArgumentException.ThrowIfNullOrWhiteSpace(ruleNamePrefix);
		ct.ThrowIfCancellationRequested();

		if (!OperatingSystem.IsWindows())
		{
			return new FirewallScanResult(
				Scannable: false,
				Rules: Array.Empty<DiscoveredBlockRule>(),
				Note: "Windows Firewall cannot be live-scanned on a non-Windows host.",
				Backend: FirewallScanBackend.None);
		}

		ExternalCommandResult result;
		try
		{
			result = await _runner.RunDirectAsync(
				commandLabel: "powershell Get-NetFirewallRule (JSON)",
				executable: "powershell.exe",
				arguments: new[]
				{
					"-NoProfile",
					"-NonInteractive",
					"-ExecutionPolicy", "Bypass",
					"-OutputFormat", "Text",
					"-Command", FirewallRulesJsonScript,
				},
				timeout: ScanTimeout,
				ct: ct).ConfigureAwait(false);
		}
		catch (OperationCanceledException)
		{
			throw;
		}
		catch (Exception ex)
		{
			_logger.LogWarning(ex, "PowerShell firewall scan raised an exception; falling back to netsh text scan");
			return await FallBackAsync(ruleNamePrefix, "PowerShell scan threw an exception.", ct).ConfigureAwait(false);
		}

		if (result.TimedOut || result.ExitCode != 0 || string.IsNullOrWhiteSpace(result.StdOut))
		{
			_logger.LogWarning(
				"PowerShell firewall scan unusable (timedOut={TimedOut} exit={Exit} stdoutLen={Len}); falling back to netsh text scan",
				result.TimedOut,
				result.ExitCode,
				result.StdOut?.Length ?? 0);
			return await FallBackAsync(
				ruleNamePrefix,
				"PowerShell scan returned no usable JSON (Get-NetFirewallRule may be unavailable).",
				ct).ConfigureAwait(false);
		}

		IReadOnlyList<DiscoveredBlockRule> rules = PowerShellFirewallRuleParser.DiscoverRdpAuditBlockRules(
			result.StdOut,
			ruleNamePrefix,
			NetshCommandBuilder.RdpAuditGroup);

		_logger.LogInformation(
			"PowerShell firewall scan discovered {Count} RdpAudit block rule(s) (locale-independent JSON read)",
			rules.Count);

		return new FirewallScanResult(
			Scannable: true,
			Rules: rules,
			Note: "Enumerated via Get-NetFirewallRule JSON (locale-independent; matches by name prefix OR group=RdpAudit).",
			Backend: FirewallScanBackend.PowerShellJson);
	}

	private async Task<FirewallScanResult> FallBackAsync(string ruleNamePrefix, string reason, CancellationToken ct)
	{
		FirewallScanResult fallback = await _netshFallback
			.ScanRdpAuditBlockRulesAsync(ruleNamePrefix, ct).ConfigureAwait(false);
		string combinedNote = reason + " " + (fallback.Note ?? "netsh fallback produced no note.");
		return fallback with { Note = combinedNote };
	}
}
