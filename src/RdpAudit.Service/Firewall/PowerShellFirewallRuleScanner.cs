/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 1.4.2
// File   : PowerShellFirewallRuleScanner.cs
// Project: RdpAudit.Service (RdpAudit.Service.Firewall)
// Purpose: Locale-independent IFirewallRuleScanner. Enumerates RdpAudit-owned inbound block rules
//          via Get-NetFirewallRule JSON. Fixed (Bug 3): when the -Group RdpAudit scan returns 0
//          rules (i.e. rules were created by the netsh fallback path and therefore have no group
//          stamp), a secondary name-prefix scan is performed to discover those ungrouped rules so
//          verification does not falsely report Unavailable.
// Depends: IExternalCommandRunner, IFirewallRuleScanner (netsh fallback), NetshCommandBuilder
// Extends: Update FirewallRulesJsonScript and NamePrefixFallbackScript when changing rule schema.

using System.Runtime.Versioning;
using Microsoft.Extensions.Logging;
using RdpAudit.Core.Firewall;
using RdpAudit.Core.Util;

namespace RdpAudit.Service.Firewall;

/// <summary>Locale-independent <see cref="IFirewallRuleScanner"/> backed by
/// <c>Get-NetFirewallRule | ConvertTo-Json</c>. Falls back to the netsh text scanner on failure.</summary>
public sealed class PowerShellFirewallRuleScanner : IFirewallRuleScanner
{
	/// <summary>Primary script: anchored on <c>-Group RdpAudit</c> — locale-independent, preferred.
	/// Returns '[]' when no rules with the RdpAudit group exist (e.g. rules created via netsh fallback).</summary>
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

	/// <summary>FIX Bug 3: secondary name-prefix script used when the group-anchored scan returns 0
	/// rules. Discovers rules created by the netsh fallback path that have no -Group RdpAudit stamp.
	/// The '{0}' placeholder is replaced at runtime with the sanitised rule name prefix
	/// (e.g. 'RdpAudit-Block'). Single-quote doubling is applied before substitution.</summary>
	internal const string NamePrefixFallbackScriptTemplate =
		"$ErrorActionPreference='SilentlyContinue';"
		+ "$r=Get-NetFirewallRule|Where-Object{{$_.Name -like '{0}*'}};"
		+ "if($null -eq $r){{'{{'+'[]'+'}}' }}else{{"
		+ "$o=foreach($x in $r){{"
		+ "$a=$x|Get-NetFirewallAddressFilter -ErrorAction SilentlyContinue;"
		+ "$p=$x|Get-NetFirewallPortFilter -ErrorAction SilentlyContinue;"
		+ "[pscustomobject]@{{"
		+ "Name=$x.Name;DisplayName=$x.DisplayName;Group=$x.Group;DisplayGroup=$x.DisplayGroup;"
		+ "Direction=[string]$x.Direction;Action=[string]$x.Action;Enabled=[string]$x.Enabled;"
		+ "Protocol=[string]$p.Protocol;LocalPort=@($p.LocalPort);RemoteAddress=@($a.RemoteAddress)"
		+ "}}}};"
		+ "if($null -eq $o){{'[]'}}else{{$o|ConvertTo-Json -Depth 4 -Compress}}}}";

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
				commandLabel: "powershell Get-NetFirewallRule -Group RdpAudit (JSON)",
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

		// FIX Bug 3: when the group-anchored scan returns 0 rules, attempt a secondary
		// name-prefix scan. This covers rules created via the netsh fallback path that
		// have no -Group RdpAudit stamp and would otherwise be invisible to verification,
		// causing BlockAsync to return Unavailable even though the OS rule exists.
		if (rules.Count == 0)
		{
			_logger.LogDebug(
				"Group-anchored scan returned 0 rules for prefix={Prefix}; attempting name-prefix fallback scan",
				ruleNamePrefix);

			IReadOnlyList<DiscoveredBlockRule> prefixRules = await TryNamePrefixScanAsync(
				ruleNamePrefix, ct).ConfigureAwait(false);

			if (prefixRules.Count > 0)
			{
				_logger.LogInformation(
					"Name-prefix fallback scan discovered {Count} ungrouped RdpAudit rule(s) for prefix={Prefix} (rules lack -Group stamp; created via netsh fallback)",
					prefixRules.Count,
					ruleNamePrefix);
				return new FirewallScanResult(
					Scannable: true,
					Rules: prefixRules,
					Note: "Discovered via name-prefix fallback (no -Group RdpAudit stamp; rules were likely created by netsh fallback path).",
					Backend: FirewallScanBackend.PowerShellJson);
			}
		}

		_logger.LogInformation(
			"PowerShell firewall scan discovered {Count} RdpAudit block rule(s) (locale-independent JSON read)",
			rules.Count);

		return new FirewallScanResult(
			Scannable: true,
			Rules: rules,
			Note: "Enumerated via Get-NetFirewallRule JSON (locale-independent; matches by name prefix OR group=RdpAudit).",
			Backend: FirewallScanBackend.PowerShellJson);
	}

	/// <summary>FIX Bug 3: performs a secondary <c>Get-NetFirewallRule | Where Name -like 'prefix*'</c>
	/// scan to discover ungrouped rules created by the netsh fallback path. Returns an empty list when
	/// the script fails or times out — the caller then proceeds with the original 0-rule result.</summary>
	private async Task<IReadOnlyList<DiscoveredBlockRule>> TryNamePrefixScanAsync(
		string ruleNamePrefix,
		CancellationToken ct)
	{
		// Sanitise the prefix for safe interpolation into the PS single-quoted literal:
		// single quotes must be doubled so the prefix cannot break out of the string.
		string safePrefixForPs = ruleNamePrefix.Replace("'", "''", StringComparison.Ordinal);
		string script = string.Format(
			System.Globalization.CultureInfo.InvariantCulture,
			"$ErrorActionPreference='SilentlyContinue';"
			+ "$r=Get-NetFirewallRule|Where-Object{{$_.Name -like '{0}*'}};"
			+ "if($null -eq $r){{'[]'}}else{{"
			+ "$o=foreach($x in $r){{"
			+ "$a=$x|Get-NetFirewallAddressFilter -ErrorAction SilentlyContinue;"
			+ "$p=$x|Get-NetFirewallPortFilter -ErrorAction SilentlyContinue;"
			+ "[pscustomobject]@{{"
			+ "Name=$x.Name;DisplayName=$x.DisplayName;Group=$x.Group;DisplayGroup=$x.DisplayGroup;"
			+ "Direction=[string]$x.Direction;Action=[string]$x.Action;Enabled=[string]$x.Enabled;"
			+ "Protocol=[string]$p.Protocol;LocalPort=@($p.LocalPort);RemoteAddress=@($a.RemoteAddress)"
			+ "}}}};"
			+ "if($null -eq $o){{'[]'}}else{{$o|ConvertTo-Json -Depth 4 -Compress}}}}",
			safePrefixForPs);

		try
		{
			ExternalCommandResult prefixResult = await _runner.RunDirectAsync(
				commandLabel: "powershell Get-NetFirewallRule name-prefix fallback (JSON)",
				executable: "powershell.exe",
				arguments: new[]
				{
					"-NoProfile",
					"-NonInteractive",
					"-ExecutionPolicy", "Bypass",
					"-OutputFormat", "Text",
					"-Command", script,
				},
				timeout: ScanTimeout,
				ct: ct).ConfigureAwait(false);

			if (prefixResult.TimedOut || prefixResult.ExitCode != 0 || string.IsNullOrWhiteSpace(prefixResult.StdOut))
			{
				_logger.LogDebug(
					"Name-prefix fallback scan unusable (timedOut={TimedOut} exit={Exit})",
					prefixResult.TimedOut,
					prefixResult.ExitCode);
				return Array.Empty<DiscoveredBlockRule>();
			}

			return PowerShellFirewallRuleParser.DiscoverRdpAuditBlockRules(
				prefixResult.StdOut,
				ruleNamePrefix,
				NetshCommandBuilder.RdpAuditGroup);
		}
		catch (OperationCanceledException)
		{
			throw;
		}
		catch (Exception ex)
		{
			_logger.LogDebug(ex, "Name-prefix fallback scan threw; ignoring");
			return Array.Empty<DiscoveredBlockRule>();
		}
	}

	private async Task<FirewallScanResult> FallBackAsync(string ruleNamePrefix, string reason, CancellationToken ct)
	{
		FirewallScanResult fallback = await _netshFallback
			.ScanRdpAuditBlockRulesAsync(ruleNamePrefix, ct).ConfigureAwait(false);
		string combinedNote = reason + " " + (fallback.Note ?? "netsh fallback produced no note.");
		return fallback with { Note = combinedNote };
	}
}
