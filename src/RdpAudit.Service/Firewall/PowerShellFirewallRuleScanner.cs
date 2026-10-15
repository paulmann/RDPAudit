/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 2.1.0
// File   : PowerShellFirewallRuleScanner.cs
// Project: RdpAudit.Service (RdpAudit.Service.Firewall)
// Purpose: Locale-independent IFirewallRuleScanner. Enumerates RdpAudit-owned inbound block rules
//          via Get-NetFirewallRule JSON. Fixed (Bug 3): when the -Group RdpAudit scan returns 0
//          rules (i.e. rules were created by the netsh fallback path and therefore have no group
//          stamp), a secondary name-prefix scan is performed to discover those ungrouped rules so
//          verification does not falsely report Unavailable.
//
//          v2.1.0 PowerShell scan latch: after the FIRST failed / timed-out PowerShell probe the
//          scanner latches onto the netsh text fallback. While latched, every per-tick scan is
//          served by netsh and PowerShell is re-probed AT MOST ONCE per configured interval
//          (FirewallOptions.PowerShellRetryProbeIntervalMinutes, default 15 minutes) - a broken
//          PowerShell host can no longer be spawned on every reconciliation tick. The hard probe
//          timeout is configurable via FirewallOptions.PowerShellScanTimeoutSeconds (default 30s;
//          values below 1 are treated as the default). Both options are read live through
//          IOptionsMonitor<RdpAuditOptions> so appsettings.json hot-reload applies without restart.
//          The current backend and the latch switch count are published to ServiceMetrics
//          (surfaced via IPC GetStatus) through the injected Action<FirewallScanBackend?> sink.
//          Lock-free state: the retry slot is claimed via Interlocked.CompareExchange, so
//          concurrent reconciliation / cleanup callers can never both spawn PowerShell inside
//          one interval.
// Depends: IExternalCommandRunner, IFirewallRuleScanner (netsh fallback), NetshCommandBuilder,
//          IOptionsMonitor<RdpAuditOptions>, TimeProvider, PowerShellProbeLatch
// Extends: Update FirewallRulesJsonScript and NamePrefixFallbackScript when changing rule schema.

using System.Runtime.Versioning;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using RdpAudit.Core.Config;
using RdpAudit.Core.Firewall;
using RdpAudit.Core.Util;

namespace RdpAudit.Service.Firewall;

/// <summary>Locale-independent <see cref="IFirewallRuleScanner"/> backed by
/// <c>Get-NetFirewallRule | ConvertTo-Json</c>. On the first failure it latches onto the netsh text
/// scanner and re-probes PowerShell at most once per configured interval.</summary>
public sealed class PowerShellFirewallRuleScanner : IFirewallRuleScanner
{
	/// <summary>Primary script: anchored on <c>-Group RdpAudit</c> - locale-independent, preferred.
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

	/// <summary>Fallback constants: the configured defaults already live on FirewallOptions; these
	/// mirror them for defensive use when a clamped value must be resolved locally.</summary>
	internal const int DefaultScanTimeoutSeconds = 30;
	internal const int DefaultRetryProbeIntervalMinutes = 15;

	private readonly ILogger<PowerShellFirewallRuleScanner> _logger;
	private readonly IExternalCommandRunner _runner;
	private readonly IFirewallRuleScanner _netshFallback;
	private readonly IOptionsMonitor<RdpAuditOptions>? _options;
	private readonly PowerShellProbeLatch _latch;
	private readonly Action<FirewallScanBackend?>? _reportBackend;
	private readonly Func<bool> _isWindows;

	/// <summary>Production constructor - keeps the historic two-logger surface intact for
	/// Program.cs callers. Wires the real <see cref="ExternalCommandRunner"/>, the netsh fallback,
	/// a system-clock latch, and no metrics sink (back-compatible).</summary>
	[SupportedOSPlatform("windows")]
	public PowerShellFirewallRuleScanner(ILogger<PowerShellFirewallRuleScanner> logger, ILogger<NetshFirewallRuleScanner> netshLogger)
		: this(
			logger,
			new ExternalCommandRunner(),
			new NetshFirewallRuleScanner(netshLogger),
			options: null,
			latch: new PowerShellProbeLatch(TimeProvider.System),
			reportBackend: null)
	{
	}

	/// <summary>Full test / DI constructor. <paramref name="options"/> is optional (defaults used
	/// when null), matching the optional-dependency pattern of other v2.1.x processors.</summary>
	internal PowerShellFirewallRuleScanner(
		ILogger<PowerShellFirewallRuleScanner> logger,
		IExternalCommandRunner runner,
		IFirewallRuleScanner netshFallback,
		IOptionsMonitor<RdpAuditOptions>? options = null,
		PowerShellProbeLatch? latch = null,
		TimeProvider? time = null,
		Action<FirewallScanBackend?>? reportBackend = null,
		Func<bool>? isWindows = null)
	{
		ArgumentNullException.ThrowIfNull(logger);
		ArgumentNullException.ThrowIfNull(runner);
		ArgumentNullException.ThrowIfNull(netshFallback);
		_logger = logger;
		_runner = runner;
		_netshFallback = netshFallback;
		_options = options;
		_latch = latch ?? new PowerShellProbeLatch(time ?? TimeProvider.System);
		_reportBackend = reportBackend;
		_isWindows = isWindows ?? OperatingSystem.IsWindows;
	}

	/// <inheritdoc/>
	public async Task<FirewallScanResult> ScanRdpAuditBlockRulesAsync(string ruleNamePrefix, CancellationToken ct)
	{
		ArgumentException.ThrowIfNullOrWhiteSpace(ruleNamePrefix);
		ct.ThrowIfCancellationRequested();

		if (!_isWindows())
		{
			return new FirewallScanResult(
				Scannable: false,
				Rules: Array.Empty<DiscoveredBlockRule>(),
				Note: "Windows Firewall cannot be live-scanned on a non-Windows host.",
				Backend: FirewallScanBackend.None);
		}

		TimeSpan probeTimeout = ResolveScanTimeout();
		TimeSpan retryInterval = ResolveRetryInterval();
		PowerShellProbeAction action = _latch.DecidePowerShellProbe(retryInterval);

		if (action == PowerShellProbeAction.UseFallback)
		{
			ReportBackend(FirewallScanBackend.NetshText);
			return await FallBackAsync(
				ruleNamePrefix,
				"PowerShell probe is latched (retry interval has not elapsed); served from netsh without spawning PowerShell.",
				ct).ConfigureAwait(false);
		}

		if (action == PowerShellProbeAction.ProbeAfterLatch)
		{
			_logger.LogDebug(
				"PowerShell re-probe window elapsed; claiming the single retry slot (retryInterval={Interval} min)",
				retryInterval.TotalMinutes);
		}

		FirewallScanResult? probeResult = await TryPowerShellScanAsync(ruleNamePrefix, probeTimeout, ct).ConfigureAwait(false);
		if (probeResult is not null)
		{
			if (action == PowerShellProbeAction.ProbeAfterLatch)
			{
				_latch.OnProbeSuccess();
				ReportBackend(FirewallScanBackend.PowerShellJson);
				_logger.LogInformation("PowerShell re-probe succeeded; latch released");
			}
			else
			{
				ReportBackend(FirewallScanBackend.PowerShellJson);
			}

			return probeResult;
		}

		// Probe failed: arm the latch and serve netsh for this call.
		_latch.OnProbeFailure(retryInterval);
		ReportBackend(FirewallScanBackend.NetshText);
		return await FallBackAsync(ruleNamePrefix, "PowerShell scan failed or timed out.", ct).ConfigureAwait(false);
	}

	/// <summary>Runs the PowerShell probe (group-anchored scan plus the Bug-3 name-prefix fallback)
	/// and returns the scan result, or null when PowerShell is unusable. Never throws except for
	/// external cancellation.</summary>
	private async Task<FirewallScanResult?> TryPowerShellScanAsync(
		string ruleNamePrefix,
		TimeSpan probeTimeout,
		CancellationToken ct)
	{
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
				timeout: probeTimeout,
				ct: ct).ConfigureAwait(false);
		}
		catch (OperationCanceledException)
		{
			throw;
		}
		catch (Exception ex)
		{
			_logger.LogWarning(ex, "PowerShell firewall scan raised an exception; latching onto netsh text scan");
			return null;
		}

		if (result.TimedOut || result.ExitCode != 0 || string.IsNullOrWhiteSpace(result.StdOut))
		{
			_logger.LogWarning(
				"PowerShell firewall scan unusable (timedOut={TimedOut} exit={Exit} stdoutLen={Len}); latching onto netsh text scan",
				result.TimedOut,
				result.ExitCode,
				result.StdOut?.Length ?? 0);
			return null;
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
				ruleNamePrefix, probeTimeout, ct).ConfigureAwait(false);

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
	/// the script fails or times out - the caller then proceeds with the original 0-rule result.</summary>
	private async Task<IReadOnlyList<DiscoveredBlockRule>> TryNamePrefixScanAsync(
		string ruleNamePrefix,
		TimeSpan probeTimeout,
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
				timeout: probeTimeout,
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

	/// <summary>Reads <c>Firewall.PowerShellScanTimeoutSeconds</c> live through IOptionsMonitor;
	/// missing options or values below 1 fall back to the 30-second default.</summary>
	private TimeSpan ResolveScanTimeout()
	{
		int seconds = _options?.CurrentValue.Firewall.PowerShellScanTimeoutSeconds ?? 0;
		if (seconds < 1)
		{
			seconds = DefaultScanTimeoutSeconds;
		}

		return TimeSpan.FromSeconds(seconds);
	}

	/// <summary>Reads <c>Firewall.PowerShellRetryProbeIntervalMinutes</c> live through IOptionsMonitor;
	/// missing options or values below 1 fall back to the 15-minute default.</summary>
	private TimeSpan ResolveRetryInterval()
	{
		int minutes = _options?.CurrentValue.Firewall.PowerShellRetryProbeIntervalMinutes ?? 0;
		if (minutes < 1)
		{
			minutes = DefaultRetryProbeIntervalMinutes;
		}

		return TimeSpan.FromMinutes(minutes);
	}

	/// <summary>Publishes the backend that produced a scan through the optional metrics sink.
	/// Null sink (tests / legacy ctor) makes this a safe no-op.</summary>
	private void ReportBackend(FirewallScanBackend? backend) => _reportBackend?.Invoke(backend);
}
