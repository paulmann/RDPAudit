// File:    src/RdpAudit.Service/Firewall/IFirewallRuleScanner.cs
// Module:  RdpAudit.Service.Firewall
// Purpose: Live-scan abstraction for enforcement reconciliation. Enumerates the RdpAudit-owned
//          inbound block rules that actually exist in the Windows Advanced Firewall store (via a
//          single `netsh advfirewall firewall show rule name=all verbose` pass parsed by the pure
//          NetshRuleScanner) so the reconciler can compare real backend objects against the
//          database-intended blocks. The Windows implementation only runs on Windows; a no-op
//          implementation returns an unscannable result on other hosts so the reconciler reports
//          EffectiveUnknown instead of falsely claiming enforcement. Tests substitute an in-memory
//          scanner that returns canned DiscoveredBlockRule lists.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System.Runtime.Versioning;
using Microsoft.Extensions.Logging;
using RdpAudit.Core.Firewall;

namespace RdpAudit.Service.Firewall;

/// <summary>Which enumeration backend produced a <see cref="FirewallScanResult"/>. Surfaced in
/// diagnostics so the operator can tell a locale-independent PowerShell read from the legacy
/// English-text netsh parse (which silently returns zero rules on a localized host).</summary>
public enum FirewallScanBackend
{
	/// <summary>No scan was attempted (non-Windows host).</summary>
	None = 0,

	/// <summary>`Get-NetFirewallRule | ConvertTo-Json` — locale-independent, preferred.</summary>
	PowerShellJson = 1,

	/// <summary>`netsh advfirewall firewall show rule name=all verbose` text parse — locale-fragile
	/// fallback used only when the PowerShell path is unavailable or fails.</summary>
	NetshText = 2,
}

/// <summary>Outcome of a single live firewall scan for RdpAudit-owned block rules.</summary>
/// <param name="Scannable">False when the backend cannot be enumerated here (non-Windows, or every
/// backend failed); the reconciler maps this to EffectiveUnknown rather than MissingRule.</param>
/// <param name="Rules">Discovered RdpAudit-owned inbound block rules (empty when scannable but none
/// exist).</param>
/// <param name="Note">Optional human-readable note (failure cause / environment detail).</param>
/// <param name="Backend">Which enumeration backend produced this result.</param>
public sealed record FirewallScanResult(
	bool Scannable,
	IReadOnlyList<DiscoveredBlockRule> Rules,
	string? Note,
	FirewallScanBackend Backend = FirewallScanBackend.None);

/// <summary>Enumerates RdpAudit-owned firewall block rules that really exist in the local store.</summary>
public interface IFirewallRuleScanner
{
	/// <summary>Scans the local Windows Firewall for inbound block rules whose name carries
	/// <paramref name="ruleNamePrefix"/>. Returns an unscannable result on non-Windows hosts.</summary>
	Task<FirewallScanResult> ScanRdpAuditBlockRulesAsync(string ruleNamePrefix, CancellationToken ct);
}

/// <summary>Default <see cref="IFirewallRuleScanner"/> backed by <c>netsh advfirewall firewall show
/// rule name=all verbose</c> parsed by <see cref="NetshRuleScanner"/>. Only enumerates on Windows;
/// elsewhere it returns an unscannable result so reconciliation never fabricates enforcement.</summary>
public sealed class NetshFirewallRuleScanner : IFirewallRuleScanner
{
	private readonly ILogger<NetshFirewallRuleScanner> _logger;
	private readonly INetshRunner _runner;

	[SupportedOSPlatform("windows")]
	public NetshFirewallRuleScanner(ILogger<NetshFirewallRuleScanner> logger)
		: this(logger, new NetshRunner())
	{
	}

	internal NetshFirewallRuleScanner(ILogger<NetshFirewallRuleScanner> logger, INetshRunner runner)
	{
		ArgumentNullException.ThrowIfNull(logger);
		ArgumentNullException.ThrowIfNull(runner);
		_logger = logger;
		_runner = runner;
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

		NetshResult result;
		try
		{
			result = await _runner.RunAsync(NetshCommandBuilder.BuildShowAllRulesArgs(), ct).ConfigureAwait(false);
		}
		catch (OperationCanceledException)
		{
			throw;
		}
		catch (Exception ex)
		{
			_logger.LogWarning(ex, "Live firewall scan failed: netsh show rule name=all raised an exception");
			return new FirewallScanResult(
				Scannable: false,
				Rules: Array.Empty<DiscoveredBlockRule>(),
				Note: "netsh show rule name=all failed to execute.",
				Backend: FirewallScanBackend.NetshText);
		}

		if (!result.Success)
		{
			_logger.LogWarning("Live firewall scan returned exit={Exit}", result.ExitCode);
			return new FirewallScanResult(
				Scannable: false,
				Rules: Array.Empty<DiscoveredBlockRule>(),
				Note: "netsh show rule name=all returned a non-zero exit code.",
				Backend: FirewallScanBackend.NetshText);
		}

		IReadOnlyList<DiscoveredBlockRule> rules =
			NetshRuleScanner.DiscoverRdpAuditBlockRules(result.StdOut, ruleNamePrefix);
		return new FirewallScanResult(
			Scannable: true,
			Rules: rules,
			Note: "Enumerated via netsh verbose text parse (locale-fragile; rule labels are "
				+ "translated on non-English hosts and may yield zero matches).",
			Backend: FirewallScanBackend.NetshText);
	}
}

/// <summary>No-op <see cref="IFirewallRuleScanner"/> for non-Windows hosts. Always returns an
/// unscannable result so the reconciler reports EffectiveUnknown instead of fabricating a verified
/// or missing enforcement state on a platform where the Windows Firewall does not exist.</summary>
public sealed class UnsupportedFirewallRuleScanner : IFirewallRuleScanner
{
	/// <inheritdoc/>
	public Task<FirewallScanResult> ScanRdpAuditBlockRulesAsync(string ruleNamePrefix, CancellationToken ct)
	{
		ArgumentException.ThrowIfNullOrWhiteSpace(ruleNamePrefix);
		ct.ThrowIfCancellationRequested();
		return Task.FromResult(new FirewallScanResult(
			Scannable: false,
			Rules: Array.Empty<DiscoveredBlockRule>(),
			Note: "Windows Firewall live scan is not supported on this host.",
			Backend: FirewallScanBackend.None));
	}
}
