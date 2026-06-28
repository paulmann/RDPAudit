// File:    src/RdpAudit.Core/Config/FirewallOptions.cs
// Module:  RdpAudit.Core.Config
// Purpose: Settings for automatic firewall blocking on threat thresholds, provider selection,
//          static whitelist / blacklist arrays, and instant-block triggers.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com
// Version: 1.4.2

namespace RdpAudit.Core.Config;

/// <summary>Settings for automatic firewall blocking, provider selection, and static address lists.</summary>
/// <remarks>
/// Backward-compatible: pre-Stage-1 callers used only <see cref="AutoBlockBruteForce"/>,
/// <see cref="AutoBlockThreshold"/>, and <see cref="BlockRuleName"/>. New fields have safe defaults
/// so existing appsettings.json documents continue to bind.
/// </remarks>
public sealed class FirewallOptions
{
	/// <summary>Enables the brute-force-driven auto-block worker.</summary>
	public bool AutoBlockBruteForce { get; set; }

	/// <summary>Threshold of recent failures from a single IP that triggers an auto-block.</summary>
	public int AutoBlockThreshold { get; set; } = 50;

	/// <summary>Base name used to construct per-IP firewall rule names.</summary>
	public string BlockRuleName { get; set; } = "RdpAudit-Block";

	/// <summary>Selected firewall provider; defaults to Windows for backward compatibility.</summary>
	public FirewallProviderKind Provider { get; set; } = FirewallProviderKind.Windows;

	/// <summary>Static whitelist of CIDR / IP entries that must NEVER be auto-blocked.</summary>
	public List<string> Whitelist { get; set; } = new();

	/// <summary>Static blacklist of CIDR / IP entries that must always be considered hostile.</summary>
	public List<string> Blacklist { get; set; } = new();

	/// <summary>When true, a successful logon from a blacklisted address triggers an immediate block.</summary>
	public bool BlockOnBlacklistedLogin { get; set; }

	/// <summary>User names that, when seen in a successful logon, trigger an immediate block of the source IP.</summary>
	/// <remarks>Common values include disabled / honeypot accounts (e.g. "guest", "test", "admin").</remarks>
	public List<string> InstantBlockLogins { get; set; } = new();

	/// <summary>Default block duration in minutes; zero or negative means permanent until manually removed.</summary>
	/// <remarks>Defaults to 4320 minutes (3 days) so that auto-blocks and manually added blocks expire automatically unless explicitly overridden.</remarks>
	public int DefaultBlockDurationMinutes { get; set; } = 4320;

	/// <summary>Maximum number of distinct simultaneous block rules the provider is allowed to create.</summary>
	/// <remarks>Acts as a guardrail against rule-table flooding from a runaway worker or scripted attack.</remarks>
	public int MaxActiveBlocks { get; set; } = 10000;

	/// <summary>Static IP list consumed by the auto-block worker as an additional whitelist surface.</summary>
	/// <remarks>
	/// Flat list of literal addresses; CIDR matching belongs to <see cref="Whitelist"/>.
	/// Defaults are empty so deployments retain Stage 1 behaviour until an operator opts in.
	/// </remarks>
	public List<string> WhitelistIps { get; set; } = new();

	/// <summary>When true, the Windows provider refuses to block loopback / private / multicast addresses.</summary>
	/// <remarks>
	/// Default is true: blocking loopback or RFC1918 ranges on the host firewall can lock the
	/// operator out of their own network and is almost never the intent of an automatic rule.
	/// Set to <c>false</c> only with full understanding of the consequences.
	/// </remarks>
	public bool RefusePrivateAddressBlock { get; set; } = true;

	/// <summary>Debounce window in seconds applied per IP / provider to avoid auto-block storms.</summary>
	/// <remarks>
	/// When a block is already active for an IP the auto-block worker waits this long before
	/// considering the same IP again. Defaults to 60 seconds; lower values risk thrashing.
	/// </remarks>
	public int AutoBlockDebounceSeconds { get; set; } = 60;

	/// <summary>Scope of the inbound block rule: RDP listener port only, or all inbound traffic.</summary>
	/// <remarks>
	/// Defaults to <see cref="FirewallBlockScope.AllInbound"/>: a host actively under brute-force
	/// rarely has a legitimate reason to accept any other inbound traffic from the attacker IP, and
	/// blocking only the RDP port leaves lateral-movement surface open. Operators who run other
	/// services to/from the same source can switch to <see cref="FirewallBlockScope.RdpPortOnly"/>.
	/// When <see cref="FirewallBlockScope.RdpPortOnly"/> is selected the rule's remote/local port is
	/// the resolved RDP listener port (never a hardcoded 3389).
	/// </remarks>
	public FirewallBlockScope BlockScope { get; set; } = FirewallBlockScope.AllInbound;

	/// <summary>Selected enforcement backend used to realise a block beyond the DB blocklist row.</summary>
	/// <remarks>
	/// Orthogonal to <see cref="Provider"/> (which selects Windows / MikroTik / Both): the backend
	/// selects <em>how</em> the local Windows host enforces a block. Defaults to
	/// <see cref="FirewallEnforcementBackend.WindowsFirewall"/> for backward compatibility.
	/// </remarks>
	public FirewallEnforcementBackend EnforcementBackend { get; set; } = FirewallEnforcementBackend.WindowsFirewall;

	/// <summary>After installing a block rule, re-query the firewall to confirm the rule exists.</summary>
	/// <remarks>
	/// Defaults to true: the operator-reported failure mode is "blocklist row exists but no rule was
	/// created". Verification turns a silent failure into a <c>Failed</c> ActiveBlock with an
	/// actionable message instead of a falsely-<c>Active</c> row.
	/// </remarks>
	public bool VerifyAfterBlock { get; set; } = true;

	/// <summary>Blackhole gateway IP used by the experimental route-blackhole enforcement backend.</summary>
	/// <remarks>
	/// The route-blackhole backend adds a per-IP host route pointing the attacker IP at an
	/// unreachable next-hop so outbound replies are dropped. The suggested default
	/// <c>10.255.255.254</c> is a documented placeholder; the backend MUST verify the gateway is
	/// genuinely unreachable on the host before relying on it and the operator can change it.
	/// </remarks>
	public string RouteBlackholeGateway { get; set; } = "10.255.255.254";

	/// <summary>Interval in seconds between live enforcement reconciliation passes; zero or negative
	/// disables the background reconciliation worker.</summary>
	/// <remarks>
	/// The reconciliation worker periodically scans the real firewall and compares it against the
	/// database-intended blocks so RdpAudit never silently claims an IP is blocked when no backend
	/// object exists. Defaults to 300 seconds (5 minutes); a row whose enforcement is found missing or
	/// failed is demoted to <c>Failed</c> so the operator (and the Active Blocks view) sees the truth.
	/// </remarks>
	public int ReconciliationIntervalSeconds { get; set; } = 300;
}
