// File:    src/RdpAudit.Core/Firewall/EnforcementReconciliation.cs
// Module:  RdpAudit.Core.Firewall
// Purpose: Pure domain model + engine for live enforcement reconciliation. RdpAudit must never
//          claim an IP is actively blocked unless a real backend object exists and matches the
//          expected parameters. This file separates the four states the system actually has —
//          DB intent (blocklist), recorded enforcement (ActiveBlock rows), discovered backend
//          objects (live firewall / route / IPsec scan), and the reconciled effective confidence —
//          and the reconciler that maps them to a single EnforcementStatus + EnforcementConfidence
//          per (provider, ip). The engine is Win32-free and EF-free so it is unit-testable cross
//          platform; the Service layer feeds it pre-read facts (desired blocks + discovered rules).
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using RdpAudit.Core.Config;
using RdpAudit.Core.Ipc.Contracts;

namespace RdpAudit.Core.Firewall;

/// <summary>Reconciled status of one desired/observed block. Append-only enum: never reorder.</summary>
public enum EnforcementStatus
{
	/// <summary>A backend object exists and matches every expected parameter — really enforced.</summary>
	Active = 0,

	/// <summary>The database intends a block but no backend object was discovered for it.</summary>
	MissingRule = 1,

	/// <summary>A backend object exists but one or more parameters differ from the desired block
	/// (wrong port / wrong direction / disabled / wrong action / different remote IP).</summary>
	ParameterMismatch = 2,

	/// <summary>The desired block has expired; enforcement should be (or has been) removed.</summary>
	Expired = 3,

	/// <summary>A backend object exists with no backing database row — an orphan to be cleaned up.</summary>
	OrphanedRule = 4,

	/// <summary>The provider/backend that owns this block is unavailable or not implemented, so its
	/// real state cannot be determined.</summary>
	ProviderUnavailable = 5,

	/// <summary>The backend cannot be live-scanned (e.g. route table enumeration is locale-dependent
	/// or unsupported here); the effective state is unknown.</summary>
	EffectiveUnknown = 6,

	/// <summary>The recorded enforcement attempt failed and no usable backend object exists.</summary>
	Failed = 7,

	/// <summary>The block is desired and pending first enforcement (not yet attempted/confirmed).</summary>
	Desired = 8,
}

/// <summary>How confident RdpAudit is that traffic is actually blocked. Append-only enum.</summary>
public enum EnforcementConfidence
{
	/// <summary>A matching backend object was discovered live; enforcement is verified.</summary>
	Verified = 0,

	/// <summary>A matching object exists but a third-party provider (e.g. Kaspersky) may control or
	/// bypass effective enforcement, so the rule's existence does not guarantee blocking.</summary>
	ExistsButProviderMayBypass = 1,

	/// <summary>No backend object exists for a block the database intends — traffic is not blocked.</summary>
	Missing = 2,

	/// <summary>The recorded enforcement failed; treat as not blocked.</summary>
	Failed = 3,

	/// <summary>State could not be determined (provider unavailable / backend not scannable).</summary>
	Unknown = 4,
}

/// <summary>One block the database intends to enforce, projected from ActiveBlock + Blocklist rows.
/// Pre-read by the Service so the reconciler performs no I/O.</summary>
public sealed record DesiredBlock(
	long ActiveBlockId,
	string Ip,
	FirewallProviderKind Provider,
	FirewallEnforcementBackend Backend,
	string? RuleHandle,
	DateTime CreatedUtc,
	DateTime? ExpiresUtc,
	string Reason,
	bool RecordedFailed);

/// <summary>The discovered live state for a single backend's reconciliation pass. The reconciler is
/// fed one of these per provider; <see cref="Scannable"/> distinguishes "scanned and found nothing"
/// from "could not scan".</summary>
public sealed record BackendScanResult(
	FirewallProviderKind Provider,
	FirewallEnforcementBackend Backend,
	bool ProviderAvailable,
	bool Scannable,
	IReadOnlyList<DiscoveredBlockRule> DiscoveredRules,
	bool ThirdPartyMayBypass,
	string? Note)
{
	/// <summary>Which enumeration backend produced this scan ("PowerShellJson" / "NetshText" /
	/// "None"). Diagnostic-only; flows into <see cref="ReconciliationReport.ScannerBackend"/> for the
	/// Windows provider. Defaults to "None" so existing constructions (route / IPsec / tests) stay
	/// valid without naming it.</summary>
	public string ScannerBackend { get; init; } = "None";
}

/// <summary>One reconciled row: a desired block (or an orphan) with its derived status, confidence,
/// concrete backend object id, and a recommended next action. The Service maps this into a DTO and
/// the diagnostics export.</summary>
public sealed record ReconciledBlock(
	long ActiveBlockId,
	string Ip,
	FirewallProviderKind Provider,
	FirewallEnforcementBackend Backend,
	EnforcementStatus Status,
	EnforcementConfidence Confidence,
	string? EnforcementObjectId,
	DateTime? ExpiresUtc,
	string? Detail,
	string RecommendedAction);

/// <summary>Aggregate reconciliation output: every reconciled desired block plus orphaned backend
/// objects (rules with no backing row) so the operator can clean them up.</summary>
public sealed record ReconciliationReport(
	IReadOnlyList<ReconciledBlock> Blocks,
	IReadOnlyList<ReconciledBlock> Orphans,
	DateTime GeneratedUtc)
{
	/// <summary>Which Windows-firewall enumeration backend produced this report's scan
	/// (PowerShellJson / NetshText / None). Diagnostic-only; defaults to None when no scan ran.</summary>
	public string ScannerBackend { get; init; } = "None";

	/// <summary>Human-readable note from the Windows firewall scan (backend detail / failure cause).</summary>
	public string? ScannerNote { get; init; }

	/// <summary>Count of blocks with verified live enforcement.</summary>
	public int VerifiedCount
	{
		get
		{
			int n = 0;
			foreach (ReconciledBlock b in Blocks)
			{
				if (b.Confidence == EnforcementConfidence.Verified)
				{
					n++;
				}
			}
			return n;
		}
	}

	/// <summary>Count of blocks the database intends but that are not actually enforced.</summary>
	public int UnenforcedCount
	{
		get
		{
			int n = 0;
			foreach (ReconciledBlock b in Blocks)
			{
				if (b.Confidence is EnforcementConfidence.Missing or EnforcementConfidence.Failed)
				{
					n++;
				}
			}
			return n;
		}
	}
}

/// <summary>Pure reconciliation engine. Maps desired blocks + per-backend live scans to a single
/// status/confidence per (provider, ip), and surfaces orphaned RdpAudit rules.</summary>
public static class EnforcementReconciler
{
	/// <summary>Default RdpAudit firewall group name. Kept in Core so the pure reconciler can attribute
	/// group-owned rules without a Service dependency; the Service passes its own
	/// <c>NetshCommandBuilder.RdpAuditGroup</c> (the same literal) explicitly.</summary>
	public const string DefaultGroupName = "RdpAudit";

	/// <summary>Reconciles the supplied desired blocks against the per-provider live scans.</summary>
	/// <param name="desired">DB-intended blocks (ActiveBlock rows that are Active/Pending/Failed).</param>
	/// <param name="scans">One scan result per provider that owns at least one desired block (or that
	/// was scanned to detect orphans). Keyed implicitly by <see cref="BackendScanResult.Provider"/>.</param>
	/// <param name="rulePrefix">The RdpAudit rule-name prefix used to attribute discovered rules.</param>
	/// <param name="nowUtc">Reconciliation instant; expiry is computed against this.</param>
	/// <param name="groupName">The RdpAudit firewall group name used to attribute group-owned rules.</param>
	public static ReconciliationReport Reconcile(
		IReadOnlyList<DesiredBlock> desired,
		IReadOnlyList<BackendScanResult> scans,
		string rulePrefix,
		DateTime nowUtc,
		string groupName = DefaultGroupName)
	{
		ArgumentNullException.ThrowIfNull(desired);
		ArgumentNullException.ThrowIfNull(scans);
		ArgumentException.ThrowIfNullOrWhiteSpace(rulePrefix);
		ArgumentException.ThrowIfNullOrWhiteSpace(groupName);

		Dictionary<FirewallProviderKind, BackendScanResult> scanByProvider = new();
		foreach (BackendScanResult scan in scans)
		{
			scanByProvider[scan.Provider] = scan;
		}

		List<ReconciledBlock> blocks = new();
		// Track which discovered rule names were consumed by a desired block so the remainder are
		// reported as orphans.
		HashSet<string> consumedRuleNames = new(StringComparer.OrdinalIgnoreCase);

		foreach (DesiredBlock d in desired)
		{
			ReconciledBlock reconciled = ReconcileOne(d, scanByProvider, nowUtc, consumedRuleNames, rulePrefix, groupName);
			blocks.Add(reconciled);
		}

		List<ReconciledBlock> orphans = CollectOrphans(scans, consumedRuleNames, nowUtc);

		string scannerBackend = "None";
		string? scannerNote = null;
		if (scanByProvider.TryGetValue(FirewallProviderKind.Windows, out BackendScanResult? windowsScan))
		{
			scannerBackend = windowsScan.ScannerBackend;
			scannerNote = windowsScan.Note;
		}

		return new ReconciliationReport(blocks, orphans, nowUtc)
		{
			ScannerBackend = scannerBackend,
			ScannerNote = scannerNote,
		};
	}

	private static ReconciledBlock ReconcileOne(
		DesiredBlock d,
		Dictionary<FirewallProviderKind, BackendScanResult> scanByProvider,
		DateTime nowUtc,
		HashSet<string> consumedRuleNames,
		string rulePrefix,
		string groupName)
	{
		bool expired = d.ExpiresUtc is { } exp && exp <= nowUtc;

		if (!scanByProvider.TryGetValue(d.Provider, out BackendScanResult? scan))
		{
			// No scan for this provider — we cannot prove enforcement.
			return Build(d, EnforcementStatus.EffectiveUnknown, EnforcementConfidence.Unknown, null,
				"No live scan available for provider " + d.Provider + ".",
				"Run a reconciliation pass on a host where this backend can be scanned.");
		}

		if (!scan.ProviderAvailable)
		{
			return Build(d, EnforcementStatus.ProviderUnavailable, EnforcementConfidence.Unknown, null,
				scan.Note ?? "Provider is unavailable or not implemented.",
				"Restore the provider/backend, then re-reconcile to confirm enforcement.");
		}

		if (!scan.Scannable)
		{
			return Build(d, EnforcementStatus.EffectiveUnknown, EnforcementConfidence.Unknown, null,
				scan.Note ?? "Backend cannot be live-scanned in this environment.",
				"Verify enforcement manually; this backend does not support live enumeration here.");
		}

		// v1.3.9: route ownership/attribution through the pure RdpAuditFirewallRuleMatcher so a desired
		// IP is matched across ALL identity forms (canonical Name, GUID-named with canonical DisplayName,
		// and Group-owned) — not only by a RemoteAddress hit. This closes the gap where a GUID-named rule
		// (Name a GUID, Group empty) was scanned but never attributed, making the tab show MISSING RULE
		// even though a valid RdpAudit-owned block existed. Provider-only scans (route / IPsec) carry no
		// Name/Group/DisplayName, so the matcher falls back to RemoteAddress matching there.
		FirewallRuleMatchResult matchResult =
			RdpAuditFirewallRuleMatcher.MatchDiscovered(scan.DiscoveredRules, d.Ip, rulePrefix, groupName);

		// Pick the concrete discovered rule to verify parameters against: prefer the canonical-named rule
		// the matcher would create on repair, otherwise the first matched rule, ignoring ones already
		// consumed by an earlier desired block so duplicates across IPs are not double-counted.
		DiscoveredBlockRule? match = SelectDiscoveredRule(scan.DiscoveredRules, matchResult, consumedRuleNames);

		if (match is null)
		{
			if (expired)
			{
				return Build(d, EnforcementStatus.Expired, EnforcementConfidence.Missing, null,
					"Block expired and no backend object remains.",
					"No action: expired block is no longer enforced.");
			}

			if (d.RecordedFailed)
			{
				return Build(d, EnforcementStatus.Failed, EnforcementConfidence.Failed, null,
					"Recorded enforcement failed and no backend object exists.",
					"Repair to recreate the missing rule, or remove the block.");
			}

			return Build(d, EnforcementStatus.MissingRule, EnforcementConfidence.Missing, null,
				"Database intends a block but no firewall rule was discovered.",
				"Repair to create the missing rule.");
		}

		consumedRuleNames.Add(match.RuleName);

		// Surface a duplicate / canonicalization recommendation when more than one RdpAudit rule matches
		// the same IP (e.g. the canonical rule AND a GUID-named rule both block 62.176.5.200).
		string duplicateNote = matchResult.HasDuplicates
			? " " + matchResult.Describe() + " Duplicate rule(s) detected; canonicalization recommended."
			: string.Empty;
		string duplicateAction = matchResult.HasDuplicates
			? (matchResult.HasCanonicalRule
				? " A canonical rule already exists; remove the duplicate GUID-named rule(s)."
				: " Repair to create the canonical Name + Group rule, then remove the duplicate(s).")
			: string.Empty;

		// A matching rule exists; verify its parameters.
		string? mismatch = DescribeMismatch(match, d);
		if (mismatch is not null)
		{
			return Build(d, EnforcementStatus.ParameterMismatch,
				scan.ThirdPartyMayBypass ? EnforcementConfidence.ExistsButProviderMayBypass : EnforcementConfidence.Unknown,
				match.RuleName,
				mismatch + duplicateNote,
				"Repair to bring the rule parameters back in line with the desired block." + duplicateAction);
		}

		if (expired)
		{
			// Parameters match but the block should have been removed.
			return Build(d, EnforcementStatus.Expired,
				scan.ThirdPartyMayBypass ? EnforcementConfidence.ExistsButProviderMayBypass : EnforcementConfidence.Verified,
				match.RuleName,
				"Block has expired but the firewall rule still exists." + duplicateNote,
				"Remove enforcement: the rule outlived its expiry." + duplicateAction);
		}

		if (scan.ThirdPartyMayBypass)
		{
			return Build(d, EnforcementStatus.Active, EnforcementConfidence.ExistsButProviderMayBypass, match.RuleName,
				(scan.Note ?? "Windows Firewall rule verified; a third-party provider may control effective enforcement.") + duplicateNote,
				"No action required; confirm the third-party firewall is not bypassing the rule." + duplicateAction);
		}

		return Build(d, EnforcementStatus.Active, EnforcementConfidence.Verified, match.RuleName,
			"Firewall rule verified with matching parameters." + duplicateNote,
			(matchResult.HasDuplicates ? "Canonicalization recommended." + duplicateAction : "No action required."));
	}

	/// <summary>Chooses the concrete <see cref="DiscoveredBlockRule"/> to verify parameters against from
	/// the matcher's per-IP result: prefer the canonical-named rule (matching the name the matcher would
	/// create on repair), otherwise the first matched rule, skipping rules already consumed by an earlier
	/// desired block. Returns null when nothing matched. The matcher matched on identity (Name /
	/// DisplayName / Group); this maps back to the discovered rule that carries the verifiable parameters
	/// (direction / action / enabled / remote IP).</summary>
	private static DiscoveredBlockRule? SelectDiscoveredRule(
		IReadOnlyList<DiscoveredBlockRule> rules,
		FirewallRuleMatchResult matchResult,
		HashSet<string> consumedRuleNames)
	{
		if (!matchResult.RuleExists)
		{
			return null;
		}

		HashSet<string> matchedNames = new(StringComparer.OrdinalIgnoreCase);
		foreach (MatchedFirewallRule m in matchResult.Matches)
		{
			matchedNames.Add(m.RuleName);
		}

		DiscoveredBlockRule? firstUnconsumed = null;
		foreach (DiscoveredBlockRule rule in rules)
		{
			if (!matchedNames.Contains(rule.RuleName) || consumedRuleNames.Contains(rule.RuleName))
			{
				continue;
			}

			// Prefer the canonical-named rule when present.
			if (string.Equals(rule.RuleName, matchResult.CanonicalRuleName, StringComparison.OrdinalIgnoreCase))
			{
				return rule;
			}

			firstUnconsumed ??= rule;
		}

		return firstUnconsumed;
	}

	private static List<ReconciledBlock> CollectOrphans(
		IReadOnlyList<BackendScanResult> scans,
		HashSet<string> consumedRuleNames,
		DateTime nowUtc)
	{
		List<ReconciledBlock> orphans = new();
		foreach (BackendScanResult scan in scans)
		{
			if (!scan.Scannable)
			{
				continue;
			}

			foreach (DiscoveredBlockRule rule in scan.DiscoveredRules)
			{
				if (consumedRuleNames.Contains(rule.RuleName))
				{
					continue;
				}

				string ip = rule.RemoteIps.Count > 0 ? rule.RemoteIps[0] : string.Empty;
				orphans.Add(new ReconciledBlock(
					ActiveBlockId: 0,
					Ip: ip,
					Provider: scan.Provider,
					Backend: scan.Backend,
					Status: EnforcementStatus.OrphanedRule,
					Confidence: EnforcementConfidence.Unknown,
					EnforcementObjectId: rule.RuleName,
					ExpiresUtc: null,
					Detail: "RdpAudit firewall rule exists with no backing database row.",
					RecommendedAction: "Remove the orphaned RdpAudit rule."));
			}
		}

		return orphans;
	}

	/// <summary>Returns a human-readable mismatch description, or null when every parameter matches
	/// the desired block. Direction must be inbound, action must be block, and the rule must be
	/// enabled. A per-IP block whose discovered rule targets "Any" remote address is a mismatch
	/// (it would over-block). Port is only checked when the desired backend is the Windows firewall
	/// and the rule declares an explicit local port.</summary>
	internal static string? DescribeMismatch(DiscoveredBlockRule rule, DesiredBlock desired)
	{
		if (!rule.Enabled)
		{
			return "Rule is disabled.";
		}

		if (!rule.DirectionInbound)
		{
			return "Rule direction is not inbound.";
		}

		if (!rule.ActionBlock)
		{
			return "Rule action is not block.";
		}

		bool targetsAny = false;
		foreach (string ip in rule.RemoteIps)
		{
			if (string.Equals(ip, "Any", StringComparison.OrdinalIgnoreCase))
			{
				targetsAny = true;
				break;
			}
		}

		if (targetsAny)
		{
			return "Rule blocks Any remote address instead of the single desired IP.";
		}

		return null;
	}

	private static ReconciledBlock Build(
		DesiredBlock d,
		EnforcementStatus status,
		EnforcementConfidence confidence,
		string? objectId,
		string detail,
		string recommendedAction)
	{
		return new ReconciledBlock(
			ActiveBlockId: d.ActiveBlockId,
			Ip: d.Ip,
			Provider: d.Provider,
			Backend: d.Backend,
			Status: status,
			Confidence: confidence,
			EnforcementObjectId: objectId,
			ExpiresUtc: d.ExpiresUtc,
			Detail: detail,
			RecommendedAction: recommendedAction);
	}

	/// <summary>Stable English label for an <see cref="EnforcementStatus"/>.</summary>
	public static string DescribeStatus(EnforcementStatus status) => status switch
	{
		EnforcementStatus.Active => "Active",
		EnforcementStatus.MissingRule => "MissingRule",
		EnforcementStatus.ParameterMismatch => "ParameterMismatch",
		EnforcementStatus.Expired => "Expired",
		EnforcementStatus.OrphanedRule => "OrphanedRule",
		EnforcementStatus.ProviderUnavailable => "ProviderUnavailable",
		EnforcementStatus.EffectiveUnknown => "EffectiveUnknown",
		EnforcementStatus.Failed => "Failed",
		EnforcementStatus.Desired => "Desired",
		_ => status.ToString(),
	};

	/// <summary>Stable English label for an <see cref="EnforcementConfidence"/>.</summary>
	public static string DescribeConfidence(EnforcementConfidence confidence) => confidence switch
	{
		EnforcementConfidence.Verified => "Verified",
		EnforcementConfidence.ExistsButProviderMayBypass => "ExistsButProviderMayBypass",
		EnforcementConfidence.Missing => "Missing",
		EnforcementConfidence.Failed => "Failed",
		EnforcementConfidence.Unknown => "Unknown",
		_ => confidence.ToString(),
	};

	/// <summary>Derives overall firewall enforcement health from reconciliation counts. Pure for testing.</summary>
	/// <param name="enabledBlocklistRows">Count of enabled blocklist rows (enforcement that should exist).</param>
	/// <param name="verifiedEnforced">Count of blocks with verified live enforcement.</param>
	/// <param name="unenforced">Count of blocks the DB intends but reconciliation could not verify.</param>
	public static FirewallEnforcementHealth DeriveHealth(int enabledBlocklistRows, int verifiedEnforced, int unenforced)
	{
		if (enabledBlocklistRows <= 0)
		{
			return FirewallEnforcementHealth.Idle;
		}

		// Enabled rows exist but nothing is verified and nothing is even partially enforced: a missing rule.
		if (verifiedEnforced <= 0)
		{
			return FirewallEnforcementHealth.MissingRule;
		}

		// Some verified, but some intended blocks remain unenforced: partial / failed enforcement.
		if (unenforced > 0)
		{
			return FirewallEnforcementHealth.Failed;
		}

		return FirewallEnforcementHealth.Healthy;
	}

	/// <summary>Operator-facing description plus recommended action for an enforcement health value.</summary>
	public static string DescribeHealth(FirewallEnforcementHealth health, int enabledBlocklistRows, int verifiedEnforced) => health switch
	{
		FirewallEnforcementHealth.Idle =>
			"No enabled blocklist rows; firewall enforcement is idle.",
		FirewallEnforcementHealth.Healthy =>
			$"Enforcement healthy: {verifiedEnforced} of {enabledBlocklistRows} enabled block(s) verified in the firewall.",
		FirewallEnforcementHealth.MissingRule =>
			$"MISSING RULE: {enabledBlocklistRows} enabled block(s) exist but no RdpAudit firewall rule was verified. "
			+ "Use 'Repair selected' on the Active blocks tab to create the missing rules, then 'Verify all'.",
		FirewallEnforcementHealth.Failed =>
			$"ENFORCEMENT INCOMPLETE: only {verifiedEnforced} of {enabledBlocklistRows} enabled block(s) verified. "
			+ "Use 'Repair selected' on the unenforced entries, then 'Verify all'.",
		FirewallEnforcementHealth.Unknown =>
			"Enforcement state could not be verified (reconciliation unavailable). Use 'Verify all'.",
		_ => "Firewall status unknown.",
	};
}
