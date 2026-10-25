// File:    tests/RdpAudit.Core.Tests/EnforcementReconcilerTests.cs
// Module:  RdpAudit.Core.Tests
// Purpose: Exercises the pure enforcement-reconciliation engine across every status/confidence the
//          system can derive: Verified, MissingRule, ParameterMismatch, ExistsButProviderMayBypass,
//          expired-removal, Failed, ProviderUnavailable, EffectiveUnknown, and orphaned-rule
//          detection. These guard the core guarantee that RdpAudit never reports an IP as Active
//          unless a matching backend object was discovered live.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using RdpAudit.Core.Config;
using RdpAudit.Core.Firewall;
using Xunit;

namespace RdpAudit.Core.Tests;

/// <summary>Reconciliation engine scenarios mapping desired blocks + live scans to status/confidence.</summary>
public class EnforcementReconcilerTests
{
	private const string Prefix = "RdpAudit-Block";
	private static readonly DateTime Now = new(2026, 6, 8, 12, 0, 0, DateTimeKind.Utc);

	private static DesiredBlock Desired(
		string ip,
		DateTime? expires = null,
		bool recordedFailed = false,
		FirewallProviderKind provider = FirewallProviderKind.Windows) =>
		new(
			ActiveBlockId: 1,
			Ip: ip,
			Provider: provider,
			Backend: FirewallEnforcementBackend.WindowsFirewall,
			RuleHandle: null,
			CreatedUtc: Now.AddHours(-1),
			ExpiresUtc: expires,
			Reason: "test",
			RecordedFailed: recordedFailed);

	private static DiscoveredBlockRule Rule(
		string ip,
		bool enabled = true,
		bool inbound = true,
		bool block = true,
		string? name = null) =>
		new(
			RuleName: name ?? Prefix + "-" + ip,
			Enabled: enabled,
			DirectionInbound: inbound,
			ActionBlock: block,
			Protocol: "TCP",
			LocalPorts: new[] { 3389 },
			RemoteIps: new[] { ip });

	private static BackendScanResult WindowsScan(
		IReadOnlyList<DiscoveredBlockRule> rules,
		bool available = true,
		bool scannable = true,
		bool thirdParty = false,
		string? note = null) =>
		new(
			Provider: FirewallProviderKind.Windows,
			Backend: FirewallEnforcementBackend.WindowsFirewall,
			ProviderAvailable: available,
			Scannable: scannable,
			DiscoveredRules: rules,
			ThirdPartyMayBypass: thirdParty,
			Note: note);

	[Fact]
	public void MatchingRule_YieldsActiveVerified()
	{
		ReconciliationReport report = EnforcementReconciler.Reconcile(
			new[] { Desired("203.0.113.10") },
			new[] { WindowsScan(new[] { Rule("203.0.113.10") }) },
			Prefix,
			Now);

		ReconciledBlock block = Assert.Single(report.Blocks);
		Assert.Equal(EnforcementStatus.Active, block.Status);
		Assert.Equal(EnforcementConfidence.Verified, block.Confidence);
		Assert.Equal(1, report.VerifiedCount);
		Assert.Equal(0, report.UnenforcedCount);
		Assert.Empty(report.Orphans);
	}

	[Fact]
	public void DesiredButNoRule_YieldsMissingRule()
	{
		ReconciliationReport report = EnforcementReconciler.Reconcile(
			new[] { Desired("203.0.113.10") },
			new[] { WindowsScan(Array.Empty<DiscoveredBlockRule>()) },
			Prefix,
			Now);

		ReconciledBlock block = Assert.Single(report.Blocks);
		Assert.Equal(EnforcementStatus.MissingRule, block.Status);
		Assert.Equal(EnforcementConfidence.Missing, block.Confidence);
		Assert.Equal(1, report.UnenforcedCount);
	}

	[Fact]
	public void RecordedFailedAndNoRule_YieldsFailed()
	{
		ReconciliationReport report = EnforcementReconciler.Reconcile(
			new[] { Desired("203.0.113.10", recordedFailed: true) },
			new[] { WindowsScan(Array.Empty<DiscoveredBlockRule>()) },
			Prefix,
			Now);

		ReconciledBlock block = Assert.Single(report.Blocks);
		Assert.Equal(EnforcementStatus.Failed, block.Status);
		Assert.Equal(EnforcementConfidence.Failed, block.Confidence);
		Assert.Equal(1, report.UnenforcedCount);
	}

	[Fact]
	public void DisabledRule_YieldsParameterMismatch()
	{
		ReconciliationReport report = EnforcementReconciler.Reconcile(
			new[] { Desired("203.0.113.10") },
			new[] { WindowsScan(new[] { Rule("203.0.113.10", enabled: false) }) },
			Prefix,
			Now);

		ReconciledBlock block = Assert.Single(report.Blocks);
		Assert.Equal(EnforcementStatus.ParameterMismatch, block.Status);
		Assert.Contains("disabled", block.Detail, StringComparison.OrdinalIgnoreCase);
	}

	[Fact]
	public void OutboundRule_YieldsParameterMismatch()
	{
		ReconciliationReport report = EnforcementReconciler.Reconcile(
			new[] { Desired("203.0.113.10") },
			new[] { WindowsScan(new[] { Rule("203.0.113.10", inbound: false) }) },
			Prefix,
			Now);

		Assert.Equal(EnforcementStatus.ParameterMismatch, Assert.Single(report.Blocks).Status);
	}

	[Fact]
	public void AllowActionRule_YieldsParameterMismatch()
	{
		ReconciliationReport report = EnforcementReconciler.Reconcile(
			new[] { Desired("203.0.113.10") },
			new[] { WindowsScan(new[] { Rule("203.0.113.10", block: false) }) },
			Prefix,
			Now);

		Assert.Equal(EnforcementStatus.ParameterMismatch, Assert.Single(report.Blocks).Status);
	}

	[Fact]
	public void RuleTargetingAny_YieldsParameterMismatch()
	{
		DiscoveredBlockRule any = new(
			RuleName: Prefix + "-any",
			Enabled: true,
			DirectionInbound: true,
			ActionBlock: true,
			Protocol: "TCP",
			LocalPorts: new[] { 3389 },
			RemoteIps: new[] { "Any" });

		ReconciliationReport report = EnforcementReconciler.Reconcile(
			new[] { Desired("Any") },
			new[] { WindowsScan(new[] { any }) },
			Prefix,
			Now);

		ReconciledBlock block = Assert.Single(report.Blocks);
		Assert.Equal(EnforcementStatus.ParameterMismatch, block.Status);
		Assert.Contains("Any", block.Detail, StringComparison.Ordinal);
	}

	[Fact]
	public void ThirdPartyBypass_YieldsActiveButProviderMayBypass()
	{
		ReconciliationReport report = EnforcementReconciler.Reconcile(
			new[] { Desired("203.0.113.10") },
			new[] { WindowsScan(new[] { Rule("203.0.113.10") }, thirdParty: true, note: "Kaspersky detected") },
			Prefix,
			Now);

		ReconciledBlock block = Assert.Single(report.Blocks);
		Assert.Equal(EnforcementStatus.Active, block.Status);
		Assert.Equal(EnforcementConfidence.ExistsButProviderMayBypass, block.Confidence);
		// A may-bypass rule is not counted as fully verified.
		Assert.Equal(0, report.VerifiedCount);
	}

	[Fact]
	public void ExpiredWithRuleStillPresent_YieldsExpiredAndRecommendsRemoval()
	{
		ReconciliationReport report = EnforcementReconciler.Reconcile(
			new[] { Desired("203.0.113.10", expires: Now.AddMinutes(-1)) },
			new[] { WindowsScan(new[] { Rule("203.0.113.10") }) },
			Prefix,
			Now);

		ReconciledBlock block = Assert.Single(report.Blocks);
		Assert.Equal(EnforcementStatus.Expired, block.Status);
		Assert.Contains("Remove", block.RecommendedAction, StringComparison.OrdinalIgnoreCase);
	}

	[Fact]
	public void ExpiredWithNoRule_YieldsExpiredNoAction()
	{
		ReconciliationReport report = EnforcementReconciler.Reconcile(
			new[] { Desired("203.0.113.10", expires: Now.AddMinutes(-1)) },
			new[] { WindowsScan(Array.Empty<DiscoveredBlockRule>()) },
			Prefix,
			Now);

		Assert.Equal(EnforcementStatus.Expired, Assert.Single(report.Blocks).Status);
	}

	[Fact]
	public void ProviderUnavailable_YieldsProviderUnavailableUnknown()
	{
		ReconciliationReport report = EnforcementReconciler.Reconcile(
			new[] { Desired("203.0.113.10") },
			new[] { WindowsScan(Array.Empty<DiscoveredBlockRule>(), available: false, note: "service unreachable") },
			Prefix,
			Now);

		ReconciledBlock block = Assert.Single(report.Blocks);
		Assert.Equal(EnforcementStatus.ProviderUnavailable, block.Status);
		Assert.Equal(EnforcementConfidence.Unknown, block.Confidence);
	}

	[Fact]
	public void NotScannable_YieldsEffectiveUnknown()
	{
		ReconciliationReport report = EnforcementReconciler.Reconcile(
			new[] { Desired("203.0.113.10") },
			new[] { WindowsScan(Array.Empty<DiscoveredBlockRule>(), scannable: false, note: "route table not enumerable") },
			Prefix,
			Now);

		Assert.Equal(EnforcementStatus.EffectiveUnknown, Assert.Single(report.Blocks).Status);
	}

	[Fact]
	public void NoScanForProvider_YieldsEffectiveUnknown()
	{
		ReconciliationReport report = EnforcementReconciler.Reconcile(
			new[] { Desired("203.0.113.10") },
			Array.Empty<BackendScanResult>(),
			Prefix,
			Now);

		Assert.Equal(EnforcementStatus.EffectiveUnknown, Assert.Single(report.Blocks).Status);
	}

	[Fact]
	public void DiscoveredRuleWithNoDbRow_YieldsOrphan()
	{
		ReconciliationReport report = EnforcementReconciler.Reconcile(
			Array.Empty<DesiredBlock>(),
			new[] { WindowsScan(new[] { Rule("203.0.113.99") }) },
			Prefix,
			Now);

		Assert.Empty(report.Blocks);
		ReconciledBlock orphan = Assert.Single(report.Orphans);
		Assert.Equal(EnforcementStatus.OrphanedRule, orphan.Status);
		Assert.Equal("203.0.113.99", orphan.Ip);
	}

	[Fact]
	public void ConsumedRule_IsNotAlsoReportedAsOrphan()
	{
		ReconciliationReport report = EnforcementReconciler.Reconcile(
			new[] { Desired("203.0.113.10") },
			new[] { WindowsScan(new[] { Rule("203.0.113.10"), Rule("203.0.113.99") }) },
			Prefix,
			Now);

		Assert.Equal(EnforcementStatus.Active, Assert.Single(report.Blocks).Status);
		ReconciledBlock orphan = Assert.Single(report.Orphans);
		Assert.Equal("203.0.113.99", orphan.Ip);
	}
}
