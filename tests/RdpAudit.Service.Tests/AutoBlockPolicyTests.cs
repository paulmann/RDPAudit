// File:    tests/RdpAudit.Service.Tests/AutoBlockPolicyTests.cs
// Module:  RdpAudit.Service.Tests
// Purpose: Unit tests for the Stage 3 auto-block decision function. Covers whitelist skip,
//          brute-force threshold block, blacklisted-login block, instant-login trip-wire block,
//          and invalid-IP / missing-IP skip paths.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com
// Version: 1.4.0

using RdpAudit.Core.Config;
using RdpAudit.Core.Models;
using RdpAudit.Core.Util;
using RdpAudit.Service.Workers;
using Xunit;

namespace RdpAudit.Service.Tests;

public class AutoBlockPolicyTests
{
	private static HashSet<string> Empty() => new(StringComparer.OrdinalIgnoreCase);

	private static Alert AlertOf(string? ruleId, string? sourceIp, string? userName) => new()
	{
		Id = 1,
		RuleId = ruleId ?? string.Empty,
		Severity = AlertSeverity.High,
		TimeUtc = DateTime.UtcNow,
		SourceIp = sourceIp,
		UserName = userName,
		Message = "test",
	};

	[Fact]
	public void MissingSourceIp_SkipsWithReason()
	{
		FirewallOptions cfg = new() { AutoBlockBruteForce = true };
		AutoBlockDecision decision = AutoBlockPolicy.Decide(
			AlertOf("BRUTE_FORCE_01", null, "alice"),
			cfg,
			Empty(), Empty(), Empty(), Empty());

		Assert.Equal(AutoBlockAction.Skip, decision.Action);
		Assert.Equal("no-source-ip", decision.SkipReason);
	}

	[Fact]
	public void InvalidSourceIp_Skips()
	{
		FirewallOptions cfg = new() { AutoBlockBruteForce = true };
		AutoBlockDecision decision = AutoBlockPolicy.Decide(
			AlertOf("BRUTE_FORCE_01", "not-an-ip", "alice"),
			cfg,
			Empty(), Empty(), Empty(), Empty());

		Assert.Equal(AutoBlockAction.Skip, decision.Action);
		Assert.Equal("invalid-ip", decision.SkipReason);
	}

	[Fact]
	public void DbWhitelist_BeatsBruteForce()
	{
		FirewallOptions cfg = new() { AutoBlockBruteForce = true };
		HashSet<string> whitelist = new(StringComparer.OrdinalIgnoreCase) { "203.0.113.10" };
		AutoBlockDecision decision = AutoBlockPolicy.Decide(
			AlertOf("BRUTE_FORCE_01", "203.0.113.10", "alice"),
			cfg,
			whitelist, Empty(), Empty(), Empty());

		Assert.Equal(AutoBlockAction.Skip, decision.Action);
		Assert.Equal("whitelist", decision.SkipReason);
	}

	[Fact]
	public void ConfigWhitelist_BeatsBruteForce()
	{
		FirewallOptions cfg = new() { AutoBlockBruteForce = true };
		HashSet<string> whitelistConfig = new(StringComparer.OrdinalIgnoreCase) { "203.0.113.10" };
		AutoBlockDecision decision = AutoBlockPolicy.Decide(
			AlertOf("BRUTE_FORCE_01", "203.0.113.10", "alice"),
			cfg,
			Empty(), whitelistConfig, Empty(), Empty());

		Assert.Equal(AutoBlockAction.Skip, decision.Action);
		Assert.Equal("whitelist", decision.SkipReason);
	}

	[Fact]
	public void BruteForceAlert_TriggersBlockWhenEnabled()
	{
		FirewallOptions cfg = new() { AutoBlockBruteForce = true };
		AutoBlockDecision decision = AutoBlockPolicy.Decide(
			AlertOf("BRUTE_FORCE_01", "203.0.113.10", "alice"),
			cfg,
			Empty(), Empty(), Empty(), Empty());

		Assert.Equal(AutoBlockAction.Block, decision.Action);
		Assert.Equal("BruteForce", decision.ReasonTag);
		Assert.Equal("203.0.113.10", decision.NormalizedIp);
	}

	[Fact]
	public void BruteForceAlert_SkippedWhenAutoBlockDisabled()
	{
		FirewallOptions cfg = new() { AutoBlockBruteForce = false };
		AutoBlockDecision decision = AutoBlockPolicy.Decide(
			AlertOf("BRUTE_FORCE_01", "203.0.113.10", "alice"),
			cfg,
			Empty(), Empty(), Empty(), Empty());

		Assert.Equal(AutoBlockAction.Skip, decision.Action);
	}

	[Fact]
	public void InstantLogin_TripsBlockEvenWithoutBruteForce()
	{
		FirewallOptions cfg = new() { AutoBlockBruteForce = false };
		HashSet<string> instant = new(StringComparer.OrdinalIgnoreCase) { "guest" };
		AutoBlockDecision decision = AutoBlockPolicy.Decide(
			AlertOf("UNRELATED", "203.0.113.10", "guest"),
			cfg,
			Empty(), Empty(), Empty(), instant);

		Assert.Equal(AutoBlockAction.Block, decision.Action);
		Assert.Equal("InstantLogin", decision.ReasonTag);
	}

	[Fact]
	public void BlacklistedLogin_BlocksWhenEnabled()
	{
		FirewallOptions cfg = new()
		{
			AutoBlockBruteForce = false,
			BlockOnBlacklistedLogin = true,
		};
		HashSet<string> blacklist = new(StringComparer.OrdinalIgnoreCase) { "admin" };
		AutoBlockDecision decision = AutoBlockPolicy.Decide(
			AlertOf("EXTERNAL_RDP_LOGIN", "203.0.113.10", "admin"),
			cfg,
			Empty(), Empty(), blacklist, Empty());

		Assert.Equal(AutoBlockAction.Block, decision.Action);
		Assert.Equal("BlacklistedLogin", decision.ReasonTag);
	}

	[Fact]
	public void BlacklistedLogin_DoesNotBlockWhenSettingDisabled()
	{
		FirewallOptions cfg = new()
		{
			AutoBlockBruteForce = false,
			BlockOnBlacklistedLogin = false,
		};
		HashSet<string> blacklist = new(StringComparer.OrdinalIgnoreCase) { "admin" };
		AutoBlockDecision decision = AutoBlockPolicy.Decide(
			AlertOf("EXTERNAL_RDP_LOGIN", "203.0.113.10", "admin"),
			cfg,
			Empty(), Empty(), blacklist, Empty());

		Assert.Equal(AutoBlockAction.Skip, decision.Action);
	}

	[Fact]
	public void NonBruteForceAlert_DoesNotTriggerBlockUnderBruteForcePolicy()
	{
		FirewallOptions cfg = new() { AutoBlockBruteForce = true };
		AutoBlockDecision decision = AutoBlockPolicy.Decide(
			AlertOf("EXTERNAL_RDP_LOGIN", "203.0.113.10", "alice"),
			cfg,
			Empty(), Empty(), Empty(), Empty());

		Assert.Equal(AutoBlockAction.Skip, decision.Action);
	}

	[Fact]
	public void ResolveBlockDurationMinutes_PositiveConfig_HonouredVerbatim()
	{
		Assert.Equal(120, AutoBlockPolicy.ResolveBlockDurationMinutes(120));
	}

	[Theory]
	[InlineData(0)]
	[InlineData(-1)]
	[InlineData(-9999)]
	public void ResolveBlockDurationMinutes_NonPositiveConfig_FallsBackToBoundedDefault(int configured)
	{
		Assert.Equal(AutoBlockPolicy.FallbackBlockDurationMinutes, AutoBlockPolicy.ResolveBlockDurationMinutes(configured));
		Assert.True(AutoBlockPolicy.ResolveBlockDurationMinutes(configured) > 0, "auto-blocks must always expire");
	}

	// ── CIDR whitelist (private-network ranges) ──────────────────────────────────────

	[Theory]
	[InlineData("10.0.0.0/8", "10.5.6.7")]
	[InlineData("172.16.0.0/12", "172.20.1.1")]
	[InlineData("192.168.0.0/16", "192.168.1.60")]
	public void WhitelistCidrRange_Ipv4MemberOfRange_Skips(string cidr, string ip)
	{
		FirewallOptions cfg = new() { AutoBlockBruteForce = true };
		IReadOnlyList<CidrRange> ranges = AutoBlockPolicy.BuildWhitelistRanges(new[] { cidr });

		AutoBlockDecision decision = AutoBlockPolicy.Decide(
			AlertOf("BRUTE_FORCE_01", ip, "alice"),
			cfg,
			Empty(), Empty(), Empty(), Empty(),
			ranges);

		Assert.Equal(AutoBlockAction.Skip, decision.Action);
		Assert.Equal("whitelist", decision.SkipReason);
	}

	[Theory]
	[InlineData("fc00::/7", "fc00::1")]
	[InlineData("fc00::/7", "fd12:3456::99")]
	[InlineData("fd00::/8", "fd00:abcd::1")]
	public void WhitelistCidrRange_Ipv6MemberOfRange_Skips(string cidr, string ip)
	{
		FirewallOptions cfg = new() { AutoBlockBruteForce = true };
		IReadOnlyList<CidrRange> ranges = AutoBlockPolicy.BuildWhitelistRanges(new[] { cidr });

		AutoBlockDecision decision = AutoBlockPolicy.Decide(
			AlertOf("BRUTE_FORCE_01", ip, "alice"),
			cfg,
			Empty(), Empty(), Empty(), Empty(),
			ranges);

		Assert.Equal(AutoBlockAction.Skip, decision.Action);
		Assert.Equal("whitelist", decision.SkipReason);
	}

	[Fact]
	public void WhitelistCidrRange_PublicIpOutsideRange_StillBlocks()
	{
		// A public attacker IP outside every whitelisted private range must still be blocked.
		FirewallOptions cfg = new() { AutoBlockBruteForce = true };
		IReadOnlyList<CidrRange> ranges = AutoBlockPolicy.BuildWhitelistRanges(
			new[] { "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7", "fd00::/8" });

		AutoBlockDecision decision = AutoBlockPolicy.Decide(
			AlertOf("BRUTE_FORCE_01", "203.0.113.50", "alice"),
			cfg,
			Empty(), Empty(), Empty(), Empty(),
			ranges);

		Assert.Equal(AutoBlockAction.Block, decision.Action);
	}

	[Fact]
	public void WhitelistCidrRange_Ipv4SourceAgainstIpv6Range_DoesNotMatch()
	{
		// Family isolation: an IPv4 attacker must not be exempted by an IPv6 private range.
		FirewallOptions cfg = new() { AutoBlockBruteForce = true };
		IReadOnlyList<CidrRange> ranges = AutoBlockPolicy.BuildWhitelistRanges(new[] { "fc00::/7" });

		AutoBlockDecision decision = AutoBlockPolicy.Decide(
			AlertOf("BRUTE_FORCE_01", "203.0.113.7", "alice"),
			cfg,
			Empty(), Empty(), Empty(), Empty(),
			ranges);

		Assert.Equal(AutoBlockAction.Block, decision.Action);
	}
}
