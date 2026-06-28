// File:    tests/RdpAudit.Service.Tests/NetshCommandBuilderTests.cs
// Module:  RdpAudit.Service.Tests
// Purpose: Unit tests for the netsh command builder: rule-name normalisation, IP validation,
//          reserved-address policy, and the argument vectors emitted for add / delete / show
//          rule actions.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System.Net;
using RdpAudit.Core.Config;
using RdpAudit.Service.Firewall;
using Xunit;

namespace RdpAudit.Service.Tests;

public class NetshCommandBuilderTests
{
	[Theory]
	[InlineData("RdpAudit-Block", "RdpAudit-Block")]
	[InlineData("RdpAudit_Block.v2", "RdpAudit_Block.v2")]
	[InlineData("Rdp Audit Block!", "Rdp-Audit-Block")]
	[InlineData("", "RdpAudit-Block")]
	[InlineData("   ", "RdpAudit-Block")]
	[InlineData("---", "RdpAudit-Block")]
	public void NormalizeRulePrefix_StripsUnsafeCharacters(string input, string expected)
	{
		Assert.Equal(expected, NetshCommandBuilder.NormalizeRulePrefix(input));
	}

	[Theory]
	[InlineData("1.2.3.4", "1.2.3.4")]
	[InlineData("203.0.113.10", "203.0.113.10")]
	[InlineData("2001:db8::1", "2001:db8::1")]
	public void NormalizeIp_RoundTripsValidAddresses(string input, string expected)
	{
		Assert.Equal(expected, NetshCommandBuilder.NormalizeIp(input));
	}

	[Theory]
	[InlineData("999.999.999.999")]
	[InlineData("not-an-ip")]
	[InlineData("1.2.3.4.5")]
	public void ParseAndValidateIp_RejectsInvalidInputs(string input)
	{
		Assert.Throws<ArgumentException>(() => NetshCommandBuilder.ParseAndValidateIp(input));
	}

	[Theory]
	[InlineData("")]
	[InlineData("   ")]
	public void ParseAndValidateIp_RejectsEmpty(string input)
	{
		Assert.Throws<ArgumentException>(() => NetshCommandBuilder.ParseAndValidateIp(input));
	}

	[Theory]
	[InlineData("127.0.0.1", true)]
	[InlineData("10.0.0.1", true)]
	[InlineData("192.168.1.1", true)]
	[InlineData("172.16.0.1", true)]
	[InlineData("172.32.0.1", false)]
	[InlineData("169.254.1.1", true)]
	[InlineData("100.64.0.1", true)]
	[InlineData("100.128.0.1", false)]
	[InlineData("224.0.0.1", true)]
	[InlineData("8.8.8.8", false)]
	[InlineData("203.0.113.10", false)]
	[InlineData("::1", true)]
	[InlineData("fe80::1", true)]
	[InlineData("2001:db8::1", false)]
	public void IsReservedAddress_ReturnsExpected(string ip, bool expected)
	{
		IPAddress addr = IPAddress.Parse(ip);
		Assert.Equal(expected, NetshCommandBuilder.IsReservedAddress(addr));
	}

	[Fact]
	public void BuildRuleName_ProducesDeterministicCompositeName()
	{
		string name = NetshCommandBuilder.BuildRuleName("RdpAudit-Block", "203.0.113.10");
		Assert.Equal("RdpAudit-Block-203.0.113.10", name);
	}

	[Fact]
	public void BuildRuleName_TruncatesAtMaximumLength()
	{
		string longPrefix = new('a', NetshCommandBuilder.MaxRuleNameLength * 2);
		string name = NetshCommandBuilder.BuildRuleName(longPrefix, "1.2.3.4");
		Assert.Equal(NetshCommandBuilder.MaxRuleNameLength, name.Length);
	}

	[Fact]
	public void BuildAddRuleArgs_IncludesBlockingRemoteIpAndDirection()
	{
		IReadOnlyList<string> args = NetshCommandBuilder.BuildAddRuleArgs(
			"RdpAudit-Block-203.0.113.10",
			"203.0.113.10",
			"reason");

		Assert.Equal("advfirewall", args[0]);
		Assert.Equal("firewall", args[1]);
		Assert.Equal("add", args[2]);
		Assert.Equal("rule", args[3]);
		Assert.Equal("name=RdpAudit-Block-203.0.113.10", args[4]);
		Assert.Equal("dir=in", args[5]);
		Assert.Equal("action=block", args[6]);
		Assert.Equal("remoteip=203.0.113.10", args[7]);
		Assert.Equal("profile=any", args[8]);
		Assert.Equal("enable=yes", args[9]);
		Assert.Equal("protocol=any", args[10]);
		Assert.Contains(args, a => a.StartsWith("description=", StringComparison.Ordinal));

		// netsh advfirewall firewall add rule rejects group=/grouping= (verified on a live host);
		// the rule-name prefix is the identity handle instead. Group is stamped via the PowerShell path.
		Assert.DoesNotContain(args, a => a.StartsWith("group=", StringComparison.OrdinalIgnoreCase));
		Assert.DoesNotContain(args, a => a.StartsWith("grouping=", StringComparison.OrdinalIgnoreCase));
	}

	[Fact]
	public void BuildAddRuleArgs_SanitisesDescriptionControlCharacters()
	{
		IReadOnlyList<string> args = NetshCommandBuilder.BuildAddRuleArgs(
			"RdpAudit-Block-1.2.3.4",
			"1.2.3.4",
			"reason\r\nwith \"quotes\" | & < > injection");

		string? description = args.FirstOrDefault(a => a.StartsWith("description=", StringComparison.Ordinal));
		Assert.NotNull(description);
		Assert.DoesNotContain('\r', description!);
		Assert.DoesNotContain('\n', description!);
		Assert.DoesNotContain('"', description!);
		Assert.DoesNotContain('|', description!);
		Assert.DoesNotContain('&', description!);
		Assert.DoesNotContain('<', description!);
		Assert.DoesNotContain('>', description!);
	}

	[Fact]
	public void BuildDeleteRuleArgs_TargetsNamedRule()
	{
		IReadOnlyList<string> args = NetshCommandBuilder.BuildDeleteRuleArgs("RdpAudit-Block-1.2.3.4");
		Assert.Equal(new[]
		{
			"advfirewall", "firewall", "delete", "rule",
			"name=RdpAudit-Block-1.2.3.4",
		}, args);
	}

	[Fact]
	public void BuildShowAllProfilesStateArgs_IsConstant()
	{
		Assert.Equal(new[]
		{
			"advfirewall", "show", "allprofiles", "state",
		}, NetshCommandBuilder.BuildShowAllProfilesStateArgs());
	}

	[Theory]
	[InlineData("Rule;Name")]
	[InlineData("Rule Name")]
	[InlineData("Rule|Name")]
	[InlineData("Rule&Name")]
	public void BuildAddRuleArgs_RejectsRuleNameWithUnsafeCharacters(string ruleName)
	{
		Assert.Throws<ArgumentException>(() =>
			NetshCommandBuilder.BuildAddRuleArgs(ruleName, "1.2.3.4", null));
	}

	[Fact]
	public void BuildAddRuleArgs_AllInbound_OmitsGroupAndUsesProfileAndProtocolAny()
	{
		IReadOnlyList<string> args = NetshCommandBuilder.BuildAddRuleArgs(
			"RdpAudit-Block-203.0.113.10",
			"203.0.113.10",
			"reason",
			FirewallBlockScope.AllInbound,
			rdpPort: 0);

		Assert.DoesNotContain(args, a => a.StartsWith("group=", StringComparison.OrdinalIgnoreCase));
		Assert.DoesNotContain(args, a => a.StartsWith("grouping=", StringComparison.OrdinalIgnoreCase));
		Assert.Contains("profile=any", args);
		Assert.Contains("protocol=any", args);
		Assert.DoesNotContain(args, a => a.StartsWith("localport=", StringComparison.Ordinal));
	}

	[Fact]
	public void BuildAddRuleArgs_RdpPortOnly_RestrictsToTcpAndResolvedPort()
	{
		IReadOnlyList<string> args = NetshCommandBuilder.BuildAddRuleArgs(
			"RdpAudit-Block-203.0.113.10",
			"203.0.113.10",
			"reason",
			FirewallBlockScope.RdpPortOnly,
			rdpPort: 3390);

		Assert.DoesNotContain(args, a => a.StartsWith("group=", StringComparison.OrdinalIgnoreCase));
		Assert.DoesNotContain(args, a => a.StartsWith("grouping=", StringComparison.OrdinalIgnoreCase));
		Assert.Contains("protocol=tcp", args);
		Assert.Contains("localport=3390", args);
		Assert.DoesNotContain("protocol=any", args);
	}

	[Theory]
	[InlineData(0)]
	[InlineData(-1)]
	[InlineData(65536)]
	public void BuildAddRuleArgs_RdpPortOnly_RejectsOutOfRangePort(int rdpPort)
	{
		Assert.Throws<ArgumentOutOfRangeException>(() =>
			NetshCommandBuilder.BuildAddRuleArgs(
				"RdpAudit-Block-203.0.113.10",
				"203.0.113.10",
				"reason",
				FirewallBlockScope.RdpPortOnly,
				rdpPort));
	}

	[Fact]
	public void BuildNewNetFirewallRuleScript_StampsGroupAndCoreParameters()
	{
		string script = NetshCommandBuilder.BuildNewNetFirewallRuleScript(
			"RdpAudit-Block-203.0.113.10",
			"203.0.113.10",
			"reason",
			FirewallBlockScope.AllInbound,
			rdpPort: 0);

		// Only the PowerShell New-NetFirewallRule path can stamp the firewall Group.
		Assert.Contains("New-NetFirewallRule", script);
		Assert.Contains("-Group 'RdpAudit'", script);
		Assert.Contains("-Name 'RdpAudit-Block-203.0.113.10'", script);
		Assert.Contains("-DisplayName 'RdpAudit-Block-203.0.113.10'", script);
		Assert.Contains("-Direction Inbound", script);
		Assert.Contains("-Action Block", script);
		Assert.Contains("-Enabled True", script);
		Assert.Contains("-RemoteAddress '203.0.113.10'", script);
		// Written to the persistent store explicitly so the rule survives reboots and is enumerable.
		Assert.Contains("-PolicyStore PersistentStore", script);
		// Idempotent pre-clean so re-applying never stacks rules.
		Assert.Contains("Remove-NetFirewallRule", script);
	}

	[Fact]
	public void BuildNewNetFirewallRuleScript_RdpPortOnly_AddsTcpAndLocalPort()
	{
		string script = NetshCommandBuilder.BuildNewNetFirewallRuleScript(
			"RdpAudit-Block-203.0.113.10",
			"203.0.113.10",
			null,
			FirewallBlockScope.RdpPortOnly,
			rdpPort: 3390);

		Assert.Contains("-Protocol TCP", script);
		Assert.Contains("-LocalPort 3390", script);
	}

	[Fact]
	public void PsLiteral_DoublesEmbeddedSingleQuotes()
	{
		// Single quotes inside a PowerShell single-quoted literal must be doubled so a value can
		// never break out of the literal. This is the escaping guard the New-NetFirewallRule path
		// relies on for every dynamic token.
		Assert.Equal("'O''Brien said hi'", NetshCommandBuilder.PsLiteral("O'Brien said hi"));
		Assert.Equal("''''", NetshCommandBuilder.PsLiteral("'"));
		Assert.Equal("'plain'", NetshCommandBuilder.PsLiteral("plain"));
	}

	[Fact]
	public void BuildNewNetFirewallRuleScript_SanitisesDescriptionShellMetacharacters()
	{
		string script = NetshCommandBuilder.BuildNewNetFirewallRuleScript(
			"RdpAudit-Block-1.2.3.4",
			"1.2.3.4",
			"reason\r\nwith \"quotes\" ' | & < > injection",
			FirewallBlockScope.AllInbound,
			rdpPort: 0);

		// The description is sanitised before it reaches the PowerShell literal. Isolate the
		// emitted -Description literal and confirm no shell-significant character survived into it
		// (the surrounding script legitimately contains a '|' in the idempotency pipeline, so we
		// must assert on the description token specifically, not the whole script).
		const string marker = "-Description '";
		int start = script.IndexOf(marker, StringComparison.Ordinal);
		Assert.True(start >= 0, "script must contain a -Description literal");
		int valueStart = start + marker.Length;
		int valueEnd = script.IndexOf('\'', valueStart);
		Assert.True(valueEnd > valueStart, "description literal must be closed");
		string descriptionLiteral = script[valueStart..valueEnd];

		Assert.DoesNotContain('"', descriptionLiteral);
		Assert.DoesNotContain('\r', descriptionLiteral);
		Assert.DoesNotContain('\n', descriptionLiteral);
		Assert.DoesNotContain('|', descriptionLiteral);
		Assert.DoesNotContain('&', descriptionLiteral);
		Assert.DoesNotContain('<', descriptionLiteral);
		Assert.DoesNotContain('>', descriptionLiteral);
	}

	[Theory]
	[InlineData(0)]
	[InlineData(-1)]
	[InlineData(65536)]
	public void BuildNewNetFirewallRuleScript_RdpPortOnly_RejectsOutOfRangePort(int rdpPort)
	{
		Assert.Throws<ArgumentOutOfRangeException>(() =>
			NetshCommandBuilder.BuildNewNetFirewallRuleScript(
				"RdpAudit-Block-203.0.113.10",
				"203.0.113.10",
				"reason",
				FirewallBlockScope.RdpPortOnly,
				rdpPort));
	}
}
