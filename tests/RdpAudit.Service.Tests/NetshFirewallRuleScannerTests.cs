// File:    tests/RdpAudit.Service.Tests/NetshFirewallRuleScannerTests.cs
// Module:  RdpAudit.Service.Tests
// Purpose: Locks the fail-closed contract of the netsh text scanner: a dump the pure parser
//          cannot anchor on (localised labels, changed format, empty output) must be reported as
//          UNSCANNABLE, never as "zero rules". A zero-rule answer demoted every intended block to
//          MissingRule in reconciliation, which in turn kept live OS rules installed forever.
// Extends: Add cases here when NetshRuleScanner gains new anchoring keys.
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging.Abstractions;
using RdpAudit.Core.Firewall;
using RdpAudit.Service.Firewall;
using Xunit;

namespace RdpAudit.Service.Tests;

public class NetshFirewallRuleScannerTests
{
	private const string Prefix = "RdpAudit-Block";

	private const string EnglishDump =
		"Rule Name:                            RdpAudit-Block-203.0.113.10\n"
		+ "----------------------------------------------------------------------\n"
		+ "Enabled:                              Yes\n"
		+ "Direction:                            In\n"
		+ "RemoteIP:                             203.0.113.10\n"
		+ "Protocol:                             Any\n"
		+ "Action:                               Block\n";

	/// <summary>Russian labels: the pure parser anchors on English keys only, so this dump is the
	/// exact shape a direct (non-English-console) netsh spawn produces on a ru-RU host.</summary>
	private const string LocalisedDump =
		"Имя правила:                          RdpAudit-Block-203.0.113.10\n"
		+ "----------------------------------------------------------------------\n"
		+ "Включено:                             Да\n"
		+ "Направление:                          Входящее\n"
		+ "Удалённый IP:                         203.0.113.10\n"
		+ "Протокол:                             Любой\n"
		+ "Действие:                             Блокировать\n";

	[Fact]
	public async Task EnglishDumpWithRules_IsScannable_AndParsed()
	{
		NetshFirewallRuleScanner sut = new(
			NullLogger<NetshFirewallRuleScanner>.Instance,
			new FakeNetshRunner(EnglishDump));

		FirewallScanResult result = await sut.ScanRdpAuditBlockRulesAsync(Prefix, CancellationToken.None);

		Assert.True(result.Scannable);
		Assert.Equal(FirewallScanBackend.NetshText, result.Backend);
		DiscoveredBlockRule rule = Assert.Single(result.Rules);
		Assert.Equal("RdpAudit-Block-203.0.113.10", rule.RuleName);
	}

	[Fact]
	public async Task EnglishEmptyAnswer_StaysScannable_AsAuthoritativeEmpty()
	{
		NetshFirewallRuleScanner sut = new(
			NullLogger<NetshFirewallRuleScanner>.Instance,
			new FakeNetshRunner("No rules match the specified criteria.\nOk.\n"));

		FirewallScanResult result = await sut.ScanRdpAuditBlockRulesAsync(Prefix, CancellationToken.None);

		Assert.True(result.Scannable);
		Assert.Empty(result.Rules);
	}

	[Fact]
	public async Task LocalisedDump_IsReportedUnscannable_NotAsZeroRules()
	{
		NetshFirewallRuleScanner sut = new(
			NullLogger<NetshFirewallRuleScanner>.Instance,
			new FakeNetshRunner(LocalisedDump));

		FirewallScanResult result = await sut.ScanRdpAuditBlockRulesAsync(Prefix, CancellationToken.None);

		Assert.False(result.Scannable);
		Assert.Empty(result.Rules);
		Assert.Contains("unknown", result.Note ?? string.Empty, StringComparison.OrdinalIgnoreCase);
	}

	[Fact]
	public async Task EmptyOutput_IsReportedUnscannable()
	{
		NetshFirewallRuleScanner sut = new(
			NullLogger<NetshFirewallRuleScanner>.Instance,
			new FakeNetshRunner(string.Empty));

		FirewallScanResult result = await sut.ScanRdpAuditBlockRulesAsync(Prefix, CancellationToken.None);

		Assert.False(result.Scannable);
	}

	private sealed class FakeNetshRunner : INetshRunner
	{
		private readonly string _stdOut;

		public FakeNetshRunner(string stdOut)
		{
			_stdOut = stdOut;
		}

		public Task<NetshResult> RunAsync(IReadOnlyList<string> args, CancellationToken ct) =>
			Task.FromResult(new NetshResult(ExitCode: 0, StdOut: _stdOut, StdErr: string.Empty));
	}
}