// File:    tests/RdpAudit.Service.Tests/MikroTikFirewallProviderTests.cs
// Module:  RdpAudit.Service.Tests
// Purpose: Tests for the Stage 9 MikroTikFirewallProvider. Exercises the mapping between
//          MikroTikOperationResult outcomes and FirewallActionResult statuses, the disabled /
//          not-configured short-circuit paths, and the comment-building helper.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using RdpAudit.Core.Config;
using RdpAudit.Core.Firewall;
using RdpAudit.Core.MikroTik;
using RdpAudit.Service.Firewall;
using Xunit;

namespace RdpAudit.Service.Tests;

public class MikroTikFirewallProviderTests
{
	private sealed class StaticOptionsMonitor<T> : IOptionsMonitor<T>
	{
		public StaticOptionsMonitor(T value) => CurrentValue = value;
		public T CurrentValue { get; }
		public T Get(string? name) => CurrentValue;
		public IDisposable? OnChange(Action<T, string?> listener) => null;
	}

	private sealed class FakeClient : IMikroTikClient
	{
		public MikroTikOperationResult PingResult { get; set; } = new() { Outcome = MikroTikOutcome.Accepted, ResponseCode = 200 };
		public MikroTikOperationResult AddResult { get; set; } = new() { Outcome = MikroTikOutcome.Accepted, ResponseCode = 200, RuleId = "*7" };
		public MikroTikOperationResult RemoveResult { get; set; } = new() { Outcome = MikroTikOutcome.Accepted, ResponseCode = 200, RuleId = "*7" };
		public IReadOnlyList<MikroTikRule> ListedRules { get; set; } = Array.Empty<MikroTikRule>();

		public int AddCount { get; private set; }
		public int RemoveCount { get; private set; }
		public int PingCount { get; private set; }

		public Task<MikroTikOperationResult> AddBlockAsync(MikroTikBlockRequest request, CancellationToken ct)
		{
			AddCount++;
			return Task.FromResult(AddResult);
		}

		public Task<(MikroTikOperationResult Result, IReadOnlyList<MikroTikRule> Rules)> ListOwnedRulesAsync(CancellationToken ct)
			=> Task.FromResult((new MikroTikOperationResult { Outcome = MikroTikOutcome.Accepted, ResponseCode = 200 }, ListedRules));

		public Task<MikroTikOperationResult> PingAsync(CancellationToken ct)
		{
			PingCount++;
			return Task.FromResult(PingResult);
		}

		public Task<MikroTikOperationResult> RemoveBlockAsync(string? ruleId, string ip, CancellationToken ct)
		{
			RemoveCount++;
			return Task.FromResult(RemoveResult);
		}
	}

	private static MikroTikFirewallProvider Build(MikroTikOptions opts, FakeClient client) =>
		new(NullLogger<MikroTikFirewallProvider>.Instance,
			new StaticOptionsMonitor<RdpAuditOptions>(new RdpAuditOptions { MikroTik = opts }),
			client);

	[Fact]
	public async Task GetStatusAsync_ReturnsDisabled_WhenDisabled()
	{
		MikroTikOptions opts = new() { Enabled = false };
		FakeClient client = new();
		MikroTikFirewallProvider provider = Build(opts, client);

		FirewallStatusReport status = await provider.GetStatusAsync(CancellationToken.None);

		Assert.Equal(FirewallProviderStatus.Disabled, status.Status);
		Assert.Equal(0, client.PingCount);
	}

	[Fact]
	public async Task GetStatusAsync_ReturnsNotConfigured_WhenMissingCreds()
	{
		MikroTikOptions opts = new() { Enabled = true, Host = "router" };
		FakeClient client = new();
		MikroTikFirewallProvider provider = Build(opts, client);

		FirewallStatusReport status = await provider.GetStatusAsync(CancellationToken.None);

		Assert.Equal(FirewallProviderStatus.NotConfigured, status.Status);
		Assert.Equal(0, client.PingCount);
	}

	[Fact]
	public async Task GetStatusAsync_PingsClient_WhenConfigured()
	{
		MikroTikOptions opts = new() { Enabled = true, Host = "router", UserName = "u", Password = "p" };
		FakeClient client = new() { PingResult = new() { Outcome = MikroTikOutcome.Accepted } };
		MikroTikFirewallProvider provider = Build(opts, client);

		FirewallStatusReport status = await provider.GetStatusAsync(CancellationToken.None);

		Assert.Equal(FirewallProviderStatus.Available, status.Status);
		Assert.Equal(1, client.PingCount);
	}

	[Fact]
	public async Task BlockAsync_ReturnsUnavailable_WhenAddRulesDisabled()
	{
		MikroTikOptions opts = new() { Enabled = true, AddAttackerRules = false, Host = "router", UserName = "u", Password = "p" };
		FakeClient client = new();
		MikroTikFirewallProvider provider = Build(opts, client);

		FirewallActionResult result = await provider.BlockAsync(new FirewallBlockRequest("203.0.113.1", "RdpAudit-Block"), CancellationToken.None);

		Assert.Equal(FirewallActionStatus.Unavailable, result.Status);
		Assert.Equal(0, client.AddCount);
	}

	[Fact]
	public async Task BlockAsync_DelegatesToClient_AndMapsRuleId()
	{
		MikroTikOptions opts = new()
		{
			Enabled = true,
			AddAttackerRules = true,
			Host = "router",
			UserName = "u",
			Password = "p",
			FilterChain = "input",
			FilterAction = "drop",
		};
		FakeClient client = new() { AddResult = new() { Outcome = MikroTikOutcome.Accepted, RuleId = "*12" } };
		MikroTikFirewallProvider provider = Build(opts, client);

		FirewallActionResult result = await provider.BlockAsync(new FirewallBlockRequest("203.0.113.1", "RdpAudit-Block"), CancellationToken.None);

		Assert.Equal(FirewallActionStatus.Success, result.Status);
		Assert.Equal("*12", result.RuleId);
		Assert.Equal(1, client.AddCount);
	}

	[Fact]
	public async Task BlockAsync_AlreadyExists_MapsToSuccess()
	{
		MikroTikOptions opts = new() { Enabled = true, AddAttackerRules = true, Host = "router", UserName = "u", Password = "p" };
		FakeClient client = new() { AddResult = new() { Outcome = MikroTikOutcome.AlreadyExists, RuleId = "*1" } };
		MikroTikFirewallProvider provider = Build(opts, client);

		FirewallActionResult result = await provider.BlockAsync(new FirewallBlockRequest("203.0.113.1", "RdpAudit-Block"), CancellationToken.None);

		Assert.Equal(FirewallActionStatus.Success, result.Status);
		Assert.Equal("*1", result.RuleId);
	}

	[Fact]
	public async Task UnblockAsync_DelegatesToClient()
	{
		MikroTikOptions opts = new() { Enabled = true, AddAttackerRules = true, Host = "router", UserName = "u", Password = "p" };
		FakeClient client = new() { RemoveResult = new() { Outcome = MikroTikOutcome.Accepted, RuleId = "*5" } };
		MikroTikFirewallProvider provider = Build(opts, client);

		FirewallActionResult result = await provider.UnblockAsync("203.0.113.1", "RdpAudit-Block", CancellationToken.None);

		Assert.Equal(FirewallActionStatus.Success, result.Status);
		Assert.Equal(1, client.RemoveCount);
	}

	[Fact]
	public async Task UnblockAsync_NotFound_MapsToNotFound()
	{
		MikroTikOptions opts = new() { Enabled = true, AddAttackerRules = true, Host = "router", UserName = "u", Password = "p" };
		FakeClient client = new() { RemoveResult = new() { Outcome = MikroTikOutcome.NotFound } };
		MikroTikFirewallProvider provider = Build(opts, client);

		FirewallActionResult result = await provider.UnblockAsync("203.0.113.1", "RdpAudit-Block", CancellationToken.None);

		Assert.Equal(FirewallActionStatus.NotFound, result.Status);
	}

	[Fact]
	public void BuildComment_StartsWithPrefix_AndContainsTimestamp()
	{
		DateTime nowUtc = new(2026, 1, 2, 3, 4, 5, DateTimeKind.Utc);
		string comment = MikroTikFirewallProvider.BuildComment("RdpAudit", "BruteForce", nowUtc, null, "auto-block");

		Assert.StartsWith("RdpAudit", comment, StringComparison.Ordinal);
		Assert.Contains("2026-01-02T03:04:05Z", comment, StringComparison.Ordinal);
		Assert.Contains("BruteForce", comment, StringComparison.Ordinal);
	}

	[Fact]
	public void HasMinimumConfig_DetectsMissingFields()
	{
		Assert.False(MikroTikFirewallProvider.HasMinimumConfig(new MikroTikOptions()));
		Assert.False(MikroTikFirewallProvider.HasMinimumConfig(new MikroTikOptions { Host = "router" }));
		Assert.False(MikroTikFirewallProvider.HasMinimumConfig(new MikroTikOptions { Host = "router", UserName = "u" }));
		Assert.True(MikroTikFirewallProvider.HasMinimumConfig(new MikroTikOptions { Host = "router", UserName = "u", Password = "p" }));
	}
}
