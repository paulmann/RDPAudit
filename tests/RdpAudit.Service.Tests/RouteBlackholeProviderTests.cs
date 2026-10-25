/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// File   : RouteBlackholeProviderTests.cs
// Project: RdpAudit.Service.Tests (RdpAudit.Service.Tests)
// Purpose: Locks the experimental route-blackhole provider's two safety contracts: the gateway
//          reachability probe must fail SAFE on an ambiguous ping status (a live-but-ICMP-filtered
//          gateway must be refused, not used as a blackhole next-hop), and route deletion must
//          distinguish "element not found" (exit 1) from a real failure so the row stays retryable.
// Depends: RouteBlackholeProvider, IRouteCommandRunner, IGatewayReachabilityProbe, xUnit
// Extends: Add a case when the gateway classification gains a new verdict.
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System.Net.NetworkInformation;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using RdpAudit.Core.Config;
using RdpAudit.Core.Firewall;
using RdpAudit.Service.Firewall;
using Xunit;

namespace RdpAudit.Service.Tests;

public sealed class RouteBlackholeProviderTests
{
	private sealed class StaticOptionsMonitor<T> : IOptionsMonitor<T>
	{
		public StaticOptionsMonitor(T value) => CurrentValue = value;
		public T CurrentValue { get; }
		public T Get(string? name) => CurrentValue;
		public IDisposable? OnChange(Action<T, string?> listener) => null;
	}

	private sealed class FakeRouteRunner : IRouteCommandRunner
	{
		public Queue<RouteCommandResult> Responses { get; } = new();

		public List<IReadOnlyList<string>> Calls { get; } = new();

		public Task<RouteCommandResult> RunAsync(IReadOnlyList<string> args, CancellationToken ct)
		{
			Calls.Add(args);
			return Task.FromResult(Responses.Count > 0
				? Responses.Dequeue()
				: new RouteCommandResult(0, string.Empty, string.Empty));
		}
	}

	private sealed class FakeProbe : IGatewayReachabilityProbe
	{
		public bool Reachable { get; set; }

		public Task<bool> IsReachableAsync(string gateway, CancellationToken ct) => Task.FromResult(Reachable);
	}

	private static RouteBlackholeProvider Build(FakeRouteRunner runner, FakeProbe probe, string gateway = "10.255.255.254")
	{
		RdpAuditOptions options = new();
		options.Firewall.RouteBlackholeGateway = gateway;
		return new RouteBlackholeProvider(
			NullLogger<RouteBlackholeProvider>.Instance,
			new StaticOptionsMonitor<RdpAuditOptions>(options),
			runner,
			probe);
	}

	[Theory]
	[InlineData(IPStatus.Success, true)]
	[InlineData(IPStatus.TimedOut, false)]
	[InlineData(IPStatus.DestinationHostUnreachable, false)]
	[InlineData(IPStatus.DestinationNetworkUnreachable, false)]
	[InlineData(IPStatus.TtlExpired, true)]
	public void IsReachableFromStatus_FailsSafeOnAmbiguousStatus(IPStatus status, bool expected)
	{
		// A live gateway that merely filters ICMP must be reported REACHABLE so the provider refuses
		// to install a blackhole route that could forward attacker traffic to it.
		Assert.Equal(expected, PingGatewayReachabilityProbe.IsReachableFromStatus(status));
	}

	[Fact]
	public async Task BlockAsync_ReachableGateway_IsRefused()
	{
		if (!OperatingSystem.IsWindows())
		{
			return;
		}

		RouteBlackholeProvider provider = Build(new FakeRouteRunner(), new FakeProbe { Reachable = true });

		FirewallActionResult result = await provider.BlockAsync(
			new FirewallBlockRequest("203.0.113.10", "RdpAudit-Block"), CancellationToken.None);

		Assert.Equal(FirewallActionStatus.Refused, result.Status);
	}

	[Fact]
	public async Task UnblockAsync_ExitOne_ReturnsNotFound()
	{
		if (!OperatingSystem.IsWindows())
		{
			return;
		}

		FakeRouteRunner runner = new();
		runner.Responses.Enqueue(new RouteCommandResult(1, string.Empty, "Element not found"));
		RouteBlackholeProvider provider = Build(runner, new FakeProbe { Reachable = false });

		FirewallActionResult result = await provider.UnblockAsync("203.0.113.10", "RdpAudit-Block", CancellationToken.None);

		Assert.Equal(FirewallActionStatus.NotFound, result.Status);
	}

	[Fact]
	public async Task UnblockAsync_NonOneFailure_ReturnsUnavailable()
	{
		if (!OperatingSystem.IsWindows())
		{
			return;
		}

		// Access-denied / enumeration failures must NOT be reported as "already removed": the route
		// may still be installed, so the caller has to keep the row retryable.
		FakeRouteRunner runner = new();
		runner.Responses.Enqueue(new RouteCommandResult(5, string.Empty, "Access is denied."));
		RouteBlackholeProvider provider = Build(runner, new FakeProbe { Reachable = false });

		FirewallActionResult result = await provider.UnblockAsync("203.0.113.10", "RdpAudit-Block", CancellationToken.None);

		Assert.Equal(FirewallActionStatus.Unavailable, result.Status);
	}
}
