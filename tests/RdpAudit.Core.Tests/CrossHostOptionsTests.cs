// File:    tests/RdpAudit.Core.Tests/CrossHostOptionsTests.cs
// Module:  RdpAudit.Core.Tests
// Purpose: Locks the P4-18 CrossHost section contract: disabled-by-default, the polling schedule
//          defaults, the clamping ranges the worker relies on, the per-poll fact cap and the
//          host-list resolution semantics (blank hosts dropped, names trimmed, values copied -
//          the in-memory options object must never be mutated). If these regress, the correlation
//          worker could poll too fast, hang on connects or flood the facts store.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using RdpAudit.Core.Config;
using Xunit;

namespace RdpAudit.Core.Tests;

/// <summary>Pins the CrossHost option defaults and clamping behaviour.</summary>
public class CrossHostOptionsTests
{
	[Fact]
	public void Defaults_AreDisabledWithSafePollingSchedule()
	{
		CrossHostOptions options = new();
		Assert.False(options.Enabled);
		Assert.Empty(options.Hosts);
		Assert.Equal(60, options.PollIntervalSeconds);
		Assert.Equal(5_000, options.ConnectTimeoutMs);
		Assert.Equal(1_000, options.MaxFactsPerPoll);
		Assert.Equal(60, CrossHostOptions.DefaultPollIntervalSeconds);
		Assert.Equal(5_000, CrossHostOptions.DefaultConnectTimeoutMs);
		Assert.Equal(1_000, CrossHostOptions.DefaultMaxFactsPerPoll);
	}

	[Theory]
	[InlineData(0, 10)]
	[InlineData(9, 10)]
	[InlineData(10, 10)]
	[InlineData(60, 60)]
	[InlineData(3_600, 3_600)]
	[InlineData(99_999, 3_600)]
	public void ResolvePollIntervalSeconds_ClampsToSupportedRange(int input, int expected)
	{
		CrossHostOptions options = new() { PollIntervalSeconds = input };
		Assert.Equal(expected, options.ResolvePollIntervalSeconds());
	}

	[Theory]
	[InlineData(0, 100)]
	[InlineData(99, 100)]
	[InlineData(100, 100)]
	[InlineData(5_000, 5_000)]
	[InlineData(60_000, 60_000)]
	[InlineData(600_000, 60_000)]
	public void ResolveConnectTimeoutMs_ClampsToSupportedRange(int input, int expected)
	{
		CrossHostOptions options = new() { ConnectTimeoutMs = input };
		Assert.Equal(expected, options.ResolveConnectTimeoutMs());
	}

	[Theory]
	[InlineData(0, 1)]
	[InlineData(-5, 1)]
	[InlineData(1, 1)]
	[InlineData(1_000, 1_000)]
	[InlineData(100_000, 100_000)]
	[InlineData(500_000, 100_000)]
	public void ResolveMaxFactsPerPoll_ClampsToSupportedRange(int input, int expected)
	{
		CrossHostOptions options = new() { MaxFactsPerPoll = input };
		Assert.Equal(expected, options.ResolveMaxFactsPerPoll());
	}

	[Fact]
	public void ResolveHosts_DropsBlankHostsAndTrimsNames()
	{
		CrossHostOptions options = new();
		options.Hosts.Add(new CrossHostHostOptions { HostName = "  SVR01  " });
		options.Hosts.Add(new CrossHostHostOptions { HostName = "   " });
		options.Hosts.Add(new CrossHostHostOptions { HostName = string.Empty });
		options.Hosts.Add(new CrossHostHostOptions { HostName = "SVR02" });

		List<CrossHostHostOptions> resolved = options.ResolveHosts();

		Assert.Equal(2, resolved.Count);
		Assert.Equal("SVR01", resolved[0].HostName);
		Assert.Equal("SVR02", resolved[1].HostName);
	}

	[Fact]
	public void ResolveHosts_ReturnsCopiesAndPreservesCredential()
	{
		const string envelope = "{\"$protected\":\"abc\",\"scope\":\"LocalMachine\"}";
		CrossHostOptions options = new();
		options.Hosts.Add(new CrossHostHostOptions { HostName = " SVR03 ", Credential = envelope });

		List<CrossHostHostOptions> resolved = options.ResolveHosts();
		resolved[0].HostName = "MUTATED";

		Assert.Equal(" SVR03 ", options.Hosts[0].HostName);
		Assert.Equal(envelope, resolved[0].Credential);
	}
}
