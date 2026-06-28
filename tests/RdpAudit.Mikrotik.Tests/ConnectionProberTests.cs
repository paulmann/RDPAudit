/*
 * File   : ConnectionProberTests.cs
 * Project: RdpAudit.Mikrotik.Tests
 * Purpose: Verifies ConnectionProber.BuildSummary derives the api-ssl/SSH availability flags and the
 *          operator-facing recommendation text correctly for every reachability combination, so the
 *          wizard always steers the operator onto a valid bootstrap and production path.
 * Depends: RdpAudit.Mikrotik.Core.ConnectionProber, MikrotikPort, PortProbeResult, ConnectionProbeSummary, Xunit
 * Extends: When a new management port or recommendation branch is added, add a matching probe case here.
 *
 * Author : Mikhail Deynekin — https://Deynekin.com
 * Version: 1.0.0
 */

using RdpAudit.Mikrotik.Core;
using Xunit;

namespace RdpAudit.Mikrotik.Tests;

public sealed class ConnectionProberTests
{
	// ── Helpers ──────────────────────────────────────────────────────────────────

	private static PortProbeResult Probe(int port, string protocol, bool tls, bool open) =>
		new(new MikrotikPort(port, protocol, tls), open, 12);

	private static ConnectionProbeSummary Summarize(bool apiSslOpen, bool sshOpen) =>
		ConnectionProber.BuildSummary(new[]
		{
			Probe(22, "ssh", false, sshOpen),
			Probe(8728, "api", false, false),
			Probe(8729, "api-ssl", true, apiSslOpen),
			Probe(443, "https", true, false),
		});

	// ── Flag Derivation ──────────────────────────────────────────────────────────

	[Theory]
	[InlineData(true, true)]
	[InlineData(true, false)]
	[InlineData(false, true)]
	[InlineData(false, false)]
	public void BuildSummary_SetsAvailabilityFlags_FromOpenPorts(bool apiSslOpen, bool sshOpen)
	{
		ConnectionProbeSummary summary = Summarize(apiSslOpen, sshOpen);

		Assert.Equal(apiSslOpen, summary.ApiSslAvailable);
		Assert.Equal(sshOpen, summary.SshAvailable);
		Assert.Equal(4, summary.Results.Count);
	}

	// ── Recommendation Logic ───────────────────────────────────────────────────────

	[Fact]
	public void BuildSummary_BothOpen_RecommendsSshBootstrapAndApiSslProduction()
	{
		ConnectionProbeSummary summary = Summarize(apiSslOpen: true, sshOpen: true);

		Assert.Contains("SSH is available for one-time bootstrap", summary.Recommendation);
		Assert.Contains("8729", summary.Recommendation);
	}

	[Fact]
	public void BuildSummary_SshOnly_RecommendsWizardWillEnableApiSsl()
	{
		ConnectionProbeSummary summary = Summarize(apiSslOpen: false, sshOpen: true);

		Assert.Contains("SSH is available for bootstrap", summary.Recommendation);
		Assert.Contains("not yet open", summary.Recommendation);
	}

	[Fact]
	public void BuildSummary_ApiSslOnly_WarnsSshRequiredForBootstrap()
	{
		ConnectionProbeSummary summary = Summarize(apiSslOpen: true, sshOpen: false);

		Assert.Contains("bootstrap requires SSH", summary.Recommendation);
	}

	[Fact]
	public void BuildSummary_NoneOpen_WarnsNothingReachable()
	{
		ConnectionProbeSummary summary = Summarize(apiSslOpen: false, sshOpen: false);

		Assert.Contains("Neither SSH", summary.Recommendation);
		Assert.Contains("8729", summary.Recommendation);
	}

	[Fact]
	public void BuildSummary_IgnoresNonStandardPortsForFlags()
	{
		// Only 443 (https) open — neither SSH nor api-ssl should be reported available.
		ConnectionProbeSummary summary = ConnectionProber.BuildSummary(new[]
		{
			Probe(22, "ssh", false, false),
			Probe(8729, "api-ssl", true, false),
			Probe(443, "https", true, true),
		});

		Assert.False(summary.ApiSslAvailable);
		Assert.False(summary.SshAvailable);
		Assert.Contains("Neither SSH", summary.Recommendation);
	}
}
