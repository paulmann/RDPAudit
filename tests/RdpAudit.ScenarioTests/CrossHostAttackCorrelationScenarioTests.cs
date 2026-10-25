/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// File   : CrossHostAttackCorrelationScenarioTests.cs
// Project: RdpAudit.ScenarioTests
// Purpose: P4-18 Step 10 scenario fixture. Walks the cross-host correlation flow the way the
//          central service would: three configured agent hosts export fact projections, every
//          host availability view is supplied, and the pure Core engine must emit exactly the
//          documented lateral-movement chain - or nothing at all when a hop host goes
//          unavailable (fail-closed). Covers positive and negative user scenarios without any
//          I/O, EF Core or named pipes.
// Depends: RdpAudit.Core.CrossHost, xunit
// Extends: Add a scenario here whenever the default rule catalogue gains a new chain template.

using RdpAudit.Core.CrossHost;
using Xunit;

namespace RdpAudit.ScenarioTests;

public sealed class CrossHostAttackCorrelationScenarioTests
{
	private static readonly DateTime NowUtc = new(2026, 9, 11, 12, 0, 0, DateTimeKind.Utc);

	private static CrossHostFactProjection Fact(string host, DateTime timeUtc, string user, CrossHostFactKind kind, int eventId, string? sourceIp = null)
	{
		CrossHostFactProjection fact = new()
		{
			HostName = host,
			TimeUtc = timeUtc,
			UserName = user,
			// The agent-side exporter canonicalizes the user key (domain-stripped, lower-case)
			// before shipping the projection; the scenario fixture mirrors that contract.
			NormalizedUserName = user[(user.LastIndexOf('\\') + 1)..].ToLowerInvariant(),
			SourceIp = sourceIp,
			Kind = kind,
			EventId = eventId,
		};
		fact.DedupKey = fact.BuildDedupKey();
		return fact;
	}

	private static CrossHostAvailabilityView Available(string host)
		=> new(host, CrossHostAvailability.Available, NowUtc.AddMinutes(-1), null);

	private static List<CrossHostFactProjection> BuildThreeHostFixture()
	{
		List<CrossHostFactProjection> facts = new();

		// SRV-A: 5 failed logons for alice (4625) - satisfies MinFailedAttempts=3.
		for (int i = 0; i < 5; i++)
		{
			facts.Add(Fact("SRV-A", NowUtc.AddMinutes(-20 + i), "DOMAIN\\alice", CrossHostFactKind.FailedLogon, 4625, "203.0.113.10"));
		}

		// SRV-B: successful logon (4624), within the chain window.
		facts.Add(Fact("SRV-B", NowUtc.AddMinutes(-5), "DOMAIN\\alice", CrossHostFactKind.SuccessfulLogon, 4624, "203.0.113.11"));

		// SRV-C: privileged logon (4672), within the chain window.
		facts.Add(Fact("SRV-C", NowUtc.AddMinutes(-2), "DOMAIN\\alice", CrossHostFactKind.PrivilegedLogon, 4672, "203.0.113.12"));

		return facts;
	}

	/// <summary>Given three reachable agent hosts contributed alice's failed (A), successful (B)
	/// and privileged (C) logons in order, when the engine correlates the projections, then
	/// exactly one RDP_LATERAL_MOVEMENT chain must be emitted with the ordered host path
	/// SRV-A -&gt; SRV-B -&gt; SRV-C, at least the rule's failed-attempt floor and a positive score.</summary>
	[Fact]
	public void ThreeAvailableHosts_AttackSequence_EmitsOneChain()
	{
		CrossHostCorrelationEngine engine = new();
		List<CrossHostAvailabilityView> availability = new()
		{
			Available("SRV-A"),
			Available("SRV-B"),
			Available("SRV-C"),
		};

		CrossHostCorrelationResult result = engine.Correlate(BuildThreeHostFixture(), availability, NowUtc);

		CrossHostChainCandidate chain = Assert.Single(result.Chains);
		Assert.Equal("RDP_LATERAL_MOVEMENT", chain.RuleId);
		Assert.Equal("alice", chain.NormalizedUserName);
		Assert.True(chain.FailedAttemptCount >= 3, "chain must carry at least 3 failed attempts");
		Assert.True(chain.Score > 0, "chain must carry a positive risk score");
		Assert.Equal(new[] { "SRV-A", "SRV-B", "SRV-C" }, chain.Links.Select(l => l.HostName).ToArray());
		Assert.Equal(
			new[] { CrossHostFactKind.FailedLogon, CrossHostFactKind.SuccessfulLogon, CrossHostFactKind.PrivilegedLogon },
			chain.Links.Select(l => l.Kind).ToArray());
	}

	/// <summary>Given the same attack sequence but one mid-path agent host went unavailable,
	/// when the engine correlates, then zero chains must be emitted - an unavailable host
	/// contributes no facts and the sequence can never be completed (fail-closed).</summary>
	[Fact]
	public void UnavailableMidPathHost_CompletesNoChain()
	{
		CrossHostCorrelationEngine engine = new();
		List<CrossHostAvailabilityView> availability = new()
		{
			Available("SRV-A"),
			new("SRV-B", CrossHostAvailability.Unavailable, NowUtc.AddMinutes(-10), "pipe connect timeout"),
			Available("SRV-C"),
		};

		CrossHostCorrelationResult result = engine.Correlate(BuildThreeHostFixture(), availability, NowUtc);

		Assert.Empty(result.Chains);
		Assert.True(result.FactsRejected > 0, "facts from the unavailable host must be rejected");
	}
}
