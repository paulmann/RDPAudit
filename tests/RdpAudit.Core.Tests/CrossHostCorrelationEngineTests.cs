/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// File   : CrossHostCorrelationEngineTests.cs
// Project: RdpAudit.Core.Tests (RdpAudit.Core.Tests)
// Purpose: Locks the pure cross-host correlation engine: happy path, clock skew, dedup,
//          fail-closed host availability, bounded flood processing and determinism.
// Depends: RdpAudit.Core.CrossHost, xUnit
// Extends: Add a test whenever a new chain rule hops configuration ships in CrossHostRules.

using RdpAudit.Core.CrossHost;
using Xunit;

namespace RdpAudit.Core.Tests;

/// <summary>Unit tests for the pure deterministic cross-host correlation engine.</summary>
public class CrossHostCorrelationEngineTests
{
	private static readonly DateTime BaselineUtc = new DateTime(2026, 9, 10, 12, 0, 0, DateTimeKind.Utc);

	private static CrossHostFactProjection Fact(
		string host,
		string user,
		CrossHostFactKind kind,
		int eventId,
		DateTime timeUtc,
		string? sourceIp = null)
	{
		CrossHostFactProjection fact = new CrossHostFactProjection
		{
			HostName = host,
			UserName = user,
			NormalizedUserName = user.ToLowerInvariant(),
			Kind = kind,
			EventId = eventId,
			TimeUtc = timeUtc,
			SourceIp = sourceIp,
		};
		fact.DedupKey = fact.BuildDedupKey();
		return fact;
	}

	private static List<CrossHostAvailabilityView> Available(params string[] hosts) =>
		hosts.Select(h => new CrossHostAvailabilityView(h, CrossHostAvailability.Available, BaselineUtc, null)).ToList();

	private static List<CrossHostAvailabilityView> Availability(params (string Host, CrossHostAvailability Status)[] items) =>
		items.Select(i => new CrossHostAvailabilityView(i.Host, i.Status, BaselineUtc, null)).ToList();

	[Fact]
	public void HappyPath_FailedOnA_SuccessOnB_PrivilegedOnC_ProducesExactlyOneChain()
	{
		// Given: 3 failed logons on host A, then success on B, then privileged logon on C,
		// all for the same user inside the chain window.
		List<CrossHostFactProjection> facts = new List<CrossHostFactProjection>
		{
			Fact("HOST-A", "victim", CrossHostFactKind.FailedLogon, 4625, BaselineUtc.AddMinutes(-10), "203.0.113.7"),
			Fact("HOST-A", "victim", CrossHostFactKind.FailedLogon, 4625, BaselineUtc.AddMinutes(-9), "203.0.113.7"),
			Fact("HOST-A", "victim", CrossHostFactKind.FailedLogon, 4625, BaselineUtc.AddMinutes(-8), "203.0.113.7"),
			Fact("HOST-A", "victim", CrossHostFactKind.FailedLogon, 4625, BaselineUtc.AddMinutes(-7), "203.0.113.7"),
			Fact("HOST-B", "victim", CrossHostFactKind.SuccessfulLogon, 4624, BaselineUtc.AddMinutes(-4)),
			Fact("HOST-C", "victim", CrossHostFactKind.PrivilegedLogon, 4672, BaselineUtc.AddMinutes(-1)),
		};

		CrossHostCorrelationEngine engine = new CrossHostCorrelationEngine();

		// When
		CrossHostCorrelationResult result = engine.Correlate(facts, Available("HOST-A", "HOST-B", "HOST-C"), BaselineUtc);

		// Then
		CrossHostChainCandidate chain = Assert.Single(result.Chains);
		Assert.Equal("RDP_LATERAL_MOVEMENT", chain.RuleId);
		Assert.Equal("victim", chain.NormalizedUserName);
		Assert.Equal(3, chain.Links.Count);
		Assert.Equal("HOST-A", chain.Links[0].HostName);
		Assert.Equal("HOST-B", chain.Links[1].HostName);
		Assert.Equal("HOST-C", chain.Links[2].HostName);
		Assert.Equal(CrossHostFactKind.FailedLogon, chain.Links[0].Kind);
		Assert.Equal(CrossHostFactKind.SuccessfulLogon, chain.Links[1].Kind);
		Assert.Equal(CrossHostFactKind.PrivilegedLogon, chain.Links[2].Kind);
		Assert.True(chain.FailedAttemptCount >= 3);
		Assert.NotEmpty(chain.ChainKey);
		Assert.Equal(6, result.FactsAccepted);
		Assert.Equal(0, result.FactsRejected);
	}

	[Fact]
	public void MissingMiddleHop_DoesNotProduceChain()
	{
		// Given: failed logons on A and privileged on C, but the middle 4624 hop is absent.
		List<CrossHostFactProjection> facts = new List<CrossHostFactProjection>
		{
			Fact("HOST-A", "victim", CrossHostFactKind.FailedLogon, 4625, BaselineUtc.AddMinutes(-9), "203.0.113.7"),
			Fact("HOST-A", "victim", CrossHostFactKind.FailedLogon, 4625, BaselineUtc.AddMinutes(-8), "203.0.113.7"),
			Fact("HOST-A", "victim", CrossHostFactKind.FailedLogon, 4625, BaselineUtc.AddMinutes(-7), "203.0.113.7"),
			Fact("HOST-C", "victim", CrossHostFactKind.PrivilegedLogon, 4672, BaselineUtc.AddMinutes(-1)),
		};

		CrossHostCorrelationEngine engine = new CrossHostCorrelationEngine();

		// When
		CrossHostCorrelationResult result = engine.Correlate(facts, Available("HOST-A", "HOST-C"), BaselineUtc);

		// Then
		Assert.Empty(result.Chains);
	}

	[Fact]
	public void UnavailableHost_ContributesNoLinks()
	{
		// Given: a full candidate sequence, but HOST-B is unavailable.
		List<CrossHostFactProjection> facts = new List<CrossHostFactProjection>
		{
			Fact("HOST-A", "victim", CrossHostFactKind.FailedLogon, 4625, BaselineUtc.AddMinutes(-9), "203.0.113.7"),
			Fact("HOST-A", "victim", CrossHostFactKind.FailedLogon, 4625, BaselineUtc.AddMinutes(-8), "203.0.113.7"),
			Fact("HOST-A", "victim", CrossHostFactKind.FailedLogon, 4625, BaselineUtc.AddMinutes(-7), "203.0.113.7"),
			Fact("HOST-B", "victim", CrossHostFactKind.SuccessfulLogon, 4624, BaselineUtc.AddMinutes(-4)),
			Fact("HOST-C", "victim", CrossHostFactKind.PrivilegedLogon, 4672, BaselineUtc.AddMinutes(-1)),
		};

		CrossHostCorrelationEngine engine = new CrossHostCorrelationEngine();

		// When
		CrossHostCorrelationResult result = engine.Correlate(
			facts,
			Availability(("HOST-A", CrossHostAvailability.Available), ("HOST-B", CrossHostAvailability.Unavailable), ("HOST-C", CrossHostAvailability.Available)),
			BaselineUtc);

		// Then: B's fact is dropped, so no chain can be built.
		Assert.Empty(result.Chains);
		Assert.True(result.FactsRejected >= 1);
	}

	[Fact]
	public void AbsentHost_FactIsRejected_FailClosed()
	{
		// A fact persisted under an IP/machine alias becomes "available" only through a successful
		// pull. When the host is down the alias is absent from the availability map; an absent host
		// must contribute nothing rather than being assumed available.
		List<CrossHostFactProjection> facts = new List<CrossHostFactProjection>
		{
			Fact("HOST-A", "victim", CrossHostFactKind.FailedLogon, 4625, BaselineUtc.AddMinutes(-9), "203.0.113.7"),
			Fact("HOST-A", "victim", CrossHostFactKind.FailedLogon, 4625, BaselineUtc.AddMinutes(-8), "203.0.113.7"),
			Fact("HOST-A", "victim", CrossHostFactKind.FailedLogon, 4625, BaselineUtc.AddMinutes(-7), "203.0.113.7"),
			Fact("HOST-B", "victim", CrossHostFactKind.SuccessfulLogon, 4624, BaselineUtc.AddMinutes(-4)),
			Fact("HOST-C", "victim", CrossHostFactKind.PrivilegedLogon, 4672, BaselineUtc.AddMinutes(-1)),
		};

		CrossHostCorrelationEngine engine = new CrossHostCorrelationEngine();

		// HOST-B is absent (dead host under an alias); only A and C are positively Available.
		CrossHostCorrelationResult result = engine.Correlate(facts, Available("HOST-A", "HOST-C"), BaselineUtc);

		Assert.Empty(result.Chains);
		Assert.True(result.FactsRejected >= 1);
	}

	[Fact]
	public void DuplicateFacts_AreDeduplicated()
	{
		// Given: the exact same host/time/kind fact twice via different object instances.
		CrossHostFactProjection first = Fact("HOST-A", "victim", CrossHostFactKind.FailedLogon, 4625, BaselineUtc.AddMinutes(-9), "203.0.113.7");
		CrossHostFactProjection duplicate = Fact("HOST-A", "victim", CrossHostFactKind.FailedLogon, 4625, BaselineUtc.AddMinutes(-9), "203.0.113.7");
		List<CrossHostFactProjection> facts = new List<CrossHostFactProjection>
		{
			first,
			duplicate,
			Fact("HOST-A", "victim", CrossHostFactKind.FailedLogon, 4625, BaselineUtc.AddMinutes(-8), "203.0.113.7"),
			Fact("HOST-A", "victim", CrossHostFactKind.FailedLogon, 4625, BaselineUtc.AddMinutes(-7), "203.0.113.7"),
			Fact("HOST-B", "victim", CrossHostFactKind.SuccessfulLogon, 4624, BaselineUtc.AddMinutes(-4)),
			Fact("HOST-C", "victim", CrossHostFactKind.PrivilegedLogon, 4672, BaselineUtc.AddMinutes(-1)),
		};

		CrossHostCorrelationEngine engine = new CrossHostCorrelationEngine();

		// When
		CrossHostCorrelationResult result = engine.Correlate(facts, Available("HOST-A", "HOST-B", "HOST-C"), BaselineUtc);

		// Then: duplicate counted, but only one chain and one accepted copy per key.
		Assert.Single(result.Chains);
		Assert.Equal(1, result.FactsDuplicated);
	}

	[Fact]
	public void ClockSkew_ToleratedWithinTolerance()
	{
		// Given: B's clock is 30 seconds ahead of A's; the 4624 event arrives 10 seconds
		// "later" than the window would allow but still inside the skew tolerance.
		List<CrossHostFactProjection> facts = new List<CrossHostFactProjection>
		{
			Fact("HOST-A", "victim", CrossHostFactKind.FailedLogon, 4625, BaselineUtc.AddMinutes(-5), "203.0.113.7"),
			Fact("HOST-A", "victim", CrossHostFactKind.FailedLogon, 4625, BaselineUtc.AddMinutes(-4), "203.0.113.7"),
			Fact("HOST-A", "victim", CrossHostFactKind.FailedLogon, 4625, BaselineUtc.AddMinutes(-3), "203.0.113.7"),
			Fact("HOST-B", "victim", CrossHostFactKind.SuccessfulLogon, 4624, BaselineUtc.AddMinutes(-1).AddSeconds(30)),
			Fact("HOST-C", "victim", CrossHostFactKind.PrivilegedLogon, 4672, BaselineUtc.AddMinutes(0)),
		};

		CrossHostCorrelationEngine engine = new CrossHostCorrelationEngine();

		// When
		CrossHostCorrelationResult result = engine.Correlate(facts, Available("HOST-A", "HOST-B", "HOST-C"), BaselineUtc);

		// Then
		Assert.Single(result.Chains);
	}

	[Fact]
	public void Deterministic_ResultAcrossRepeatedPasses()
	{
		// Given: the same facts with varied insertion order.
		List<CrossHostFactProjection> facts = new List<CrossHostFactProjection>
		{
			Fact("HOST-A", "victim", CrossHostFactKind.FailedLogon, 4625, BaselineUtc.AddMinutes(-10), "203.0.113.7"),
			Fact("HOST-A", "victim", CrossHostFactKind.FailedLogon, 4625, BaselineUtc.AddMinutes(-9), "203.0.113.7"),
			Fact("HOST-A", "victim", CrossHostFactKind.FailedLogon, 4625, BaselineUtc.AddMinutes(-8), "203.0.113.7"),
			Fact("HOST-B", "victim", CrossHostFactKind.SuccessfulLogon, 4624, BaselineUtc.AddMinutes(-4)),
			Fact("HOST-C", "victim", CrossHostFactKind.PrivilegedLogon, 4672, BaselineUtc.AddMinutes(-1)),
		};
		List<CrossHostFactProjection> shuffled = facts.OrderBy(f => Guid.NewGuid()).ToList();

		CrossHostCorrelationEngine engine = new CrossHostCorrelationEngine();

		// When
		CrossHostCorrelationResult a = engine.Correlate(facts, Available("HOST-A", "HOST-B", "HOST-C"), BaselineUtc);
		CrossHostCorrelationResult b = engine.Correlate(shuffled, Available("HOST-A", "HOST-B", "HOST-C"), BaselineUtc);

		// Then: identical chain sets (the engine sorts internally).
		Assert.Equal(a.Chains.Count, b.Chains.Count);
		Assert.Equal(a.Chains.Single().ChainKey, b.Chains.Single().ChainKey);
		Assert.Equal(a.Chains.Single().Links.Select(l => $"{l.HostName}:{l.Kind}"), b.Chains.Single().Links.Select(l => $"{l.HostName}:{l.Kind}"));
	}

	[Fact]
	public void KnownChainKeys_SuppressReemission()
	{
		// Given: a chain was already persisted in a previous pass.
		List<CrossHostFactProjection> facts = new List<CrossHostFactProjection>
		{
			Fact("HOST-A", "victim", CrossHostFactKind.FailedLogon, 4625, BaselineUtc.AddMinutes(-9), "203.0.113.7"),
			Fact("HOST-A", "victim", CrossHostFactKind.FailedLogon, 4625, BaselineUtc.AddMinutes(-8), "203.0.113.7"),
			Fact("HOST-A", "victim", CrossHostFactKind.FailedLogon, 4625, BaselineUtc.AddMinutes(-7), "203.0.113.7"),
			Fact("HOST-B", "victim", CrossHostFactKind.SuccessfulLogon, 4624, BaselineUtc.AddMinutes(-4)),
			Fact("HOST-C", "victim", CrossHostFactKind.PrivilegedLogon, 4672, BaselineUtc.AddMinutes(-1)),
		};

		CrossHostCorrelationEngine engine = new CrossHostCorrelationEngine();

		// When: first pass computes the key, second pass feeds it back as known.
		CrossHostCorrelationResult first = engine.Correlate(facts, Available("HOST-A", "HOST-B", "HOST-C"), BaselineUtc);
		string key = first.Chains.Single().ChainKey;
		CrossHostCorrelationResult second = engine.Correlate(facts, Available("HOST-A", "HOST-B", "HOST-C"), BaselineUtc, new HashSet<string> { key });

		// Then
		Assert.Empty(second.Chains);
	}

	[Fact]
	public void FloodOfFacts_IsBoundedAndTerminates()
	{
		// Given: 1200 facts from one host (200 failed per 60-second bucket) - over the
		// per-host default cap of 1000 - plus a noise host with 500 facts.
		List<CrossHostFactProjection> facts = new List<CrossHostFactProjection>();
		DateTime baseTime = BaselineUtc.AddHours(-1);
		for (int bucket = 0; bucket < 6; bucket++)
		{
			for (int i = 0; i < 200; i++)
			{
				facts.Add(Fact("HOST-A", "flood", CrossHostFactKind.FailedLogon, 4625, baseTime.AddSeconds((bucket * 60) + (i % 60) / 2.0 + bucket * 0.001), "198.51.100.1"));
			}
		}

		for (int i = 0; i < 500; i++)
		{
			facts.Add(Fact("HOST-B", "flood", CrossHostFactKind.SuccessfulLogon, 4624, baseTime.AddSeconds(i)));
		}

		CrossHostCorrelationEngine engine = new CrossHostCorrelationEngine();

		// When / Then: terminates with a bounded accepted set and no uncaught exception.
		CrossHostCorrelationResult result = engine.Correlate(facts, Available("HOST-A", "HOST-B"), BaselineUtc);
		Assert.True(result.FactsAccepted <= 2000);
		Assert.True(result.FactsDuplicated <= 1700);
	}

	[Fact]
	public void MalformedFacts_AreRejected()
	{
		// Given: a fact with an empty host, a Kind sentinel, and a speculative far-future fact.
		List<CrossHostFactProjection> facts = new List<CrossHostFactProjection>
		{
			Fact(string.Empty, "victim", CrossHostFactKind.FailedLogon, 4625, BaselineUtc.AddMinutes(-1), "203.0.113.7"),
			Fact("HOST-A", "victim", CrossHostFactKind.Unknown, 4625, BaselineUtc.AddMinutes(-1)),
			Fact("HOST-A", "victim", CrossHostFactKind.FailedLogon, 4625, new DateTime(2300, 1, 1, 0, 0, 0, DateTimeKind.Utc)),
			Fact("HOST-A", "victim", CrossHostFactKind.FailedLogon, 4625, BaselineUtc.AddMinutes(-1), "203.0.113.7"),
			Fact("HOST-A", "victim", CrossHostFactKind.FailedLogon, 4625, BaselineUtc.AddMinutes(0), "203.0.113.7"),
			Fact("HOST-A", "victim", CrossHostFactKind.FailedLogon, 4625, BaselineUtc.AddMinutes(1), "203.0.113.7"),
			Fact("HOST-B", "victim", CrossHostFactKind.SuccessfulLogon, 4624, BaselineUtc.AddMinutes(4)),
			Fact("HOST-C", "victim", CrossHostFactKind.PrivilegedLogon, 4672, BaselineUtc.AddMinutes(5)),
		};

		CrossHostCorrelationEngine engine = new CrossHostCorrelationEngine();

		// When
		CrossHostCorrelationResult result = engine.Correlate(facts, Available("HOST-A", "HOST-B", "HOST-C"), BaselineUtc.AddMinutes(6));

		// Then: malformed facts were rejected and a single chain arrived.
		Assert.True(result.FactsRejected >= 3);
		Assert.Single(result.Chains);
	}

	[Fact]
	public void SameHostSequence_DoesNotFormLateralChain()
	{
		// Given: all three hops on the same host (no lateral movement).
		List<CrossHostFactProjection> facts = new List<CrossHostFactProjection>
		{
			Fact("HOST-A", "victim", CrossHostFactKind.FailedLogon, 4625, BaselineUtc.AddMinutes(-9), "203.0.113.7"),
			Fact("HOST-A", "victim", CrossHostFactKind.FailedLogon, 4625, BaselineUtc.AddMinutes(-8), "203.0.113.7"),
			Fact("HOST-A", "victim", CrossHostFactKind.FailedLogon, 4625, BaselineUtc.AddMinutes(-7), "203.0.113.7"),
			Fact("HOST-A", "victim", CrossHostFactKind.SuccessfulLogon, 4624, BaselineUtc.AddMinutes(-4)),
			Fact("HOST-A", "victim", CrossHostFactKind.PrivilegedLogon, 4672, BaselineUtc.AddMinutes(-1)),
		};

		CrossHostCorrelationEngine engine = new CrossHostCorrelationEngine();

		// When
		CrossHostCorrelationResult result = engine.Correlate(facts, Available("HOST-A"), BaselineUtc);

		// Then
		Assert.Empty(result.Chains);
	}

	[Fact]
	public void ChainSpanningLongerThanMaxChainSpan_IsRejected_EvenWhenEachHopFits()
	{
		// Two 100-minute gaps: each hop is inside the 120-minute window, but the whole chain spans
		// 198 minutes and must be rejected by the per-chain bound (the per-hop check alone accepted it).
		List<CrossHostFactProjection> facts = new List<CrossHostFactProjection>
		{
			Fact("HOST-A", "victim", CrossHostFactKind.FailedLogon, 4625, BaselineUtc.AddMinutes(-200), "203.0.113.7"),
			Fact("HOST-A", "victim", CrossHostFactKind.FailedLogon, 4625, BaselineUtc.AddMinutes(-199), "203.0.113.7"),
			Fact("HOST-A", "victim", CrossHostFactKind.FailedLogon, 4625, BaselineUtc.AddMinutes(-198), "203.0.113.7"),
			Fact("HOST-B", "victim", CrossHostFactKind.SuccessfulLogon, 4624, BaselineUtc.AddMinutes(-100)),
			Fact("HOST-C", "victim", CrossHostFactKind.PrivilegedLogon, 4672, BaselineUtc),
		};

		CrossHostCorrelationEngine engine = new CrossHostCorrelationEngine();

		CrossHostCorrelationResult result = engine.Correlate(facts, Available("HOST-A", "HOST-B", "HOST-C"), BaselineUtc);

		Assert.Empty(result.Chains);
	}

	[Fact]
	public void BuildDedupKey_DistinguishesTwoFactsInTheSameSecond()
	{
		// Second-precision keys collapsed two distinct failed logons (a spray) into one row.
		CrossHostFactProjection first = Fact("HOST-A", "victim", CrossHostFactKind.FailedLogon, 4625, BaselineUtc);
		CrossHostFactProjection second = Fact("HOST-A", "victim", CrossHostFactKind.FailedLogon, 4625, BaselineUtc.AddMilliseconds(250));

		Assert.NotEqual(first.DedupKey, second.DedupKey);
	}

	[Fact]
	public void BuildDedupKey_IsStableAcrossHostAndUserCasing()
	{
		CrossHostFactProjection first = Fact("HOST-A", "victim", CrossHostFactKind.FailedLogon, 4625, BaselineUtc);
		CrossHostFactProjection second = Fact("host-a", "VICTIM", CrossHostFactKind.FailedLogon, 4625, BaselineUtc);

		Assert.Equal(first.DedupKey, second.DedupKey);
	}
}
