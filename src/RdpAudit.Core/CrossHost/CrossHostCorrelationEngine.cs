// File:    src/RdpAudit.Core/CrossHost/CrossHostCorrelationEngine.cs
// Module:  RdpAudit.Core.CrossHost
// Purpose: Pure, deterministic cross-host correlation engine. Turns a set of host fact
//          projections plus per-host availability into deduplicated attack-chain candidates
//          using data-driven rules. No I/O, no EF Core, no clock reads other than the supplied
//          nowUtc - every output is a pure function of the inputs so the engine is fully
//          unit-testable and adversarial input can never cause unbounded work.
//          Trust boundary: facts are UNTRUSTED external data; every fact is validated, every
//          host that is unavailable contributes zero links (fail-closed), and per-host input
//          is bounded so a flooding agent can never exhaust memory.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

namespace RdpAudit.Core.CrossHost;

/// <summary>Pure deterministic engine described in the file Purpose header.</summary>
public sealed class CrossHostCorrelationEngine
{
	private readonly IReadOnlyList<CrossHostChainRule> _rules;

	public CrossHostCorrelationEngine(IReadOnlyList<CrossHostChainRule>? rules = null)
	{
		_rules = rules is { Count: > 0 } ? rules : new List<CrossHostChainRule> { CrossHostChainRule.CreateDefault() };
	}

	/// <summary>Runs one correlation pass. <paramref name="knownChainKeys"/> holds the dedup keys
	/// of chains that were already persisted in previous passes; candidates whose key is already
	/// known are skipped so a re-pull of the same facts never re-emits a chain.</summary>
	public CrossHostCorrelationResult Correlate(
		IEnumerable<CrossHostFactProjection> facts,
		IEnumerable<CrossHostAvailabilityView> hostAvailability,
		DateTime nowUtc,
		ISet<string>? knownChainKeys = null)
	{
		CrossHostCorrelationResult result = new CrossHostCorrelationResult();

		Dictionary<string, CrossHostAvailability> availabilityByHost = BuildAvailabilityMap(hostAvailability);
		int perHostCap = _rules.Max(r => r.MaxFactsPerHost ?? CrossHostChainRule.DefaultMaxFactsPerHost);
		List<CrossHostFactProjection> accepted = ValidateAndDedupeFacts(facts, availabilityByHost, perHostCap, result);

		foreach (CrossHostChainRule rule in _rules)
		{
			CorrelateRule(rule, accepted, nowUtc, knownChainKeys, result);
		}

		return result;
	}

	private static Dictionary<string, CrossHostAvailability> BuildAvailabilityMap(IEnumerable<CrossHostAvailabilityView> hostAvailability)
	{
		Dictionary<string, CrossHostAvailability> map = new(StringComparer.OrdinalIgnoreCase);
		foreach (CrossHostAvailabilityView view in hostAvailability)
		{
			if (string.IsNullOrWhiteSpace(view.HostName))
			{
				continue;
			}

			map[view.HostName.Trim()] = view.Availability;
		}

		return map;
	}

	/// <summary>First trust boundary: reject malformed facts, drop facts from unavailable hosts,
	/// deduplicate by stable key, and bound the per-host contribution to the newest slice.</summary>
	private static List<CrossHostFactProjection> ValidateAndDedupeFacts(
		IEnumerable<CrossHostFactProjection> facts,
		Dictionary<string, CrossHostAvailability> availabilityByHost,
		int perHostCap,
		CrossHostCorrelationResult result)
	{
		Dictionary<string, CrossHostFactProjection> byDedupKey = new(StringComparer.Ordinal);
		Dictionary<string, List<CrossHostFactProjection>> byHost = new(StringComparer.OrdinalIgnoreCase);

		foreach (CrossHostFactProjection fact in facts)
		{
			if (fact is null)
			{
				result.FactsRejected++;
				continue;
			}

			if (!fact.IsValid())
			{
				result.FactsRejected++;
				continue;
			}

			string hostKey = fact.HostName.Trim();

			// Fail-closed: a fact contributes only when its host is POSITIVELY known Available this
			// pass. An absent host is treated exactly like an unavailable one — a fact persisted
			// under an IP/machine alias only becomes Available when a pull succeeds, so after the
			// host goes down the alias is absent from the map. If "absent" were accepted, a dead
			// host's stale rows would re-enter correlation. Unknown contributing nothing also
			// matches the product rule "unknown external answer means no data".
			if (!availabilityByHost.TryGetValue(hostKey, out CrossHostAvailability availability) ||
				availability != CrossHostAvailability.Available)
			{
				result.FactsRejected++;
				continue;
			}

			string dedupKey = string.IsNullOrWhiteSpace(fact.DedupKey) ? fact.BuildDedupKey() : fact.DedupKey;
			if (byDedupKey.ContainsKey(dedupKey))
			{
				result.FactsDuplicated++;
				continue;
			}

			byDedupKey[dedupKey] = fact;

			if (!byHost.TryGetValue(hostKey, out List<CrossHostFactProjection>? hostFacts))
			{
				hostFacts = new List<CrossHostFactProjection>();
				byHost[hostKey] = hostFacts;
			}

			hostFacts.Add(fact);
		}

		// Bounded per host: keep only the newest slice so a flooding agent cannot grow the
		// working set without limit. Ordering is deterministic (time desc, then host).
		List<CrossHostFactProjection> accepted = new List<CrossHostFactProjection>();
		foreach (KeyValuePair<string, List<CrossHostFactProjection>> pair in byHost)
		{
			List<CrossHostFactProjection> hostFacts = pair.Value;
			hostFacts.Sort((a, b) =>
			{
				int timeCompare = b.TimeUtc.CompareTo(a.TimeUtc);
				return timeCompare != 0 ? timeCompare : string.Compare(a.HostName, b.HostName, StringComparison.OrdinalIgnoreCase);
			});

			int take = Math.Min(hostFacts.Count, perHostCap);
			accepted.AddRange(hostFacts.GetRange(0, take));
		}

		result.FactsAccepted = accepted.Count;
		return accepted;
	}

	private void CorrelateRule(
		CrossHostChainRule rule,
		List<CrossHostFactProjection> accepted,
		DateTime nowUtc,
		ISet<string>? knownChainKeys,
		CrossHostCorrelationResult result)
	{
		if (rule.Hops.Count < 2)
		{
			return;
		}

		DateTime maxAgeCutoff = nowUtc.AddHours(-Math.Max(1, rule.MaxFactAgeHours));
		double windowTicks = TimeSpan.FromMinutes(Math.Max(1, rule.MaxChainSpanMinutes)).Ticks;
		double skewTicks = TimeSpan.FromSeconds(Math.Max(0, rule.ClockSkewToleranceSeconds)).Ticks;

		// Group facts by normalized user, ordered deterministically for reproducible output.
		Dictionary<string, List<CrossHostFactProjection>> byUser = new(StringComparer.OrdinalIgnoreCase);
		foreach (CrossHostFactProjection fact in accepted)
		{
			if (fact.TimeUtc < maxAgeCutoff)
			{
				continue;
			}

			string userKey = fact.NormalizedUserName ?? string.Empty;
			if (!byUser.TryGetValue(userKey, out List<CrossHostFactProjection>? userFacts))
			{
				userFacts = new List<CrossHostFactProjection>();
				byUser[userKey] = userFacts;
			}

			userFacts.Add(fact);
		}

		foreach (KeyValuePair<string, List<CrossHostFactProjection>> pair in byUser)
		{
			List<CrossHostFactProjection> userFacts = pair.Value;
			userFacts.Sort((a, b) =>
			{
				int timeCompare = a.TimeUtc.CompareTo(b.TimeUtc);
				if (timeCompare != 0)
				{
					return timeCompare;
				}

				int hostCompare = string.Compare(a.HostName, b.HostName, StringComparison.OrdinalIgnoreCase);
				return hostCompare != 0 ? hostCompare : ((int)a.Kind).CompareTo((int)b.Kind);
			});

			MatchChainsForUser(rule, pair.Key, userFacts, windowTicks, skewTicks, nowUtc, knownChainKeys, result);
		}
	}

	private void MatchChainsForUser(
		CrossHostChainRule rule,
		string normalizedUser,
		List<CrossHostFactProjection> userFacts,
		double windowTicks,
		double skewTicks,
		DateTime nowUtc,
		ISet<string>? knownChainKeys,
		CrossHostCorrelationResult result)
	{
		int hopCount = rule.Hops.Count;
		HashSet<string> emittedKeys = new(StringComparer.Ordinal);

		// Sliding scan: for every fact that matches the LAST hop, walk backwards through the
		// template to find a complete ordered multi-host sequence. Greedy per anchor keeps the
		// result deterministic (the earliest qualifying link sequence wins for a given anchor).
		for (int anchorIndex = userFacts.Count - 1; anchorIndex >= 0; anchorIndex--)
		{
			CrossHostFactProjection anchor = userFacts[anchorIndex];
			if (!MatchesHop(rule, hopCount - 1, anchor))
			{
				continue;
			}

			List<CrossHostFactProjection>? links = TryBuildChain(rule, userFacts, anchorIndex, windowTicks, skewTicks);
			if (links is null)
			{
				continue;
			}

			int failedCount = CountFailedLogons(userFacts, links[0].TimeUtc, windowTicks);
			if (failedCount < rule.MinFailedAttempts)
			{
				continue;
			}

			List<(string HostName, CrossHostFactKind Kind)> hopPairs = new(links.Count);
			foreach (CrossHostFactProjection link in links)
			{
				hopPairs.Add((link.HostName.Trim(), link.Kind));
			}

			string chainKey = CrossHostStableHash.ComputeChainKey(normalizedUser, hopPairs);
			if (knownChainKeys is not null && knownChainKeys.Contains(chainKey))
			{
				continue;
			}

			if (!emittedKeys.Add(chainKey))
			{
				continue;
			}

			CrossHostChainCandidate candidate = new CrossHostChainCandidate
			{
				RuleId = rule.RuleId,
				ChainKey = chainKey,
				NormalizedUserName = normalizedUser,
				FirstSeenUtc = links[0].TimeUtc,
				LastSeenUtc = links[links.Count - 1].TimeUtc,
				FailedAttemptCount = failedCount,
			};

			foreach (CrossHostFactProjection link in links)
			{
				candidate.Links.Add(new CrossHostChainLinkCandidate
				{
					HostName = link.HostName.Trim(),
					Kind = link.Kind,
					EventId = link.EventId,
					TimeUtc = link.TimeUtc,
					SourceIp = link.SourceIp,
					UserName = link.UserName,
				});
			}

			candidate.Score = rule.ComputeScore(failedCount, candidate.Links.Count, candidate.FirstSeenUtc, candidate.LastSeenUtc, nowUtc);
			result.Chains.Add(candidate);
		}
	}

	private static bool MatchesHop(CrossHostChainRule rule, int hopIndex, CrossHostFactProjection fact)
	{
		CrossHostRuleHopMarker hop = rule.Hops[hopIndex];
		return fact.Kind == hop.Kind && fact.EventId == hop.EventId;
	}

	/// <summary>Attempts to build the hop sequence ending at <paramref name="anchorIndex"/> by
	/// walking the template backwards. Each predecessor must be a DIFFERENT host than the link
	/// it attaches to and must fall inside the chain window; clock skew is tolerated by allowing
	/// a predecessor to appear up to skewTicks AFTER its successor's timestamp (clocks may differ
	/// between hosts). Returns null when the template cannot be satisfied.</summary>
	private List<CrossHostFactProjection>? TryBuildChain(
		CrossHostChainRule rule,
		List<CrossHostFactProjection> userFacts,
		int anchorIndex,
		double windowTicks,
		double skewTicks)
	{
		List<CrossHostFactProjection> links = new List<CrossHostFactProjection>(rule.Hops.Count);
		links.Add(userFacts[anchorIndex]);
		int currentIndex = anchorIndex;

		for (int hopIndex = rule.Hops.Count - 2; hopIndex >= 0; hopIndex--)
		{
			CrossHostFactProjection current = links[0];

			// Search backwards from the current link for the nearest earlier fact matching this hop.
			int found = -1;
			for (int candidateIndex = currentIndex - 1; candidateIndex >= 0; candidateIndex--)
			{
				CrossHostFactProjection candidateFact = userFacts[candidateIndex];
				if (!MatchesHop(rule, hopIndex, candidateFact))
				{
					continue;
				}

				if (string.Equals(candidateFact.HostName.Trim(), current.HostName.Trim(), StringComparison.OrdinalIgnoreCase))
				{
					// Same host: a lateral-movement chain requires distinct hosts per hop, but the
					// backward scan must keep looking for an earlier cross-host link.
					continue;
				}

				double deltaTicks = (double)(current.TimeUtc.Ticks - candidateFact.TimeUtc.Ticks);
				if (deltaTicks + skewTicks < 0)
				{
					continue;
				}

				if (deltaTicks > windowTicks + skewTicks)
				{
					continue;
				}

				found = candidateIndex;
				break;
			}

			if (found < 0)
			{
				return null;
			}

			links.Insert(0, userFacts[found]);
			currentIndex = found;
		}

		if (links.Count != rule.Hops.Count)
		{
			return null;
		}

		// Bound the TOTAL span, not just each consecutive hop: two 100-minute gaps inside a
		// 120-minute MaxChainSpanMinutes previously passed the per-hop check and produced a
		// 200-minute chain that the rule was supposed to reject.
		double totalSpanTicks = Math.Max(0d, (double)(links[^1].TimeUtc.Ticks - links[0].TimeUtc.Ticks));
		if (totalSpanTicks > windowTicks + skewTicks)
		{
			return null;
		}

		// Distinct-host guard across the whole chain.
		HashSet<string> hosts = new(StringComparer.OrdinalIgnoreCase);
		foreach (CrossHostFactProjection link in links)
		{
			hosts.Add(link.HostName.Trim());
		}

		if (hosts.Count < rule.MinHostCount)
		{
			return null;
		}

		return links;
	}

	private static int CountFailedLogons(List<CrossHostFactProjection> userFacts, DateTime firstTimeUtc, double windowTicks)
	{
		int count = 0;
		foreach (CrossHostFactProjection fact in userFacts)
		{
			if (fact.Kind != CrossHostFactKind.FailedLogon)
			{
				continue;
			}

			double deltaTicks = (double)(fact.TimeUtc.Ticks - firstTimeUtc.Ticks);
			if (deltaTicks >= -windowTicks && deltaTicks <= windowTicks)
			{
				count++;
			}
		}

		return count;
	}
}
