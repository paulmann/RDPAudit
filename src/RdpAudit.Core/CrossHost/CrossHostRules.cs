// File:    src/RdpAudit.Core/CrossHost/CrossHostRules.cs
// Module:  RdpAudit.Core.CrossHost
// Purpose: Data-driven correlation rules for cross-host attack chains. Rules are plain data:
//          each rule declares an ordered sequence of hops through event-id metadata, a
//          required minimum host count, static windows and counters thresholds, and a scoring
//          function. The engine consumes rules without any I/O; adding a new lateral-movement
//          template is a data change plus a unit test, never an engine change.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

namespace RdpAudit.Core.CrossHost;

/// <summary>Marker describing one rule hop in the chain template. All fields use plain value
/// types so a JSON appsettings section can express the same data in the future.</summary>
public readonly record struct CrossHostRuleHopMarker(
	CrossHostFactKind Kind,
	int EventId);

/// <summary>Data-driven definition of one cross-host correlation rule: an ordered hop template
/// plus the windows, counters and dedup parameters the engine applies.</summary>
public sealed class CrossHostChainRule
{
	public CrossHostChainRule(
		string ruleId,
		List<CrossHostRuleHopMarker> hops,
		int minHostCount,
		int clockSkewToleranceSeconds,
		int maxChainSpanMinutes,
		int minFailedAttempts,
		int maxFactAgeHours,
		int? maxFactsPerHost)
	{
		RuleId = ruleId;
		Hops = hops ?? throw new ArgumentNullException(nameof(hops));
		MinHostCount = minHostCount;
		ClockSkewToleranceSeconds = clockSkewToleranceSeconds;
		MaxChainSpanMinutes = maxChainSpanMinutes;
		MinFailedAttempts = minFailedAttempts;
		MaxFactAgeHours = maxFactAgeHours;
		MaxFactsPerHost = maxFactsPerHost;
	}

	public string RuleId { get; }

	public List<CrossHostRuleHopMarker> Hops { get; }

	public int MinHostCount { get; }

	public int ClockSkewToleranceSeconds { get; }

	public int MaxChainSpanMinutes { get; }

	public int MinFailedAttempts { get; }

	public int MaxFactAgeHours { get; }

	public int? MaxFactsPerHost { get; }

	/// <summary>Public default engine thresholds. Production deployment stays with these until an
	/// operator tunes them; the data lives inside the assembly (not config) so the default
	/// behaviour is pinned by unit tests.</summary>
	public const int DefaultClockSkewToleranceSeconds = 30;

	public const int DefaultMaxChainSpanMinutes = 120;

	public const int DefaultMinFailedAttempts = 5;

	public const int DefaultMaxFactAgeHours = 24;

	public const int DefaultMaxFactsPerHost = 1000;

	/// <summary>The out-of-the-box rule catalogue: the one documented P4-18 lateral-movement
	/// scenario (4625 on A, then 4624 on B, then 4672 on C).</summary>
	public static CrossHostChainRule CreateDefault()
	{
		return new CrossHostChainRule(
			"RDP_LATERAL_MOVEMENT",
			new List<CrossHostRuleHopMarker>
			{
				new(CrossHostFactKind.FailedLogon, 4625),
				new(CrossHostFactKind.SuccessfulLogon, 4624),
				new(CrossHostFactKind.PrivilegedLogon, 4672),
			},
			minHostCount: 3,
			clockSkewToleranceSeconds: 60,
			maxChainSpanMinutes: 120,
			minFailedAttempts: 3,
			maxFactAgeHours: 24,
			maxFactsPerHost: 100000);
	}

	/// <summary>Computes the 0..100 chain score from the observed counters inside the window.</summary>
	public int ComputeScore(int failedAttempts, int chainLinks, DateTime firstUtc, DateTime lastUtc, DateTime nowUtc)
	{
		int score = 0;
		if (failedAttempts >= MinFailedAttempts)
		{
			score += 20;
		}

		if (chainLinks >= Hops.Count)
		{
			score += 20;
		}

		double durationSeconds = Math.Max(0, (lastUtc - firstUtc).TotalSeconds);
		if (durationSeconds <= 300)
		{
			score += 25;
		}
		else if (durationSeconds <= 3600)
		{
			score += 15;
		}
		else
		{
			score += 5;
		}

		double ageHours = (nowUtc - lastUtc).TotalHours;
		if (Math.Max(0, ageHours) <= 1)
		{
			score += 10;
		}
		else if (Math.Max(0, ageHours) <= 24)
		{
			score += 5;
		}

		return Math.Clamp(score, 0, 100);
	}
}
