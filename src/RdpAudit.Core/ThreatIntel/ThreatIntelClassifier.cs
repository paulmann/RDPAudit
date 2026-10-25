// File:    src/RdpAudit.Core/ThreatIntel/ThreatIntelClassifier.cs
// Module:  RdpAudit.Core.ThreatIntel
// Purpose: Pure, provider-agnostic decision helpers for the Backlog #5 threat-intel High-risk
//          marking. Keeps the classification free of EF Core and HTTP so it can be exercised by
//          unit tests in RdpAudit.Core.Tests. The flag is INFORMATIONAL ONLY - it never feeds
//          auto-block, alert rules or the FirewallAutoBlockWorker.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

namespace RdpAudit.Core.ThreatIntel;

/// <summary>Pure classifier deriving the informational High-risk flag from a lookup result.</summary>
public static class ThreatIntelClassifier
{
	/// <summary>Fail-closed High-risk test. Returns true only when ALL of the following hold:
	/// <list type="bullet">
	/// <item>the lookup outcome is <see cref="ThreatIntelLookupOutcome.Success"/>;</item>
	/// <item>the provider reports the IP as public (<c>IsPublic == true</c> - true means usable);</item>
	/// <item>the provider does NOT report the IP as whitelisted (<c>IsWhitelisted != true</c>;
	/// a null whitelist flag is treated as not-whitelisted but requires the score gate to pass);</item>
	/// <item>the clamped confidence score is at or above the configured threshold.</item>
	/// </list>
	/// Any transport error, rejected key, rate-limit or malformed response therefore yields false -
	/// stale or broken provider data can never manufacture a High-risk mark.</summary>
	/// <param name="result">The lookup result. Null is treated as fail-closed (false).</param>
	/// <param name="threshold">Score threshold, typically <c>AbuseIpDbOptions.ReportThreshold</c>.</param>
	public static bool IsHighRisk(ThreatIntelLookupResult? result, int threshold)
	{
		if (result is null || result.Outcome != ThreatIntelLookupOutcome.Success)
		{
			return false;
		}

		if (result.IsPublic != true)
		{
			return false;
		}

		if (result.IsWhitelisted == true)
		{
			return false;
		}

		if (!result.AbuseConfidenceScore.HasValue)
		{
			return false;
		}

		int clamped = ClampScore(result.AbuseConfidenceScore.Value);
		return clamped >= threshold;
	}

	/// <summary>Clamps a provider-reported score into the canonical 0..100 band. Adversarial or
	/// malformed values never leave the process un-clamped.</summary>
	public static int ClampScore(int score)
	{
		if (score < 0)
		{
			return 0;
		}

		if (score > 100)
		{
			return 100;
		}

		return score;
	}
}
