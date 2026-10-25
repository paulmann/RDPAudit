// File:    src/RdpAudit.Core/AbuseIpDb/AbuseIpDbReportDecision.cs
// Module:  RdpAudit.Core.AbuseIpDb
// Purpose: Pure decision helpers used by the Stage 8 reporting worker. Keeps dedup, rate-limit and
//          threshold checks free of EF Core and HTTP so they can be exercised by unit tests.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using RdpAudit.Core.Config;
using RdpAudit.Core.Util;

namespace RdpAudit.Core.AbuseIpDb;

/// <summary>Reason an outbound report was suppressed by the local policy.</summary>
public enum AbuseIpDbSuppressionReason
{
	None = 0,
	ReportingDisabled = 1,
	NoApiKey = 2,
	InvalidIp = 3,
	NotPublicIp = 4,
	Whitelisted = 5,
	BelowThreatScore = 6,
	BelowFailedAttempts = 7,
	WithinDedupWindow = 8,
	HourlyLimitReached = 9,
	DailyLimitReached = 10,

	/// <summary>A successful report for this IP exists within the configured report cooldown window.</summary>
	WithinReportCooldown = 11,
}

/// <summary>Container for the should-report decision.</summary>
public readonly record struct AbuseIpDbReportDecision(bool ShouldReport, AbuseIpDbSuppressionReason Reason);

/// <summary>Pure policy decisions for AbuseIPDB Stage 8 reporting.</summary>
public static class AbuseIpDbPolicy
{
	/// <summary>Determines whether a candidate IP qualifies for an AbuseIPDB report.</summary>
	/// <param name="opts">Bound AbuseIPDB options (must not be null).</param>
	/// <param name="hasApiKey">True when the configured ApiKey is non-empty.</param>
	/// <param name="ip">Candidate source IP in textual form.</param>
	/// <param name="threatScore">Local threat score for the IP (from AttackStat).</param>
	/// <param name="failedAttempts">Failed attempts observed for the IP.</param>
	/// <param name="isWhitelisted">Whether the IP appears on any whitelist.</param>
	/// <param name="lastReportUtc">Last report attempt UTC for this IP; null when never reported.</param>
	/// <param name="reportsInHour">Reports already submitted in the last hour (any IP).</param>
	/// <param name="reportsInDay">Reports already submitted in the last day (any IP).</param>
	/// <param name="nowUtc">Current UTC time (passed in for determinism in tests).</param>
	/// <param name="lastSuccessfulReportUtc">Last SUCCESSFUL report UTC for this IP; null when never successfully reported. Only consulted when <see cref="AbuseIpDbOptions.ReportDedupeEnabled"/> is true.</param>
	public static AbuseIpDbReportDecision Decide(
		AbuseIpDbOptions opts,
		bool hasApiKey,
		string? ip,
		double threatScore,
		long failedAttempts,
		bool isWhitelisted,
		DateTime? lastReportUtc,
		int reportsInHour,
		int reportsInDay,
		DateTime nowUtc,
		DateTime? lastSuccessfulReportUtc = null)
	{
		ArgumentNullException.ThrowIfNull(opts);

		if (!opts.Enabled || !opts.ReportAttacks)
		{
			return new AbuseIpDbReportDecision(false, AbuseIpDbSuppressionReason.ReportingDisabled);
		}

		if (!hasApiKey)
		{
			return new AbuseIpDbReportDecision(false, AbuseIpDbSuppressionReason.NoApiKey);
		}

		if (string.IsNullOrWhiteSpace(ip))
		{
			return new AbuseIpDbReportDecision(false, AbuseIpDbSuppressionReason.InvalidIp);
		}

		if (!IpClassifier.IsPublicIp(ip))
		{
			return new AbuseIpDbReportDecision(false, AbuseIpDbSuppressionReason.NotPublicIp);
		}

		if (isWhitelisted)
		{
			return new AbuseIpDbReportDecision(false, AbuseIpDbSuppressionReason.Whitelisted);
		}

		if (threatScore < opts.MinThreatScore)
		{
			return new AbuseIpDbReportDecision(false, AbuseIpDbSuppressionReason.BelowThreatScore);
		}

		if (failedAttempts < opts.MinFailedAttempts)
		{
			return new AbuseIpDbReportDecision(false, AbuseIpDbSuppressionReason.BelowFailedAttempts);
		}

		int dedupMinutes = Math.Max(15, opts.DeduplicationWindowMinutes);
		if (lastReportUtc.HasValue)
		{
			TimeSpan since = nowUtc - lastReportUtc.Value;
			if (since < TimeSpan.FromMinutes(dedupMinutes))
			{
				return new AbuseIpDbReportDecision(false, AbuseIpDbSuppressionReason.WithinDedupWindow);
			}
		}

		// Success-filtered cooldown: only a *successful* prior report within the configured cooldown
		// suppresses. Failed reports never suppress future submissions. Gated by ReportDedupeEnabled.
		if (opts.ReportDedupeEnabled && lastSuccessfulReportUtc.HasValue)
		{
			int cooldownHours = Math.Clamp(opts.ReportCooldownHours, 1, 8760);
			TimeSpan sinceSuccess = nowUtc - lastSuccessfulReportUtc.Value;
			if (sinceSuccess < TimeSpan.FromHours(cooldownHours))
			{
				return new AbuseIpDbReportDecision(false, AbuseIpDbSuppressionReason.WithinReportCooldown);
			}
		}

		int hourlyCap = Math.Max(1, opts.MaxReportsPerHour);
		if (reportsInHour >= hourlyCap)
		{
			return new AbuseIpDbReportDecision(false, AbuseIpDbSuppressionReason.HourlyLimitReached);
		}

		int dailyCap = Math.Max(1, opts.MaxReportsPerDay);
		if (reportsInDay >= dailyCap)
		{
			return new AbuseIpDbReportDecision(false, AbuseIpDbSuppressionReason.DailyLimitReached);
		}

		return new AbuseIpDbReportDecision(true, AbuseIpDbSuppressionReason.None);
	}
}
