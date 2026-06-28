// File:    src/RdpAudit.Core/Models/AttackThreatScoring.cs
// Module:  RdpAudit.Core.Models
// Purpose: Pure, deterministic helper that computes the Attack Statistics ThreatScore (0..100) and
//          classifies a row into the cameyo-style Green / Yellow / Red severity bands. Centralised
//          here so the projection worker, IPC handlers, UI, and tests all share one definition and
//          cannot drift.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

namespace RdpAudit.Core.Models;

/// <summary>Pure deterministic helper for Attack Statistics threat scoring + classification.</summary>
/// <remarks>
/// <para>
/// The score is bounded in <c>[0, 100]</c> and assembled from five additive components so each
/// component is independently testable and explainable:
/// </para>
/// <list type="number">
///   <item><description><b>Failure pressure</b> — <c>min(40, failed * 0.5)</c>. A single failed
///   attempt contributes 0.5 points; 80+ failures saturate the failure-pressure component.</description></item>
///   <item><description><b>Success-after-fail signal</b> — flat <c>20</c> if the IP has at least one
///   failed AND at least one successful attempt. Brute-force attackers occasionally land a
///   correct guess; this signal lights up exactly those rows.</description></item>
///   <item><description><b>Intensity</b> — <c>min(20, failed / max(1, durationSeconds) * 1000)</c>.
///   Pure-rate component; a burst of failures inside a few seconds scores higher than the same
///   total spread over hours.</description></item>
///   <item><description><b>Active block</b> — flat <c>10</c> when the IP currently has at least one
///   <see cref="ActiveBlock"/> in <see cref="ActiveBlockStatus.Active"/> or
///   <see cref="ActiveBlockStatus.Pending"/>. An installed block is strong corroboration that the
///   service already classified this source as hostile.</description></item>
///   <item><description><b>Recentness</b> — <c>10</c> if <c>nowUtc - lastSeenUtc &lt; 1h</c>,
///   <c>5</c> if <c>&lt; 24h</c>, <c>0</c> otherwise. Old chatter decays.</description></item>
/// </list>
/// <para>
/// Classification thresholds:
/// </para>
/// <list type="bullet">
///   <item><description><c>0..29</c> → <see cref="AttackThreatLevel.Green"/> (legitimate or low risk)</description></item>
///   <item><description><c>30..69</c> → <see cref="AttackThreatLevel.Yellow"/> (low-intensity failures)</description></item>
///   <item><description><c>70..100</c> → <see cref="AttackThreatLevel.Red"/> (high-intensity / likely brute force)</description></item>
/// </list>
/// </remarks>
public static class AttackThreatScoring
{
	/// <summary>Saturation ceiling for the failure-pressure component.</summary>
	public const double FailurePressureMax = 40.0;

	/// <summary>Points per observed failed logon attempt, capped by <see cref="FailurePressureMax"/>.</summary>
	public const double FailurePressurePerFailure = 0.5;

	/// <summary>Flat bonus when both failed and successful attempts are observed from the IP.</summary>
	public const double SuccessAfterFailBonus = 20.0;

	/// <summary>Saturation ceiling for the intensity (failures-per-second) component.</summary>
	public const double IntensityMax = 20.0;

	/// <summary>Scale factor for the intensity component (failures per second, multiplied by this).</summary>
	public const double IntensityScale = 1000.0;

	/// <summary>Flat bonus when the IP currently has at least one Active / Pending block.</summary>
	public const double ActiveBlockBonus = 10.0;

	/// <summary>Inclusive lower bound of the Yellow band.</summary>
	public const double YellowThreshold = 30.0;

	/// <summary>Inclusive lower bound of the Red band.</summary>
	public const double RedThreshold = 70.0;

	/// <summary>Final ceiling applied to the assembled score.</summary>
	public const double ScoreMax = 100.0;

	/// <summary>Final floor applied to the assembled score.</summary>
	public const double ScoreMin = 0.0;

	/// <summary>
	/// Computes a deterministic, explainable threat score in <c>[0, 100]</c> for a single IP row.
	/// </summary>
	/// <param name="failed">Failed logon attempts observed from this IP.</param>
	/// <param name="successful">Successful logon attempts observed from this IP.</param>
	/// <param name="durationSeconds">Active-window duration in whole seconds (LastSeen - FirstSeen).</param>
	/// <param name="isBlocked">True when at least one Active / Pending block exists for this IP.</param>
	/// <param name="lastSeenUtc">UTC timestamp of the most recent attempt from this IP.</param>
	/// <param name="nowUtc">"Now" reference (UTC) — injected so the scoring is deterministic for tests.</param>
	/// <returns>The assembled score, clamped to <c>[0, 100]</c>.</returns>
	public static double ComputeScore(
		long failed,
		long successful,
		long durationSeconds,
		bool isBlocked,
		DateTime lastSeenUtc,
		DateTime nowUtc)
	{
		double failurePressure = Math.Min(FailurePressureMax, Math.Max(0, failed) * FailurePressurePerFailure);
		double successAfterFail = (failed > 0 && successful > 0) ? SuccessAfterFailBonus : 0.0;

		double safeDuration = durationSeconds < 1 ? 1.0 : durationSeconds;
		double intensity = failed > 0
			? Math.Min(IntensityMax, (failed / safeDuration) * IntensityScale)
			: 0.0;

		double activeBlock = isBlocked ? ActiveBlockBonus : 0.0;
		double recentness = ComputeRecentnessBonus(lastSeenUtc, nowUtc);

		double total = failurePressure + successAfterFail + intensity + activeBlock + recentness;
		if (total < ScoreMin)
		{
			return ScoreMin;
		}
		return total > ScoreMax ? ScoreMax : total;
	}

	/// <summary>Classifies a numeric threat score into a cameyo-style severity band.</summary>
	public static AttackThreatLevel ClassifyScore(double score)
	{
		if (score >= RedThreshold)
		{
			return AttackThreatLevel.Red;
		}
		if (score >= YellowThreshold)
		{
			return AttackThreatLevel.Yellow;
		}
		return AttackThreatLevel.Green;
	}

	/// <summary>Returns the recentness component contribution (0 / 5 / 10).</summary>
	internal static double ComputeRecentnessBonus(DateTime lastSeenUtc, DateTime nowUtc)
	{
		TimeSpan age = nowUtc - lastSeenUtc;
		if (age < TimeSpan.Zero)
		{
			// LastSeen in the future relative to now (clock skew) → treat as very recent.
			return 10.0;
		}
		if (age < TimeSpan.FromHours(1))
		{
			return 10.0;
		}
		if (age < TimeSpan.FromHours(24))
		{
			return 5.0;
		}
		return 0.0;
	}
}
