/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 2.0.0
// File   : InformationDensityRetentionPlanner.cs
// Project: RdpAudit.Core (RdpAudit.Core.Retention)
// Purpose: Pure, deterministic planner for information-density retention. Given the policy and a
//          snapshot of the dense event codes, it decides exactly which rows may be deleted: never an
//          anchor, never a protected tail row, never a fresh row, never a protected class, and never
//          more than the per-pass budget. No I/O, no clock of its own, no database - so every rule and
//          every invariant is testable in isolation and two identical inputs always produce an
//          identical plan.
// Depends: RetentionPolicyOptions, RetentionCodeState, RetentionPlan
// Extends: Add a new eligibility rule here and a matching RetentionSkipReason, then bump
//          RetentionRuleVersion so ledger rows written by the previous rule stay distinguishable.

using RdpAudit.Core.Config;

namespace RdpAudit.Core.Retention;

/// <summary>
/// Pure information-density retention planner. The owner's rule, made deterministic:
/// the oldest record of a code (the anchor) is never deleted, the newest
/// <c>TailKeepPerCode</c> records (the tail) are never deleted, and only the interior is
/// compressible - densest code first, oldest row first inside a code, never below the age floor,
/// never above the eligibility threshold and never more than the per-pass budget.
/// </summary>
public static class InformationDensityRetentionPlanner
{
	// ── Public API ───────────────────────────────────────────────────────────────

	/// <summary>
	/// Produces the deletion plan for one point in time.
	/// </summary>
	/// <param name="nowUtc">Current UTC wall clock; the age floor is measured from it.</param>
	/// <param name="options">Policy. Disabled => empty plan; legal hold => empty plan.</param>
	/// <param name="states">Snapshots of the candidate codes. Keys must be unique.</param>
	/// <returns>A plan whose steps never cover an anchor, a protected tail row or a fresh row.</returns>
	public static RetentionPlan Plan(
		DateTime nowUtc,
		RetentionPolicyOptions options,
		IReadOnlyList<RetentionCodeState> states)
	{
		ArgumentNullException.ThrowIfNull(options);
		ArgumentNullException.ThrowIfNull(states);

		List<RetentionPlanStep> steps = [];
		List<RetentionPlanSkip> skipped = [];
		int ruleVersion = RetentionRuleVersion.Current;

		// An installation that never opted in keeps today's behaviour exactly.
		if (!options.Enabled)
		{
			return new RetentionPlan { Steps = steps, Skipped = skipped, RuleVersion = ruleVersion };
		}

		// Legal hold disables every pressure rule, whatever the other settings say.
		if (options.LegalHold)
		{
			foreach (RetentionCodeState state in states)
			{
				skipped.Add(new RetentionPlanSkip { Key = state.Key, Reason = RetentionSkipReason.LegalHold });
			}

			return new RetentionPlan { Steps = steps, Skipped = skipped, RuleVersion = ruleVersion };
		}

		int tailKeep = options.ResolveTailKeepPerCode();
		int candidateMinRows = options.ResolveCandidateMinRows();
		DateTime minAgeCutoffUtc = nowUtc.AddDays(-options.ResolveMinAgeDays());
		int budget = options.ResolveMaxRowsPerPass();
		HashSet<int> protectedCodes = options.ResolveProtectedEventIds();

		List<InteriorCandidate> candidates = [];
		foreach (RetentionCodeState state in states)
		{
			if (protectedCodes.Contains(state.Key.EventId))
			{
				skipped.Add(new RetentionPlanSkip { Key = state.Key, Reason = RetentionSkipReason.ProtectedEventCode });
				continue;
			}

			if (state.TailBoundary is not { } tailBoundary)
			{
				// Row count is at or below the protected tail length: the code has no interior.
				skipped.Add(new RetentionPlanSkip { Key = state.Key, Reason = RetentionSkipReason.NoInteriorRows });
				continue;
			}

			// The code can never expose more interior rows than (total rows - anchor - tail). Clamping
			// here keeps the reported density honest even if a caller over-counts.
			long interiorCapacity = Math.Max(0L, state.TotalRows - 1L - tailKeep);
			if (interiorCapacity <= 0)
			{
				// Everything the code holds is its anchor and its tail: there is nothing to compress.
				skipped.Add(new RetentionPlanSkip { Key = state.Key, Reason = RetentionSkipReason.NoInteriorRows });
				continue;
			}

			long density = Math.Clamp(state.EligibleInteriorRows, 0L, interiorCapacity);
			if (density < candidateMinRows)
			{
				skipped.Add(new RetentionPlanSkip { Key = state.Key, Reason = RetentionSkipReason.BelowCandidateMinRows });
				continue;
			}

			List<RetentionRow> interior = SelectInteriorRows(state, interiorCapacity, minAgeCutoffUtc);
			if (interior.Count == 0)
			{
				skipped.Add(new RetentionPlanSkip { Key = state.Key, Reason = RetentionSkipReason.NoInteriorRows });
				continue;
			}

			candidates.Add(new InteriorCandidate(state, tailBoundary, interior, density));
		}

		candidates.Sort(CompareCandidates);

		foreach (InteriorCandidate candidate in candidates)
		{
			if (budget <= 0)
			{
				skipped.Add(new RetentionPlanSkip { Key = candidate.State.Key, Reason = RetentionSkipReason.BudgetExhausted });
				continue;
			}

			int take = Math.Min(budget, candidate.Rows.Count);
			RetentionRow first = candidate.Rows[0];
			RetentionRow last = candidate.Rows[take - 1];
			budget -= take;

			steps.Add(new RetentionPlanStep
			{
				Key = candidate.State.Key,
				Rows = take,
				AnchorRowId = candidate.State.Anchor.Id,
				AnchorTimeUtc = candidate.State.Anchor.TimeUtc,
				TailBoundaryRowId = candidate.TailBoundary.Id,
				TailBoundaryTimeUtc = candidate.TailBoundary.TimeUtc,
				LowestRowId = candidate.State.LowestRowId,
				HighestRowId = candidate.State.HighestRowId,
				WindowStartUtc = first.TimeUtc,
				WindowEndUtc = last.TimeUtc,
			});
		}

		return new RetentionPlan { Steps = steps, Skipped = skipped, RuleVersion = ruleVersion };
	}

	// ── Interior selection ───────────────────────────────────────────────────────

	/// <summary>
	/// Projects the deletable interior of one code. Every protection is re-applied here rather than
	/// trusted from the caller, so no input can make the plan cover an anchor, a tail row or a fresh
	/// row: rows are ordered ascending, the anchor and everything at or before it are dropped, the
	/// tail boundary and everything at or after it are dropped, rows at or newer than the age floor
	/// are dropped, and the result is capped at the number of rows the code can physically expose
	/// between its anchor and its tail.
	/// </summary>
	private static List<RetentionRow> SelectInteriorRows(
		RetentionCodeState state,
		long interiorCapacity,
		DateTime minAgeCutoffUtc)
	{
		if (interiorCapacity <= 0 || state.CandidateRows.Count == 0)
		{
			return [];
		}

		List<RetentionRow> ordered = [.. state.CandidateRows];
		ordered.Sort(CompareRowsAscending);

		List<RetentionRow> interior = new(ordered.Count);
		foreach (RetentionRow row in ordered)
		{
			if (interior.Count >= interiorCapacity)
			{
				break;
			}

			if (row.TimeUtc >= minAgeCutoffUtc)
			{
				// Ascending order: no later row can be older than the floor.
				break;
			}

			if (CompareRowsAscending(row, state.Anchor) <= 0)
			{
				// The anchor (and anything at or before it) is never a candidate.
				continue;
			}

			if (state.TailBoundary is { } tailBoundary && CompareRowsAscending(row, tailBoundary) >= 0)
			{
				// Ascending order: the tail starts here and continues to the newest row.
				break;
			}

			interior.Add(row);
		}

		return interior;
	}

	// ── Deterministic ordering ───────────────────────────────────────────────────

	/// <summary>
	/// Total order over candidate codes: densest first, then event id, channel and IP hex, with a
	/// final backstop so the plan never depends on sort stability even if a caller supplies a
	/// duplicated key.
	/// </summary>
	private static int CompareCandidates(InteriorCandidate x, InteriorCandidate y)
	{
		int byDensity = y.Density.CompareTo(x.Density);
		if (byDensity != 0)
		{
			return byDensity;
		}

		int byEventId = x.State.Key.EventId.CompareTo(y.State.Key.EventId);
		if (byEventId != 0)
		{
			return byEventId;
		}

		int byChannel = string.CompareOrdinal(x.State.Key.Channel, y.State.Key.Channel);
		if (byChannel != 0)
		{
			return byChannel;
		}

		int byIp = string.CompareOrdinal(x.State.Key.IpHex, y.State.Key.IpHex);
		if (byIp != 0)
		{
			return byIp;
		}

		int byTotalRows = y.State.TotalRows.CompareTo(x.State.TotalRows);
		return byTotalRows != 0 ? byTotalRows : y.State.Anchor.Id.CompareTo(x.State.Anchor.Id);
	}

	/// <summary>Ascending order over rows: <c>TimeUtc</c>, tie-break <c>Id</c>.</summary>
	private static int CompareRowsAscending(RetentionRow x, RetentionRow y)
	{
		int byTime = x.TimeUtc.CompareTo(y.TimeUtc);
		return byTime != 0 ? byTime : x.Id.CompareTo(y.Id);
	}

	// ── Internal model ───────────────────────────────────────────────────────────

	/// <summary>An eligible code with its already-projected, ascending interior rows and its clamped
	/// density.</summary>
	private readonly record struct InteriorCandidate(
		RetentionCodeState State,
		RetentionRow TailBoundary,
		List<RetentionRow> Rows,
		long Density);
}
