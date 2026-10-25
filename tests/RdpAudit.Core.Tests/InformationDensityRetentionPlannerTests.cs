/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 2.0.0
// File   : InformationDensityRetentionPlannerTests.cs
// Project: RdpAudit.Core.Tests (RdpAudit.Core.Tests)
// Purpose: Locks every invariant of the pure information-density retention planner, with no database
//          and no clock of its own: the anchor and the protected tail survive even when a caller
//          over-claims the interior, only interior rows older than the age floor are candidates,
//          protected classes and rare codes are skipped with a named reason, the densest code goes
//          first with deterministic tie-breaks, the per-pass budget is distributed in that order, a
//          legal hold or a disabled policy produces an empty plan, and two identical inputs always
//          produce an identical plan.
// Depends: InformationDensityRetentionPlanner, RetentionCodeState, RetentionPolicyOptions, Xunit
// Extends: Add a case per new eligibility rule, ordering rule and skip reason.

using RdpAudit.Core.Config;
using RdpAudit.Core.Retention;
using Xunit;

namespace RdpAudit.Core.Tests;

/// <summary>Pure-planner tests for the information-density retention rule set.</summary>
public class InformationDensityRetentionPlannerTests
{
	private static readonly DateTime NowUtc = new(2026, 9, 14, 12, 0, 0, DateTimeKind.Utc);

	private sealed record CodeFixture(
		RetentionCodeState State,
		RetentionRow Anchor,
		IReadOnlyList<RetentionRow> Interior,
		IReadOnlyList<RetentionRow> Tail);

	/// <summary>
	/// A code with one anchor, <paramref name="interiorCount"/> interior rows and
	/// <paramref name="tailCount"/> tail rows, adjacent rows spaced one day apart with the newest row
	/// <paramref name="newestOffsetDays"/> days before the planning instant. Every row is therefore
	/// comfortably older than a 7-day floor, so a test that expects rows to survive must say why.
	/// </summary>
	private static CodeFixture BuildCode(
		int eventId,
		int interiorCount,
		int tailCount,
		int newestOffsetDays = 30,
		string channel = "Security",
		byte[]? ip = null,
		long firstId = 1)
	{
		int total = 1 + interiorCount + tailCount;
		long id = firstId;
		RetentionRow[] rows = new RetentionRow[total];
		for (int index = 0; index < total; index++)
		{
			rows[index] = new RetentionRow(id++, NowUtc.AddDays(-(newestOffsetDays + total - 1 - index)));
		}

		RetentionRow anchor = rows[0];
		RetentionRow[] interior = new RetentionRow[interiorCount];
		Array.Copy(rows, 1, interior, 0, interiorCount);
		RetentionRow[] tail = new RetentionRow[tailCount];
		Array.Copy(rows, 1 + interiorCount, tail, 0, tailCount);
		RetentionRow? tailBoundary = tailCount > 0 ? tail[0] : null;
		RetentionCodeState state = new()
		{
			Key = new RetentionCodeKey { EventId = eventId, Channel = channel, IpBinary16 = ip },
			TotalRows = total,
			Anchor = anchor,
			TailBoundary = tailBoundary,
			EligibleInteriorRows = interiorCount,
			LowestRowId = rows[0].Id,
			HighestRowId = rows[^1].Id,
			CandidateRows = interior,
		};
		return new CodeFixture(state, anchor, interior, tail);
	}

	private static RetentionPolicyOptions Policy(
		int tailKeep = 5,
		int candidateMinRows = 10,
		int minAgeDays = 7,
		int maxRowsPerPass = 10_000)
		=> new()
		{
			Enabled = true,
			TailKeepPerCode = tailKeep,
			CandidateMinRows = candidateMinRows,
			MinAgeDays = minAgeDays,
			MaxRowsPerPass = maxRowsPerPass,
		};

	// ── Posture ──────────────────────────────────────────────────────────────────

	[Fact]
	public void Plan_DisabledPolicy_ReturnsEmptyPlanAndTouchesNothing()
	{
		CodeFixture fixture = BuildCode(4625, interiorCount: 500, tailCount: 5);
		RetentionPolicyOptions policy = Policy();
		policy.Enabled = false;

		RetentionPlan plan = InformationDensityRetentionPlanner.Plan(NowUtc, policy, [fixture.State]);

		Assert.True(plan.IsEmpty);
		Assert.Equal(0L, plan.PlannedRows);
		Assert.Empty(plan.Skipped);
	}

	[Theory]
	[InlineData(0)]
	[InlineData(1)]
	[InlineData(500)]
	public void Plan_LegalHold_ReturnsEmptyPlanAndNamesTheReason(int interiorCount)
	{
		CodeFixture fixture = BuildCode(4625, interiorCount, tailCount: 5);
		RetentionPolicyOptions policy = Policy();
		policy.LegalHold = true;

		RetentionPlan plan = InformationDensityRetentionPlanner.Plan(NowUtc, policy, [fixture.State]);

		Assert.True(plan.IsEmpty);
		Assert.Equal(0L, plan.PlannedRows);
		RetentionPlanSkip skip = Assert.Single(plan.Skipped);
		Assert.Equal(RetentionSkipReason.LegalHold, skip.Reason);
		Assert.Equal(4625, skip.Key.EventId);
	}

	[Fact]
	public void Plan_NoCodes_ReturnsEmptyPlan()
	{
		RetentionPlan plan = InformationDensityRetentionPlanner.Plan(NowUtc, Policy(), []);
		Assert.True(plan.IsEmpty);
		Assert.Empty(plan.Skipped);
	}

	// ── Anchor and tail protection ───────────────────────────────────────────────

	[Fact]
	public void Plan_NeverCoversTheAnchorOrTheTail_WhenTheCallerOverClaimsTheInterior()
	{
		CodeFixture fixture = BuildCode(4625, interiorCount: 400, tailCount: 5);

		// Hostile input: the caller offers the anchor and every tail row as candidates.
		RetentionCodeState overClaimed = fixture.State with
		{
			CandidateRows = [fixture.Anchor, .. fixture.Interior, .. fixture.Tail],
		};

		RetentionPlan plan = InformationDensityRetentionPlanner.Plan(
			NowUtc,
			Policy(maxRowsPerPass: 10_000),
			[overClaimed]);

		RetentionPlanStep step = Assert.Single(plan.Steps);
		Assert.Equal(fixture.Interior.Count, step.Rows);
		Assert.True(
			step.WindowStartUtc > fixture.Anchor.TimeUtc,
			"the planned window must start strictly after the anchor");
		Assert.Equal(fixture.Interior[0].TimeUtc, step.WindowStartUtc);
		Assert.Equal(fixture.Interior[^1].TimeUtc, step.WindowEndUtc);
		Assert.True(
			step.WindowEndUtc < fixture.Tail[0].TimeUtc,
			"the planned window must end strictly before the protected tail");
	}

	[Fact]
	public void Plan_NeverClaimsMoreRowsThanTheCodeCanPhysicallyExpose()
	{
		// TotalRows says 20 rows exist (1 anchor + 10 interior + 9 tail) but the caller offers 500.
		CodeFixture fixture = BuildCode(4625, interiorCount: 10, tailCount: 9);
		List<RetentionRow> overClaim = [.. fixture.Interior];
		for (int index = 0; index < 490; index++)
		{
			overClaim.Add(new RetentionRow(10_000 + index, NowUtc.AddDays(-200).AddMinutes(index)));
		}

		RetentionPlan plan = InformationDensityRetentionPlanner.Plan(
			NowUtc,
			Policy(tailKeep: 9, maxRowsPerPass: 10_000),
			[fixture.State with { CandidateRows = overClaim }]);

		RetentionPlanStep step = Assert.Single(plan.Steps);
		Assert.Equal(10, step.Rows);
	}

	[Fact]
	public void Plan_CodeWithNoInterior_IsSkippedWithNoInteriorRows()
	{
		CodeFixture fixture = BuildCode(4625, interiorCount: 0, tailCount: 5);
		RetentionPlan plan = InformationDensityRetentionPlanner.Plan(NowUtc, Policy(), [fixture.State]);

		Assert.True(plan.IsEmpty);
		Assert.Equal(RetentionSkipReason.NoInteriorRows, Assert.Single(plan.Skipped).Reason);
	}

	[Fact]
	public void Plan_CodeWithNoTailBoundary_IsSkippedWithNoInteriorRows()
	{
		CodeFixture fixture = BuildCode(4625, interiorCount: 100, tailCount: 5);
		RetentionCodeState withoutBoundary = fixture.State with { TailBoundary = null };

		RetentionPlan plan = InformationDensityRetentionPlanner.Plan(NowUtc, Policy(), [withoutBoundary]);

		Assert.True(plan.IsEmpty);
		Assert.Equal(RetentionSkipReason.NoInteriorRows, Assert.Single(plan.Skipped).Reason);
	}

	// ── Age floor ────────────────────────────────────────────────────────────────

	[Fact]
	public void Plan_RowsNewerThanTheAgeFloor_AreNeverCandidates()
	{
		// One anchor 6 hours back, 200 interior rows inside the last hour and 5 tail rows in the last
		// five minutes: every interior row is fresh, so the age floor must protect all of them.
		long id = 1;
		RetentionRow anchor = new(id++, NowUtc.AddHours(-6));
		List<RetentionRow> rows = [anchor];
		for (int index = 0; index < 200; index++)
		{
			rows.Add(new RetentionRow(id++, NowUtc.AddMinutes(-60).AddSeconds(index)));
		}

		for (int index = 0; index < 5; index++)
		{
			rows.Add(new RetentionRow(id++, NowUtc.AddMinutes(-5 + index)));
		}

		RetentionCodeState state = new()
		{
			Key = new RetentionCodeKey { EventId = 4625, Channel = "Security" },
			TotalRows = rows.Count,
			Anchor = anchor,
			TailBoundary = rows[^5],
			EligibleInteriorRows = 0,
			LowestRowId = anchor.Id,
			HighestRowId = rows[^1].Id,
			CandidateRows = rows.GetRange(1, rows.Count - 1),
		};

		RetentionPlan plan = InformationDensityRetentionPlanner.Plan(
			NowUtc,
			Policy(tailKeep: 5, candidateMinRows: 10, minAgeDays: 7, maxRowsPerPass: 10_000),
			[state]);

		Assert.True(plan.IsEmpty);
	}

	[Fact]
	public void Plan_OnlyRowsOlderThanTheAgeFloor_ArePlanned()
	{
		// Anchor 40 days back, 100 interior rows 30 days old, 100 interior rows two hours old and
		// 5 tail rows. A 7-day floor must plan exactly the 100 old rows.
		long id = 1;
		RetentionRow anchor = new(id++, NowUtc.AddDays(-40));
		List<RetentionRow> rows = [anchor];
		List<RetentionRow> oldRows = [];
		for (int index = 0; index < 100; index++)
		{
			RetentionRow row = new(id++, NowUtc.AddDays(-30).AddMinutes(index));
			oldRows.Add(row);
			rows.Add(row);
		}

		for (int index = 0; index < 100; index++)
		{
			rows.Add(new RetentionRow(id++, NowUtc.AddMinutes(-120).AddMinutes(index)));
		}

		for (int index = 0; index < 5; index++)
		{
			rows.Add(new RetentionRow(id++, NowUtc.AddMinutes(-5 + index)));
		}

		RetentionCodeState state = new()
		{
			Key = new RetentionCodeKey { EventId = 4625, Channel = "Security" },
			TotalRows = rows.Count,
			Anchor = anchor,
			TailBoundary = rows[^5],
			EligibleInteriorRows = 100,
			LowestRowId = anchor.Id,
			HighestRowId = rows[^1].Id,
			// Hostile input: everything except the anchor is offered as a candidate.
			CandidateRows = rows.GetRange(1, rows.Count - 1),
		};

		RetentionPlan plan = InformationDensityRetentionPlanner.Plan(
			NowUtc,
			Policy(tailKeep: 5, candidateMinRows: 50, minAgeDays: 7, maxRowsPerPass: 10_000),
			[state]);

		RetentionPlanStep step = Assert.Single(plan.Steps);
		Assert.Equal(100, step.Rows);
		Assert.Equal(oldRows[0].TimeUtc, step.WindowStartUtc);
		Assert.Equal(oldRows[^1].TimeUtc, step.WindowEndUtc);
	}

	[Fact]
	public void Plan_MinAgeDaysFloor_IsNeverRelaxedBelowOneDay()
	{
		RetentionPolicyOptions policy = Policy();
		policy.MinAgeDays = 0;
		Assert.Equal(1, policy.ResolveMinAgeDays());

		// Rows two hours old must survive a requested zero-day floor, because the floor clamps to a day.
		long id = 1;
		RetentionRow anchor = new(id++, NowUtc.AddHours(-3));
		List<RetentionRow> rows = [anchor];
		for (int index = 0; index < 200; index++)
		{
			rows.Add(new RetentionRow(id++, NowUtc.AddMinutes(-120).AddSeconds(index)));
		}

		for (int index = 0; index < 5; index++)
		{
			rows.Add(new RetentionRow(id++, NowUtc.AddMinutes(-5 + index)));
		}

		RetentionCodeState state = new()
		{
			Key = new RetentionCodeKey { EventId = 4625, Channel = "Security" },
			TotalRows = rows.Count,
			Anchor = anchor,
			TailBoundary = rows[^5],
			EligibleInteriorRows = 0,
			LowestRowId = anchor.Id,
			HighestRowId = rows[^1].Id,
			CandidateRows = rows.GetRange(1, rows.Count - 1),
		};

		RetentionPlan plan = InformationDensityRetentionPlanner.Plan(NowUtc, policy, [state]);

		Assert.True(plan.IsEmpty);
	}

	// ── Eligibility ──────────────────────────────────────────────────────────────

	[Fact]
	public void Plan_BelowCandidateMinRows_IsSkippedWithTheThresholdReason()
	{
		CodeFixture fixture = BuildCode(4625, interiorCount: 99, tailCount: 5);
		RetentionPlan plan = InformationDensityRetentionPlanner.Plan(
			NowUtc,
			Policy(candidateMinRows: 100),
			[fixture.State]);

		Assert.True(plan.IsEmpty);
		Assert.Equal(RetentionSkipReason.BelowCandidateMinRows, Assert.Single(plan.Skipped).Reason);
	}

	[Fact]
	public void Plan_AtCandidateMinRows_BecomesEligible()
	{
		CodeFixture fixture = BuildCode(4625, interiorCount: 100, tailCount: 5);
		RetentionPlan plan = InformationDensityRetentionPlanner.Plan(
			NowUtc,
			Policy(candidateMinRows: 100, maxRowsPerPass: 10_000),
			[fixture.State]);

		Assert.Equal(100, Assert.Single(plan.Steps).Rows);
	}

	[Fact]
	public void Plan_ProtectedEventCode_IsSkippedEvenAtExtremeDensity()
	{
		CodeFixture dense = BuildCode(4625, interiorCount: 5_000, tailCount: 5);
		CodeFixture protectedCode = BuildCode(4720, interiorCount: 5_000, tailCount: 5);

		RetentionPlan plan = InformationDensityRetentionPlanner.Plan(
			NowUtc,
			Policy(maxRowsPerPass: 1_000_000),
			[dense.State, protectedCode.State]);

		RetentionPlanStep step = Assert.Single(plan.Steps);
		Assert.Equal(4625, step.Key.EventId);
		Assert.Contains(plan.Skipped, s => s.Key.EventId == 4720 && s.Reason == RetentionSkipReason.ProtectedEventCode);
	}

	// ── Ordering and budget ──────────────────────────────────────────────────────

	[Fact]
	public void Plan_DensestCodeIsPlannedFirst()
	{
		CodeFixture sparse = BuildCode(4624, interiorCount: 100, tailCount: 5);
		CodeFixture dense = BuildCode(4625, interiorCount: 900, tailCount: 5);
		CodeFixture middle = BuildCode(4634, interiorCount: 400, tailCount: 5);

		RetentionPlan plan = InformationDensityRetentionPlanner.Plan(
			NowUtc,
			Policy(maxRowsPerPass: 10_000),
			[sparse.State, dense.State, middle.State]);

		Assert.Equal([4625, 4634, 4624], plan.Steps.Select(s => s.Key.EventId).ToArray());
	}

	[Fact]
	public void Plan_EqualDensity_TieBreaksByEventIdThenChannelThenIpHex()
	{
		byte[] ipA = [0x0A, 0x00, 0x00, 0x01];
		byte[] ipB = [0x0A, 0x00, 0x00, 0x02];
		CodeFixture perCodeSystem = BuildCode(4625, 200, 5, channel: "System");
		CodeFixture perCodeSecurity = BuildCode(4625, 200, 5, channel: "Security");
		CodeFixture perIpB = BuildCode(4625, 200, 5, channel: "Application", ip: ipB);
		CodeFixture perIpA = BuildCode(4625, 200, 5, channel: "Application", ip: ipA);
		CodeFixture lowerEventId = BuildCode(1000, 200, 5);

		RetentionPlan plan = InformationDensityRetentionPlanner.Plan(
			NowUtc,
			Policy(maxRowsPerPass: 10_000),
			[perCodeSystem.State, perIpB.State, perCodeSecurity.State, perIpA.State, lowerEventId.State]);

		Assert.Equal(
			[
				"Security/1000",
				$"Application/4625/{Convert.ToHexString(ipA)}",
				$"Application/4625/{Convert.ToHexString(ipB)}",
				"Security/4625",
				"System/4625",
			],
			plan.Steps.Select(s => s.Key.Describe()).ToArray());
	}

	[Fact]
	public void Plan_BudgetIsDistributedInPriorityOrderAndNeverExceeded()
	{
		CodeFixture dense = BuildCode(4625, interiorCount: 900, tailCount: 5);
		CodeFixture middle = BuildCode(4634, interiorCount: 400, tailCount: 5);

		RetentionPlan plan = InformationDensityRetentionPlanner.Plan(
			NowUtc,
			Policy(maxRowsPerPass: 1_000),
			[dense.State, middle.State]);

		Assert.Equal(1_000L, plan.PlannedRows);
		Assert.Equal(900, plan.Steps[0].Rows);
		Assert.Equal(100, plan.Steps[1].Rows);
	}

	[Fact]
	public void Plan_ExhaustedBudget_IsReportedAsBudgetExhausted()
	{
		CodeFixture dense = BuildCode(4625, interiorCount: 900, tailCount: 5);
		CodeFixture alsoDense = BuildCode(4634, interiorCount: 900, tailCount: 5);

		RetentionPlan plan = InformationDensityRetentionPlanner.Plan(
			NowUtc,
			Policy(maxRowsPerPass: 500),
			[dense.State, alsoDense.State]);

		Assert.Equal(500L, plan.PlannedRows);
		Assert.Single(plan.Steps);
		Assert.Contains(plan.Skipped, s => s.Reason == RetentionSkipReason.BudgetExhausted);
	}

	[Fact]
	public void Plan_PlansTheOldestInteriorRows_NotTheNewest()
	{
		CodeFixture fixture = BuildCode(4625, interiorCount: 300, tailCount: 5);

		RetentionPlan plan = InformationDensityRetentionPlanner.Plan(
			NowUtc,
			Policy(maxRowsPerPass: 100),
			[fixture.State]);

		RetentionPlanStep step = Assert.Single(plan.Steps);
		Assert.Equal(100, step.Rows);
		Assert.Equal(fixture.Interior[0].TimeUtc, step.WindowStartUtc);
		Assert.Equal(fixture.Interior[99].TimeUtc, step.WindowEndUtc);
	}

	[Fact]
	public void Plan_StepCarriesBothProtectionBoundariesAndTheKeySpan()
	{
		CodeFixture fixture = BuildCode(4625, interiorCount: 100, tailCount: 5, firstId: 1_000);

		RetentionPlan plan = InformationDensityRetentionPlanner.Plan(
			NowUtc,
			Policy(maxRowsPerPass: 10_000),
			[fixture.State]);

		RetentionPlanStep step = Assert.Single(plan.Steps);
		Assert.Equal(fixture.Anchor.Id, step.AnchorRowId);
		Assert.Equal(fixture.Anchor.TimeUtc, step.AnchorTimeUtc);
		Assert.Equal(fixture.State.TailBoundary!.Value.Id, step.TailBoundaryRowId);
		Assert.Equal(fixture.State.TailBoundary!.Value.TimeUtc, step.TailBoundaryTimeUtc);
		Assert.Equal(1_000L, step.LowestRowId);
		Assert.Equal(1_105L, step.HighestRowId);
		Assert.Equal(RetentionRuleVersion.Current, plan.RuleVersion);
	}

	[Fact]
	public void Plan_PerIpCode_CarriesTheAddressKey()
	{
		byte[] ip = [0xC0, 0xA8, 0x01, 0x01];
		CodeFixture fixture = BuildCode(4625, interiorCount: 100, tailCount: 5, ip: ip);

		RetentionPlan plan = InformationDensityRetentionPlanner.Plan(
			NowUtc,
			Policy(maxRowsPerPass: 10_000),
			[fixture.State]);

		RetentionPlanStep step = Assert.Single(plan.Steps);
		Assert.Equal(ip, step.Key.IpBinary16);
		Assert.Equal("C0A80101", step.Key.IpHex);
	}

	// ── Determinism and idempotency ──────────────────────────────────────────────

	[Fact]
	public void Plan_IdenticalInputs_ProduceIdenticalPlans()
	{
		byte[] ip = [0x0A, 0x00, 0x00, 0x07];
		List<RetentionCodeState> states =
		[
			BuildCode(4625, 900, 5).State,
			BuildCode(4624, 400, 5, ip: ip).State,
			BuildCode(4634, 400, 5, channel: "System").State,
			BuildCode(4720, 900, 5).State,
			BuildCode(1000, 50, 5).State,
		];
		RetentionPolicyOptions policy = Policy(maxRowsPerPass: 700);

		RetentionPlan first = InformationDensityRetentionPlanner.Plan(NowUtc, policy, states);
		RetentionPlan second = InformationDensityRetentionPlanner.Plan(NowUtc, policy, states);

		Assert.Equal(first.Steps.Count, second.Steps.Count);
		for (int index = 0; index < first.Steps.Count; index++)
		{
			Assert.Equal(first.Steps[index], second.Steps[index]);
		}

		Assert.Equal(
			first.Skipped.Select(s => (s.Key.Describe(), s.Reason)),
			second.Skipped.Select(s => (s.Key.Describe(), s.Reason)));
	}

	[Fact]
	public void Plan_ReplanningAfterApplyingThePlan_DeletesNothingMore()
	{
		CodeFixture fixture = BuildCode(4625, interiorCount: 300, tailCount: 5);
		RetentionPolicyOptions policy = Policy(maxRowsPerPass: 10_000);

		RetentionPlan first = InformationDensityRetentionPlanner.Plan(NowUtc, policy, [fixture.State]);
		Assert.Equal(300L, first.PlannedRows);

		// The state an executor leaves behind: anchor, empty interior, tail.
		RetentionCodeState afterPass = fixture.State with { CandidateRows = [] };
		RetentionPlan second = InformationDensityRetentionPlanner.Plan(NowUtc, policy, [afterPass]);

		Assert.True(second.IsEmpty);
	}

	[Fact]
	public void Plan_UnsortedCandidateRows_AreOrderedOldestFirst()
	{
		CodeFixture fixture = BuildCode(4625, interiorCount: 300, tailCount: 5);
		List<RetentionRow> reversed = [.. fixture.Interior];
		reversed.Reverse();

		RetentionPlan plan = InformationDensityRetentionPlanner.Plan(
			NowUtc,
			Policy(maxRowsPerPass: 100),
			[fixture.State with { CandidateRows = reversed }]);

		RetentionPlanStep step = Assert.Single(plan.Steps);
		Assert.Equal(fixture.Interior[0].TimeUtc, step.WindowStartUtc);
		Assert.Equal(fixture.Interior[99].TimeUtc, step.WindowEndUtc);
	}
}
