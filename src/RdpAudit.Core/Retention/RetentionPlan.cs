/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 2.0.0
// File   : RetentionPlan.cs
// Project: RdpAudit.Core (RdpAudit.Core.Retention)
// Purpose: The immutable result of one planning pass: the ordered deletion steps an executor may run,
//          the codes that were honestly skipped and why, and the rule version that produced them.
// Depends: RetentionCodeKey
// Extends: Add a new skip reason whenever a new eligibility rule is introduced, so a dry run can
//          always explain itself.

namespace RdpAudit.Core.Retention;

/// <summary>Version of the information-density rule set. Bump it whenever the eligibility or ordering
/// rules change, so a ledger entry written by an older rule stays distinguishable.</summary>
public static class RetentionRuleVersion
{
	/// <summary>Current rule set: anchor + protected tail + interior-only deletion, density-ordered,
/// bounded by an age floor, an eligibility threshold and a per-pass row budget.</summary>
	public const int Current = 1;
}

/// <summary>Why a code did not produce a deletion step.</summary>
public enum RetentionSkipReason
{
	/// <summary>A legal hold is in force; no pressure rule may run at all.</summary>
	LegalHold = 0,

	/// <summary>The code is in <c>ProtectedEventIds</c> and is never a pressure candidate.</summary>
	ProtectedEventCode = 1,

	/// <summary>The code has fewer eligible interior rows than <c>CandidateMinRows</c>.</summary>
	BelowCandidateMinRows = 2,

	/// <summary>The code has no interior rows: everything it holds is anchor, protected tail or fresh.</summary>
	NoInteriorRows = 3,

	/// <summary>The per-pass row budget was already exhausted by denser codes.</summary>
	BudgetExhausted = 4,
}

/// <summary>One honestly skipped code and the reason.</summary>
public sealed record RetentionPlanSkip
{
	/// <summary>Identity of the skipped code.</summary>
	public required RetentionCodeKey Key { get; init; }

	/// <summary>Reason the code produced no deletion step.</summary>
	public required RetentionSkipReason Reason { get; init; }
}

/// <summary>
/// One bounded deletion step. It names the code, the exact number of rows to remove, the window those
/// rows span and the two protection boundaries the executor must re-apply, so the executor can
/// reproduce the planned row set from SQL alone.
/// </summary>
public sealed record RetentionPlanStep
{
	/// <summary>Identity of the affected code.</summary>
	public required RetentionCodeKey Key { get; init; }

	/// <summary>Number of interior rows to delete, oldest first.</summary>
	public required int Rows { get; init; }

	/// <summary>Surrogate key of the code's anchor. Never deleted.</summary>
	public required long AnchorRowId { get; init; }

	/// <summary>UTC timestamp of the code's anchor. Never deleted.</summary>
	public required DateTime AnchorTimeUtc { get; init; }

	/// <summary>Surrogate key of the tail boundary row. Never deleted.</summary>
	public required long TailBoundaryRowId { get; init; }

	/// <summary>UTC timestamp of the tail boundary row. Never deleted.</summary>
	public required DateTime TailBoundaryTimeUtc { get; init; }

	/// <summary>Smallest surrogate key of the code, bounding the linked-evidence guard.</summary>
	public required long LowestRowId { get; init; }

	/// <summary>Largest surrogate key of the code, bounding the linked-evidence guard.</summary>
	public required long HighestRowId { get; init; }

	/// <summary>Oldest UTC timestamp covered by the planned rows, inclusive.</summary>
	public required DateTime WindowStartUtc { get; init; }

	/// <summary>Newest UTC timestamp covered by the planned rows, inclusive.</summary>
	public required DateTime WindowEndUtc { get; init; }
}

/// <summary>Immutable result of one planning pass.</summary>
public sealed record RetentionPlan
{
	/// <summary>Ordered deletion steps: densest code first, oldest interior row first inside a code.</summary>
	public required IReadOnlyList<RetentionPlanStep> Steps { get; init; }

	/// <summary>Codes that were considered and honestly skipped, with the reason.</summary>
	public required IReadOnlyList<RetentionPlanSkip> Skipped { get; init; }

	/// <summary>Version of the rule set that produced this plan.</summary>
	public required int RuleVersion { get; init; }

	/// <summary>Total number of rows the plan asks the executor to delete.</summary>
	public long PlannedRows
	{
		get
		{
			long total = 0;
			foreach (RetentionPlanStep step in Steps)
			{
				total += step.Rows;
			}

			return total;
		}
	}

	/// <summary>True when the plan asks for no deletion at all.</summary>
	public bool IsEmpty => Steps.Count == 0;
}
