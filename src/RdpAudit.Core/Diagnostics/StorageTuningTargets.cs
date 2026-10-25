/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 2.0.2
// File   : StorageTuningTargets.cs
// Project: RdpAudit.Core (RdpAudit.Core.Diagnostics)
// Purpose: The operational goals and safety factors the recommendation rules are written in terms of.
//          Keeping them as data - instead of burying "3x" and "30 seconds" in the rule bodies - is what
//          makes a recommendation reviewable: an operator who disagrees with a goal can see exactly
//          which one produced the number, and a test can exercise the rule at a different goal. Every
//          target that is not a supported bound of the setting itself is stated here with its reason.
// Depends: RdpAudit.Core.Config (supported bounds are NOT restated here; the rules clamp against those)
// Extends: Add a target with a comment naming where the number comes from; never introduce a magic
//          number into a rule that a reader cannot trace back to a product constant or a documented goal.

namespace RdpAudit.Core.Diagnostics;

/// <summary>The goals the tuning rules optimize for.</summary>
public sealed record StorageTuningTargets
{
	/// <summary>The goals this repository is willing to defend without further evidence.</summary>
	public static StorageTuningTargets Default { get; } = new();

	/// <summary>How long one retention pass should take. The retention worker ticks once a minute, so a
	/// pass that is targeted at half a tick finishes with margin and cannot delay the next tick.</summary>
	public int TargetRetentionPassSeconds { get; init; } = 30;

	/// <summary>Multiplier applied to the measured p95 batch hold when sizing the writer-lock budget. The
	/// engine treats "a batch exceeded the budget" as "defer the rest of this pass to the next tick", so
	/// the budget must accommodate a batch that is slower than average - p95 already means one batch in
	/// twenty is slower than it, and this factor is the room for a busier store than the measured one.</summary>
	public double WriterLockHeadroomFactor { get; init; } = 3.0;

	/// <summary>Share of the writer-lock budget one batch should consume in normal operation, so a batch
	/// has room to run slow without exhausting the pass.</summary>
	public double BatchBudgetShare { get; init; } = 0.5;

	/// <summary>Free space that must remain on the volume beyond the artifacts the rules already account
	/// for. One gibibyte covers the write-ahead log plus the transient files a snapshot or a compaction
	/// creates next to the store.</summary>
	public long FreeSpaceHeadroomBytes { get; init; } = 1L << 30;

	/// <summary>Largest share of the volume a recommended free-space floor may claim. A floor above this
	/// is not a tuning recommendation but a statement that the volume is too small for the store, and the
	/// rule declines instead of proposing it.</summary>
	public double MaxFreeSpaceFloorVolumeShare { get; init; } = 0.25;

	/// <summary>Full-integrity duration up to which a weekly schedule is reasonable.</summary>
	public int WeeklyIntegrityMaxSeconds { get; init; } = 60;

	/// <summary>Full-integrity duration up to which a monthly schedule is still reasonable.</summary>
	public int MonthlyIntegrityMaxSeconds { get; init; } = 300;

	/// <summary>Per-step timeout the service applies to a database-maintenance step
	/// (<c>DatabaseMaintenanceService.StepTimeoutMs</c>). A measured full integrity check longer than this
	/// cannot complete through that command at all, which the integrity rule reports.</summary>
	public int MaintenanceStepTimeoutMs { get; init; } = 30_000;

	/// <summary>Rounding step applied to recommended row counts, so a number such as <c>38214</c> is
	/// rendered as <c>38000</c>. Recommendation is not precision.</summary>
	public int RowRoundStep { get; init; } = 1_000;

	/// <summary>Rounding step applied to recommended batch sizes.</summary>
	public int BatchRoundStep { get; init; } = 100;

	/// <summary>Rounding step applied to recommended byte floors (one mebibyte).</summary>
	public long ByteRoundStep { get; init; } = 1L << 20;
}
