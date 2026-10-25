/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 2.0.0
// File   : RetentionCodeState.cs
// Project: RdpAudit.Core (RdpAudit.Core.Retention)
// Purpose: The bounded, immutable snapshot of one retention code that the planner reasons about. It
//          carries the two protection boundaries (anchor and tail) explicitly so the planner can
//          enforce them without touching the database.
// Depends: RetentionCodeKey
// Extends: Keep this a pure data contract - the planner must stay free of I/O.

namespace RdpAudit.Core.Retention;

/// <summary>One persisted row of a retention code, identified by surrogate key and UTC timestamp.</summary>
public readonly record struct RetentionRow(long Id, DateTime TimeUtc);

/// <summary>
/// Snapshot of one retention code as observed by the caller. <see cref="CandidateRows"/> may be a
/// bounded fetch, but <see cref="Anchor"/>, <see cref="TailBoundary"/> and <see cref="TotalRows"/>
/// must describe the code truthfully: they are the boundaries the planner enforces.
/// </summary>
public sealed record RetentionCodeState
{
	/// <summary>Identity of the code.</summary>
	public required RetentionCodeKey Key { get; init; }

	/// <summary>Total number of rows of this code currently persisted, of every age.</summary>
	public required long TotalRows { get; init; }

	/// <summary>Oldest row of the code (by <c>TimeUtc</c>, tie-break <c>Id</c>). Never deleted.</summary>
	public required RetentionRow Anchor { get; init; }

	/// <summary>
	/// Oldest row of the protected tail. Rows at or newer than this boundary are the tail, and rows
	/// strictly older than it are the interior. Null when the code holds no interior at all (its row
	/// count is at or below the configured tail length).
	/// </summary>
	public required RetentionRow? TailBoundary { get; init; }

	/// <summary>
	/// Number of eligible interior rows the caller counted for this code inside the deletion window,
	/// before any fetch truncation. This is the density <c>d(c)</c> the eligibility threshold and the
	/// priority order are measured against; the planner clamps it to the rows the code can physically
	/// expose between its anchor and its tail. A code whose interior is larger than
	/// <see cref="CandidateRows"/> is still evaluated at its true density.
	/// </summary>
	public required long EligibleInteriorRows { get; init; }

	/// <summary>Smallest surrogate key currently used by the code. Bounds the linked-evidence guard.</summary>
	public required long LowestRowId { get; init; }

	/// <summary>Largest surrogate key currently used by the code. Bounds the linked-evidence guard.</summary>
	public required long HighestRowId { get; init; }

	/// <summary>
	/// Interior rows offered by the caller, ordered or unordered - the planner sorts them. Rows at or
	/// before the anchor, at or after the tail boundary, or newer than the age floor are dropped by
	/// the planner regardless of what is supplied here.
	/// </summary>
	public required IReadOnlyList<RetentionRow> CandidateRows { get; init; }
}
