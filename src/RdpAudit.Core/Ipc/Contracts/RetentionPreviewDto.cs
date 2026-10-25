/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 2.0.0
// File   : RetentionPreviewDto.cs
// Project: RdpAudit.Core (RdpAudit.Core.Ipc.Contracts)
// Purpose: Dry-run contract for the Database tab's Retention preview. The service produces it
//          from the same trigger enumeration, the same statistics snapshot and the same planner
//          the real pass uses, so the per-code PlannedRows and the step order are exactly what a
//          subsequent real pass deletes on the same state. Read-only: producing this DTO never
//          deletes a row and never writes a ledger entry.
// Depends: MessagePack, IpcResultStatus, EventDeletionTrigger, RetentionSkipReason
// Extends: Append fields only; [Key] indices are an append-only ABI.

using MessagePack;
using RdpAudit.Core.Models;
using RdpAudit.Core.Retention;

namespace RdpAudit.Core.Ipc.Contracts;

/// <summary>One code considered by the preview: what it holds, what the pass would delete and,
/// when it would be left alone, why.</summary>
[MessagePackObject(keyAsPropertyName: false)]
public sealed class RetentionPreviewCodeDto
{
	/// <summary>Windows event identifier of the code (or of the code's event class).</summary>
	[Key(0)]
	public int EventId { get; set; }

	/// <summary>Event channel of the code.</summary>
	[Key(1)]
	public string Channel { get; set; } = string.Empty;

	/// <summary>Uppercase hexadecimal source address of a per-IP code; empty for a host-wide code.</summary>
	[Key(2)]
	public string IpHex { get; set; } = string.Empty;

	/// <summary>True when the code is per source address (<c>AnchorScope = PerCodeAndIp</c>).</summary>
	[Key(3)]
	public bool PerIp { get; set; }

	/// <summary>Total rows the code currently holds, of every age.</summary>
	[Key(4)]
	public long Count { get; set; }

	/// <summary>Eligible interior rows the code holds inside the deletion window, before the
	/// per-pass budget is applied. This is the density the ordering is measured against.</summary>
	[Key(5)]
	public long EligibleInteriorRows { get; set; }

	/// <summary>Rows a real pass would delete for this code under the current policy. Zero for a
	/// code the planner skipped.</summary>
	[Key(6)]
	public int PlannedRows { get; set; }

	/// <summary>Why the code produced no deletion step; null when it produced one.</summary>
	[Key(7)]
	public RetentionSkipReason? SkipReason { get; set; }

	/// <summary>Operator-facing explanation of <see cref="SkipReason"/>, or of the fact that the
	/// code would be compressed.</summary>
	[Key(8)]
	public string Explanation { get; set; } = string.Empty;

	/// <summary>UTC timestamp of the oldest row the code would keep (its anchor). Null when the
	/// code has no rows.</summary>
	[Key(9)]
	public DateTime? OldestRetainedUtc { get; set; }

	/// <summary>UTC timestamp of the oldest row the pass would delete. Null when the code would
	/// lose nothing.</summary>
	[Key(10)]
	public DateTime? OldestDeletedUtc { get; set; }

	/// <summary>UTC timestamp of the newest row the pass would delete. Null when the code would
	/// lose nothing.</summary>
	[Key(11)]
	public DateTime? NewestDeletedUtc { get; set; }
}

/// <summary>One planned deletion step, in the exact order a real pass would execute it.</summary>
[MessagePackObject(keyAsPropertyName: false)]
public sealed class RetentionPreviewStepDto
{
	/// <summary>Zero-based position in the execution order.</summary>
	[Key(0)]
	public int Order { get; set; }

	/// <summary>Windows event identifier of the step's code.</summary>
	[Key(1)]
	public int EventId { get; set; }

	/// <summary>Event channel of the step's code.</summary>
	[Key(2)]
	public string Channel { get; set; } = string.Empty;

	/// <summary>Uppercase hexadecimal source address of a per-IP code; empty for a host-wide code.</summary>
	[Key(3)]
	public string IpHex { get; set; } = string.Empty;

	/// <summary>Rows this step would delete.</summary>
	[Key(4)]
	public int Rows { get; set; }

	/// <summary>Surrogate key of the code's anchor, which the step never covers.</summary>
	[Key(5)]
	public long AnchorRowId { get; set; }

	/// <summary>UTC timestamp of the anchor.</summary>
	[Key(6)]
	public DateTime AnchorTimeUtc { get; set; }

	/// <summary>Surrogate key of the oldest protected tail row, which the step never covers.</summary>
	[Key(7)]
	public long TailBoundaryRowId { get; set; }

	/// <summary>UTC timestamp of the oldest protected tail row.</summary>
	[Key(8)]
	public DateTime TailBoundaryTimeUtc { get; set; }

	/// <summary>Oldest UTC timestamp the step's rows span, inclusive.</summary>
	[Key(9)]
	public DateTime WindowStartUtc { get; set; }

	/// <summary>Newest UTC timestamp the step's rows span, inclusive.</summary>
	[Key(10)]
	public DateTime WindowEndUtc { get; set; }
}

/// <summary>Response of <c>PreviewRetention</c>: the dry run of one retention pass.</summary>
[MessagePackObject(keyAsPropertyName: false)]
public sealed class RetentionPreviewDto
{
	/// <summary><see cref="IpcResultStatus.Unavailable"/> when the store could not be examined.</summary>
	[Key(0)]
	public IpcResultStatus Status { get; set; } = IpcResultStatus.Success;

	/// <summary>True when the information-density retention policy is enabled.</summary>
	[Key(1)]
	public bool PolicyEnabled { get; set; }

	/// <summary>True when a legal hold is in force, which makes every pressure rule inert and the
	/// preview empty whatever the ceilings say.</summary>
	[Key(2)]
	public bool LegalHold { get; set; }

	/// <summary>The first pressure trigger that would fire, in the fixed evaluation order, or
	/// <see cref="EventDeletionTrigger.Unknown"/> when the store is inside every configured ceiling.
	/// Reported even while a legal hold is in force, so the operator can see which ceiling the hold
	/// is currently covering.</summary>
	[Key(3)]
	public EventDeletionTrigger Trigger { get; set; } = EventDeletionTrigger.Unknown;

	/// <summary>True when a real pass would act on the reported trigger: at least one configured
	/// ceiling is breached and no legal hold is in force.</summary>
	[Key(4)]
	public bool TriggerWouldFire { get; set; }

	/// <summary>Rows a real pass would delete on this state. Equals the sum of
	/// <see cref="RetentionPreviewStepDto.Rows"/>.</summary>
	[Key(5)]
	public long WouldDeleteRows { get; set; }

	/// <summary>
	/// Bytes the deletion itself would return to the filesystem allocator, or null when no honest
	/// figure exists. Deliberately null: SQLite deletes release pages to the file's own freelist, so
	/// the file only shrinks after an incremental vacuum or a VACUUM, and the page-granular yield
	/// depends on page occupancy — a number here would be a guess, not a measurement. The exact
	/// figure that <em>is</em> known is <see cref="WouldDeleteRows"/>.
	/// </summary>
	[Key(6)]
	public long? EstimatedReclaimedBytes { get; set; }

	/// <summary>Why <see cref="EstimatedReclaimedBytes"/> is null (or how it was computed).</summary>
	[Key(7)]
	public string ReclaimedBytesNote { get; set; } = string.Empty;

	/// <summary>Version of the retention rule set that produced this preview.</summary>
	[Key(8)]
	public int RuleVersion { get; set; }

	/// <summary>Rows newer than this UTC instant are never candidates. This is the age floor the
	/// preview applied.</summary>
	[Key(9)]
	public DateTime MinAgeCutoffUtc { get; set; }

	/// <summary>Effective protected-tail length used by the preview.</summary>
	[Key(10)]
	public int TailKeepPerCode { get; set; }

	/// <summary>Effective per-pass row budget used by the preview.</summary>
	[Key(11)]
	public int MaxRowsPerPass { get; set; }

	/// <summary>Every code the preview considered, ordered densest first, then by code.</summary>
	[Key(12)]
	public List<RetentionPreviewCodeDto> Codes { get; set; } = new();

	/// <summary>The planned steps in execution order — identical to what a real pass would run.</summary>
	[Key(13)]
	public List<RetentionPreviewStepDto> Steps { get; set; } = new();

	/// <summary>Number of codes the preview reports as left alone. Equals
	/// <see cref="Codes"/>.Count minus <see cref="Steps"/>.Count.</summary>
	[Key(14)]
	public int SkippedCodeCount { get; set; }

	/// <summary>UTC instant this preview describes.</summary>
	[Key(15)]
	public DateTime QueriedUtc { get; set; }

	/// <summary>Operator-facing summary; never carries secret material.</summary>
	[Key(16)]
	public string? Message { get; set; }
}
