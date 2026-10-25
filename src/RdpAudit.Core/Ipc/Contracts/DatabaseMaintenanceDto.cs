/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 2.0.0
// File   : DatabaseMaintenanceDto.cs
// Project: RdpAudit.Core (RdpAudit.Core.Ipc.Contracts)
// Purpose: Bounded request and structured report for RunDatabaseMaintenance (IPC ordinal 89). The
//          request names exactly one safe action (DatabaseMaintenanceKind - there is deliberately no
//          full-VACUUM member) and the report answers with one step per executed pragma, its outcome
//          and detail, plus a monospace ResultText the Configurator can display verbatim. Read-safe:
//          no action in this family deletes evidence rows, rewrites the database file wholesale or
//          touches the shard tree.
// Depends: MessagePack, IpcResultStatus, DatabaseMaintenanceKind
// Extends: Append fields only; [Key] indices are an append-only ABI.

using MessagePack;

namespace RdpAudit.Core.Ipc.Contracts;

/// <summary>Request payload for <c>RunDatabaseMaintenance</c>. Every field is optional: an absent
/// payload is refused (the operator must name the action), and the page cap only clamps the
/// bounded checks.</summary>
[MessagePackObject(keyAsPropertyName: false)]
public sealed class DatabaseMaintenanceRequest
{
	/// <summary>The single maintenance action to run. <see cref="DatabaseMaintenanceKind.Unknown"/>
	/// and any value outside the defined set are refused with <see cref="IpcResultStatus.InvalidRequest"/>.</summary>
	[Key(0)]
	public DatabaseMaintenanceKind Kind { get; set; }

	/// <summary>Upper bound on the free pages <see cref="DatabaseMaintenanceKind.IncrementalVacuum"/>
	/// may release in one pass. Null or out-of-range values resolve to the server default.</summary>
	[Key(1)]
	public int? IncrementalVacuumPages { get; set; }
}

/// <summary>One executed step of the maintenance report.</summary>
[MessagePackObject(keyAsPropertyName: false)]
public sealed class DatabaseMaintenanceStepDto
{
	/// <summary>Stable step name (for example <c>PRAGMA quick_check</c>).</summary>
	[Key(0)]
	public string Name { get; set; } = string.Empty;

	/// <summary><c>Completed</c>, <c>TimedOut</c> or <c>Failed</c>.</summary>
	[Key(1)]
	public string Outcome { get; set; } = string.Empty;

	/// <summary>What the step reported; the first line a check produced, the counts a checkpoint
	/// returned, or the failure reason.</summary>
	[Key(2)]
	public string Detail { get; set; } = string.Empty;

	/// <summary>Wall-clock duration of the step in milliseconds.</summary>
	[Key(3)]
	public long DurationMs { get; set; }
}

/// <summary>Structured result of one maintenance action.</summary>
[MessagePackObject(keyAsPropertyName: false)]
public sealed class DatabaseMaintenanceReportDto
{
	/// <summary><see cref="IpcResultStatus.Success"/> when the action ran to completion (whether or
	/// not the check found problems - that is what the steps report);
	/// <see cref="IpcResultStatus.InvalidRequest"/> when the kind was refused;
	/// <see cref="IpcResultStatus.Unavailable"/> when the store could not be opened.</summary>
	[Key(0)]
	public IpcResultStatus Status { get; set; } = IpcResultStatus.Success;

	/// <summary>UTC instant the action was executed.</summary>
	[Key(1)]
	public DateTime QueriedUtc { get; set; }

	/// <summary>The action that was requested (echoed verbatim, including refusals).</summary>
	[Key(2)]
	public DatabaseMaintenanceKind Kind { get; set; }

	/// <summary>Name of <see cref="Kind"/>, so a client can render it without sharing the enum table.</summary>
	[Key(3)]
	public string KindName { get; set; } = string.Empty;

	/// <summary>Total wall-clock duration of the action in milliseconds.</summary>
	[Key(4)]
	public long DurationMs { get; set; }

	/// <summary>Executed steps in execution order.</summary>
	[Key(5)]
	public List<DatabaseMaintenanceStepDto> Steps { get; set; } = new();

	/// <summary>Monospace, operator-facing report rendered from the steps; the Configurator shows
	/// this verbatim and never has to re-render the DTO itself.</summary>
	[Key(6)]
	public string ResultText { get; set; } = string.Empty;

	/// <summary>Operator-facing summary or refusal reason; never carries secret material.</summary>
	[Key(7)]
	public string? Message { get; set; }
}
