// File:    src/RdpAudit.Core/Ipc/Contracts/OperationLogDto.cs
// Module:  RdpAudit.Core.Ipc.Contracts
// Purpose: DTOs returned by QueryOperationLogs: a single operation-log row projected for the Logs
//          tab, and the paged envelope carrying the rows plus paging metadata. Detail fields
//          (DetailsJson, StackTrace) are populated by the server only when DEBUG mode is enabled,
//          so a normal-mode client shows concise rows and a DEBUG client shows full detail.
//          Append-only [Key] indices preserve cross-version IPC compatibility.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using MessagePack;
using RdpAudit.Core.Models;

namespace RdpAudit.Core.Ipc.Contracts;

/// <summary>A single operation-log row projected for the Logs tab.</summary>
[MessagePackObject(keyAsPropertyName: false)]
public sealed class OperationLogDto
{
	[Key(0)]
	public long Id { get; set; }

	[Key(1)]
	public DateTime TimeUtc { get; set; }

	[Key(2)]
	public OperationLogSeverity Severity { get; set; }

	[Key(3)]
	public string Source { get; set; } = string.Empty;

	[Key(4)]
	public string Operation { get; set; } = string.Empty;

	[Key(5)]
	public string Message { get; set; } = string.Empty;

	/// <summary>Structured details (JSON). Populated only when DEBUG mode is enabled.</summary>
	[Key(6)]
	public string? DetailsJson { get; set; }

	[Key(7)]
	public string? ExceptionType { get; set; }

	[Key(8)]
	public string? ExceptionMessage { get; set; }

	/// <summary>Stack trace. Populated only when DEBUG mode is enabled.</summary>
	[Key(9)]
	public string? StackTrace { get; set; }

	[Key(10)]
	public string? CorrelationId { get; set; }

	[Key(11)]
	public long? DurationMs { get; set; }

	[Key(12)]
	public bool IsDebug { get; set; }

	[Key(13)]
	public string? Actor { get; set; }

	/// <summary>Number of consecutive identical rows (same Source + Operation + Message) this row
	/// represents when the query collapsed duplicates. <c>1</c> for an ungrouped or unique row. The Logs
	/// tab appends "(×N)" to the message when this exceeds 1. Append-only ABI field (Key 14).</summary>
	[Key(14)]
	public int OccurrenceCount { get; set; } = 1;
}

/// <summary>Paged envelope returned by <c>QueryOperationLogs</c>.</summary>
[MessagePackObject(keyAsPropertyName: false)]
public sealed class OperationLogPageDto
{
	[Key(0)]
	public IpcResultStatus Status { get; set; } = IpcResultStatus.Success;

	/// <summary>The rows for the requested page (newest first).</summary>
	[Key(1)]
	public List<OperationLogDto> Items { get; set; } = new();

	/// <summary>Total rows matching the filter within the depth window (across all pages).</summary>
	[Key(2)]
	public long TotalMatching { get; set; }

	/// <summary>Zero-based page index that was served.</summary>
	[Key(3)]
	public int Page { get; set; }

	/// <summary>Effective page size used by the server (after clamping).</summary>
	[Key(4)]
	public int PageSize { get; set; }

	/// <summary>Effective depth in days used by the server (after clamping / defaulting).</summary>
	[Key(5)]
	public int DepthDays { get; set; }

	/// <summary>True when the server populated DEBUG-only detail fields on the rows.</summary>
	[Key(6)]
	public bool DebugMode { get; set; }

	/// <summary>UTC timestamp of the query that produced this page.</summary>
	[Key(7)]
	public DateTime QueriedUtc { get; set; }

	/// <summary>Operator-facing message; never carries secret material.</summary>
	[Key(8)]
	public string? Message { get; set; }
}
