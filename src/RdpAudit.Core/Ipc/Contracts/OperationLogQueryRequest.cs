// File:    src/RdpAudit.Core/Ipc/Contracts/OperationLogQueryRequest.cs
// Module:  RdpAudit.Core.Ipc.Contracts
// Purpose: Request DTO for QueryOperationLogs: bounded, filtered, paged query over the durable
//          operation-log table for the Configurator's Logs tab. All filters are optional; the
//          server clamps DepthDays and PageSize to safe ranges so a client can never ask the
//          service to scan or serialize the whole table.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using MessagePack;
using RdpAudit.Core.Models;

namespace RdpAudit.Core.Ipc.Contracts;

/// <summary>Request DTO for <c>QueryOperationLogs</c> (bounded, filtered, paged).</summary>
[MessagePackObject(keyAsPropertyName: false)]
public sealed class OperationLogQueryRequest
{
	/// <summary>How many days back to include. <c>0</c> or negative means "use the configured
	/// Logs.ViewDepthDays default". The server clamps to the supported range.</summary>
	[Key(0)]
	public int DepthDays { get; set; }

	/// <summary>Minimum severity to include (inclusive). <c>null</c> means all severities.</summary>
	[Key(1)]
	public OperationLogSeverity? MinSeverity { get; set; }

	/// <summary>Optional exact source filter (case-insensitive).</summary>
	[Key(2)]
	public string? Source { get; set; }

	/// <summary>Optional substring match against Operation / Message / Source (case-insensitive).</summary>
	[Key(3)]
	public string? SearchText { get; set; }

	/// <summary>Zero-based page index.</summary>
	[Key(4)]
	public int Page { get; set; }

	/// <summary>Rows per page. <c>0</c> or negative means "use the configured Logs.DefaultPageSize".
	/// The server clamps to a safe maximum.</summary>
	[Key(5)]
	public int PageSize { get; set; }

	/// <summary>When <c>true</c> (the default view), Debug-classified rows and the high-volume IPC
	/// accept-loop / connection noise are excluded so the operator sees meaningful operations and errors.
	/// When <c>false</c> every row (including IPC Debug) is returned. Append-only ABI field (Key 6).</summary>
	[Key(6)]
	public bool ExcludeDebugNoise { get; set; } = true;

	/// <summary>When <c>true</c>, consecutive rows sharing the same Source + Operation + Message are
	/// collapsed into a single representative row carrying an occurrence count, so a repeated identical
	/// entry does not flood the view. When <c>false</c> every row is returned individually (used by the
	/// DEBUG "expand repeated entries" view). Append-only ABI field (Key 7).</summary>
	[Key(7)]
	public bool GroupDuplicates { get; set; } = true;
}
