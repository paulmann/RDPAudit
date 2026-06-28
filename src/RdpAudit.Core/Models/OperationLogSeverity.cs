// File:    src/RdpAudit.Core/Models/OperationLogSeverity.cs
// Module:  RdpAudit.Core.Models
// Purpose: Severity classification for durable operation-log entries (program actions, not security
//          attack events). Ordinals are append-only and persisted as integers, so existing values
//          must never be reused or reordered.
// Extends: System.Enum
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

namespace RdpAudit.Core.Models;

/// <summary>Severity classification for durable operation-log entries.</summary>
public enum OperationLogSeverity
{
	/// <summary>Routine, expected progress; the bulk of normal-mode log volume.</summary>
	Information = 0,

	/// <summary>A recoverable or non-fatal anomaly worth surfacing in normal mode.</summary>
	Warning = 1,

	/// <summary>An operation failed but the service remained usable.</summary>
	Error = 2,

	/// <summary>A fatal or near-fatal condition (e.g. an unhandled crash captured before exit).</summary>
	Critical = 3,
}
