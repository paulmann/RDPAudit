/* Project: RDPAudit 2.0 | Author: Mikhail Deynekin | Site: Deynekin.com | Email: Mikhail@Deynekin.com */
// Version: 2.0.0
// File   : RetentionPolicyDto.cs
// Project: RdpAudit.Core (RdpAudit.Core.Ipc.Contracts)
// Purpose: Read contract for the Database tab's Retention editor: the global StorageOptions
//          windows, every per-event-code EventRetention override, and all RetentionPolicyOptions
//          fields reported both as configured and as clamped-effective, plus the supported bounds
//          so a client never has to invent a limit. Values are reported, never interpreted: the
//          Resolve* clamps stay the single source of truth in RetentionPolicyOptions.
// Depends: MessagePack, IpcResultStatus, RetentionAnchorScope
// Extends: Append fields only; [Key] indices are an append-only ABI. Every new clampsable
//          RetentionPolicyOptions field must appear here as Configured + Effective.

using MessagePack;
using RdpAudit.Core.Config;

namespace RdpAudit.Core.Ipc.Contracts;

/// <summary>Supported ranges of the clampsable retention-policy fields.</summary>
[MessagePackObject(keyAsPropertyName: false)]
public sealed class RetentionPolicyBoundsDto
{
	/// <summary><c>TailKeepPerCode</c> lower bound.</summary>
	[Key(0)]
	public int MinTailKeepPerCode { get; set; } = RetentionPolicyOptions.MinTailKeepPerCode;

	/// <summary><c>TailKeepPerCode</c> upper bound.</summary>
	[Key(1)]
	public int MaxTailKeepPerCode { get; set; } = RetentionPolicyOptions.MaxTailKeepPerCode;

	/// <summary><c>CandidateMinRows</c> lower bound.</summary>
	[Key(2)]
	public int MinCandidateMinRows { get; set; } = RetentionPolicyOptions.MinCandidateMinRows;

	/// <summary><c>CandidateMinRows</c> upper bound.</summary>
	[Key(3)]
	public int MaxCandidateMinRows { get; set; } = RetentionPolicyOptions.MaxCandidateMinRows;

	/// <summary><c>MinAgeDays</c> lower bound.</summary>
	[Key(4)]
	public int MinMinAgeDays { get; set; } = RetentionPolicyOptions.MinMinAgeDays;

	/// <summary><c>MinAgeDays</c> upper bound.</summary>
	[Key(5)]
	public int MaxMinAgeDays { get; set; } = RetentionPolicyOptions.MaxMinAgeDays;

	/// <summary><c>MaxRowsPerPass</c> lower bound.</summary>
	[Key(6)]
	public int MinMaxRowsPerPass { get; set; } = RetentionPolicyOptions.MinMaxRowsPerPass;

	/// <summary><c>MaxRowsPerPass</c> upper bound.</summary>
	[Key(7)]
	public int MaxMaxRowsPerPass { get; set; } = RetentionPolicyOptions.MaxMaxRowsPerPass;

	/// <summary><c>MaxWriterLockMs</c> lower bound.</summary>
	[Key(8)]
	public int MinMaxWriterLockMs { get; set; } = RetentionPolicyOptions.MinMaxWriterLockMs;

	/// <summary><c>MaxWriterLockMs</c> upper bound.</summary>
	[Key(9)]
	public int MaxMaxWriterLockMs { get; set; } = RetentionPolicyOptions.MaxMaxWriterLockMs;

	/// <summary><c>DeleteBatchRows</c> lower bound.</summary>
	[Key(10)]
	public int MinDeleteBatchRows { get; set; } = RetentionPolicyOptions.MinDeleteBatchRows;

	/// <summary><c>DeleteBatchRows</c> upper bound.</summary>
	[Key(11)]
	public int MaxDeleteBatchRows { get; set; } = RetentionPolicyOptions.MaxDeleteBatchRows;
}

/// <summary>
/// Every <c>RetentionPolicyOptions</c> field. The <c>Configured*</c> value is what the settings
/// document says; the <c>Effective*</c> value is what the <c>Resolve*</c> clamp actually enforces.
/// They differ only when a hand-edited appsettings.json sits outside the supported range.
/// </summary>
[MessagePackObject(keyAsPropertyName: false)]
public sealed class RetentionPolicyValuesDto
{
	// ── Master switches ─────────────────────────────────────────────────────────

	/// <summary>Master switch for the information-density retention pass.</summary>
	[Key(0)]
	public bool Enabled { get; set; }

	/// <summary>Legal hold: when true no pressure rule runs at all.</summary>
	[Key(1)]
	public bool LegalHold { get; set; }

	// ── Anchor scope and protected classes ──────────────────────────────────────

	/// <summary>Configured anchor granularity.</summary>
	[Key(2)]
	public RetentionAnchorScope AnchorScope { get; set; } = RetentionAnchorScope.PerCode;

	/// <summary>Effective anchor granularity after the defined-enum-member fallback.</summary>
	[Key(3)]
	public RetentionAnchorScope EffectiveAnchorScope { get; set; } = RetentionAnchorScope.PerCode;

	/// <summary>Event codes that are never pressure candidates. An empty array in settings resolves
	/// back to the built-in protected set; <see cref="EffectiveProtectedEventIds"/> carries what is
	/// actually enforced.</summary>
	[Key(4)]
	public List<int> ProtectedEventIds { get; set; } = new();

	/// <summary>Protected event codes as actually enforced (never empty).</summary>
	[Key(5)]
	public List<int> EffectiveProtectedEventIds { get; set; } = new();

	// ── Interior selection ──────────────────────────────────────────────────────

	/// <summary>Configured protected-tail length.</summary>
	[Key(6)]
	public int TailKeepPerCode { get; set; }

	/// <summary>Effective protected-tail length after clamping.</summary>
	[Key(7)]
	public int EffectiveTailKeepPerCode { get; set; }

	/// <summary>Configured eligibility threshold.</summary>
	[Key(8)]
	public int CandidateMinRows { get; set; }

	/// <summary>Effective eligibility threshold after clamping.</summary>
	[Key(9)]
	public int EffectiveCandidateMinRows { get; set; }

	/// <summary>Configured age floor in days.</summary>
	[Key(10)]
	public int MinAgeDays { get; set; }

	/// <summary>Effective age floor in days after clamping.</summary>
	[Key(11)]
	public int EffectiveMinAgeDays { get; set; }

	/// <summary>Configured per-pass row budget.</summary>
	[Key(12)]
	public int MaxRowsPerPass { get; set; }

	/// <summary>Effective per-pass row budget after clamping.</summary>
	[Key(13)]
	public int EffectiveMaxRowsPerPass { get; set; }

	/// <summary>Configured writer-lock budget in milliseconds.</summary>
	[Key(14)]
	public int MaxWriterLockMs { get; set; }

	/// <summary>Effective writer-lock budget in milliseconds after clamping.</summary>
	[Key(15)]
	public int EffectiveMaxWriterLockMs { get; set; }

	/// <summary>Configured rows per delete statement.</summary>
	[Key(16)]
	public int DeleteBatchRows { get; set; }

	/// <summary>Effective rows per delete statement after clamping.</summary>
	[Key(17)]
	public int EffectiveDeleteBatchRows { get; set; }

	// ── Pressure triggers (0 = disabled) ───────────────────────────────────────

	/// <summary>Configured database-file ceiling in bytes.</summary>
	[Key(18)]
	public long MaxDatabaseBytes { get; set; }

	/// <summary>Effective database-file ceiling in bytes (never negative).</summary>
	[Key(19)]
	public long EffectiveMaxDatabaseBytes { get; set; }

	/// <summary>Configured <c>RawEvents</c> row ceiling.</summary>
	[Key(20)]
	public long MaxRawEventRows { get; set; }

	/// <summary>Effective <c>RawEvents</c> row ceiling (never negative).</summary>
	[Key(21)]
	public long EffectiveMaxRawEventRows { get; set; }

	/// <summary>Configured free-disk floor in bytes.</summary>
	[Key(22)]
	public long MinFreeDiskBytes { get; set; }

	/// <summary>Effective free-disk floor in bytes (never negative).</summary>
	[Key(23)]
	public long EffectiveMinFreeDiskBytes { get; set; }

	// ── Derived state ───────────────────────────────────────────────────────────

	/// <summary>True when at least one pressure ceiling is positive.</summary>
	[Key(24)]
	public bool HasAnyPressureTrigger { get; set; }

	/// <summary>True when <see cref="Enabled"/> is true and <see cref="LegalHold"/> is false, i.e.
	/// a pass may delete rows.</summary>
	[Key(25)]
	public bool PressureDeletionAllowed { get; set; }

	/// <summary>Supported clamp ranges for the fields above.</summary>
	[Key(26)]
	public RetentionPolicyBoundsDto Bounds { get; set; } = new();
}

/// <summary>The global <c>StorageOptions</c> retention windows, in days.</summary>
[MessagePackObject(keyAsPropertyName: false)]
public sealed class RetentionWindowsDto
{
	/// <summary>Default retention for <c>RawEvents</c> details when no per-event override applies.</summary>
	[Key(0)]
	public int EventRetentionDays { get; set; }

	/// <summary>Retention for alerts.</summary>
	[Key(1)]
	public int AlertRetentionDays { get; set; }

	/// <summary>Retention for abuse reports.</summary>
	[Key(2)]
	public int AbuseReportRetentionDays { get; set; }

	/// <summary>Retention for expired / removed active blocks.</summary>
	[Key(3)]
	public int ActiveBlockRetentionDays { get; set; }

	/// <summary>Retention for stale attack statistics.</summary>
	[Key(4)]
	public int AttackStatRetentionDays { get; set; }

	/// <summary>Retention for session/IP correlations.</summary>
	[Key(5)]
	public int SessionIpCorrelationRetentionDays { get; set; }

	/// <summary>Retention for RDP connection facts.</summary>
	[Key(6)]
	public int RdpConnectionFactRetentionDays { get; set; }

	/// <summary>Retention for operation logs.</summary>
	[Key(7)]
	public int LogRetentionDays { get; set; }
}

/// <summary>One per-event-code retention override as persisted in <c>EventRetention</c>, enriched
/// with the catalog metadata the editor needs.</summary>
[MessagePackObject(keyAsPropertyName: false)]
public sealed class EventRetentionWindowDto
{
	/// <summary>Windows event identifier this override applies to.</summary>
	[Key(0)]
	public int EventId { get; set; }

	/// <summary>Channel from the event catalog; empty when the id is not catalogued.</summary>
	[Key(1)]
	public string Channel { get; set; } = string.Empty;

	/// <summary>Catalog description; empty when the id is not catalogued.</summary>
	[Key(2)]
	public string DisplayName { get; set; } = string.Empty;

	/// <summary>Override window in days; zero means retain the code's rows forever.</summary>
	[Key(3)]
	public int RetentionDays { get; set; }

	/// <summary>Catalog default window in days, so the editor can show override vs default;
	/// <c>-1</c> when the id is not catalogued.</summary>
	[Key(4)]
	public int DefaultRetentionDays { get; set; } = -1;

	/// <summary>UTC instant the override was last written; null when the value is not a persisted
	/// override (that is, when the row was reported only as a catalog default).</summary>
	[Key(5)]
	public DateTime? UpdatedUtc { get; set; }
}

/// <summary>Response of <c>GetRetentionPolicy</c>.</summary>
[MessagePackObject(keyAsPropertyName: false)]
public sealed class RetentionPolicyDto
{
	/// <summary><see cref="IpcResultStatus.Unavailable"/> when the settings or the overrides could
	/// not be read at all.</summary>
	[Key(0)]
	public IpcResultStatus Status { get; set; } = IpcResultStatus.Success;

	/// <summary>Effective information-density retention policy.</summary>
	[Key(1)]
	public RetentionPolicyValuesDto Policy { get; set; } = new();

	/// <summary>Global retention windows from <c>StorageOptions</c>.</summary>
	[Key(2)]
	public RetentionWindowsDto GlobalWindows { get; set; } = new();

	/// <summary>Per-event-code overrides currently persisted in <c>EventRetention</c>, ordered by
	/// event id ascending.</summary>
	[Key(3)]
	public List<EventRetentionWindowDto> EventWindows { get; set; } = new();

	/// <summary>Absolute path of the settings document these values come from.</summary>
	[Key(4)]
	public string ConfigPath { get; set; } = string.Empty;

	/// <summary>UTC instant this snapshot describes.</summary>
	[Key(5)]
	public DateTime QueriedUtc { get; set; }

	/// <summary>True when the per-event overrides could not be read and
	/// <see cref="EventWindows"/> is empty for that reason rather than because no override exists.</summary>
	[Key(6)]
	public bool EventWindowsUnavailable { get; set; }

	/// <summary>Operator-facing message; never carries secret material.</summary>
	[Key(7)]
	public string? Message { get; set; }
}
