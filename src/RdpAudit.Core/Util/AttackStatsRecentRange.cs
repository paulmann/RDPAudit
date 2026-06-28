// File:    src/RdpAudit.Core/Util/AttackStatsRecentRange.cs
// Module:  RdpAudit.Core.Util
// Purpose: Pure helper that maps the Stage 6B "recent period" UI dropdown to an absolute
//          AttackStatsRequest.SinceUtc bound. Lives in Core so the mapping (and its bounds) are
//          unit-testable without WinForms and shared with any future automation.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

namespace RdpAudit.Core.Util;

/// <summary>Preset recent-period choices for the Attack Statistics tab toolbar.</summary>
/// <remarks>
/// APPEND-ONLY: ordinals must not be reused so a future settings file can persist the operator's
/// last-used choice without breaking on upgrade.
/// </remarks>
public enum AttackStatsRecentRange
{
	/// <summary>Last hour (rolling).</summary>
	LastHour = 0,

	/// <summary>Last 24 hours (rolling).</summary>
	Last24Hours = 1,

	/// <summary>Last 7 days (rolling) — matches the Stage 6A IPC default window.</summary>
	Last7Days = 2,

	/// <summary>Last 30 days (rolling) — matches the worker's <c>LookBackWindow</c>.</summary>
	Last30Days = 3,

	/// <summary>No lower bound. The server still applies its own clamps.</summary>
	All = 4,
}

/// <summary>Maps an <see cref="AttackStatsRecentRange"/> to an absolute UTC <c>SinceUtc</c> bound.</summary>
public static class AttackStatsRecentRanges
{
	/// <summary>Returns <c>null</c> when the range is <see cref="AttackStatsRecentRange.All"/> (no lower bound), otherwise the inclusive UTC floor.</summary>
	public static DateTime? ToSinceUtc(AttackStatsRecentRange range, DateTime nowUtc) => range switch
	{
		AttackStatsRecentRange.LastHour => nowUtc - TimeSpan.FromHours(1),
		AttackStatsRecentRange.Last24Hours => nowUtc - TimeSpan.FromDays(1),
		AttackStatsRecentRange.Last7Days => nowUtc - TimeSpan.FromDays(7),
		AttackStatsRecentRange.Last30Days => nowUtc - TimeSpan.FromDays(30),
		AttackStatsRecentRange.All => null,
		_ => null,
	};

	/// <summary>Stable display label for the toolbar dropdown.</summary>
	public static string ToDisplayLabel(AttackStatsRecentRange range) => range switch
	{
		AttackStatsRecentRange.LastHour => "Last hour",
		AttackStatsRecentRange.Last24Hours => "Last 24 hours",
		AttackStatsRecentRange.Last7Days => "Last 7 days",
		AttackStatsRecentRange.Last30Days => "Last 30 days",
		AttackStatsRecentRange.All => "All time",
		_ => range.ToString(),
	};
}
