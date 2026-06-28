// File:    src/RdpAudit.Core/Util/AttackStatsFilter.cs
// Module:  RdpAudit.Core.Util
// Purpose: Pure, UI-agnostic predicate for the Configurator Attack Statistics tab. Mirrors the
//          server-side AttackStatsRequest filter so the UI can pre-filter cached rows without
//          another IPC round-trip while operators type. Lifted into Core so the rules can be unit
//          tested without a UI host.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using RdpAudit.Core.Ipc.Contracts;

namespace RdpAudit.Core.Util;

/// <summary>Pure predicate for the Attack Statistics grid.</summary>
public sealed class AttackStatsFilter
{
	/// <summary>Free-text IP query. Null / empty / whitespace matches every row.</summary>
	public string? IpQuery { get; init; }

	/// <summary>Inclusive minimum <c>ThreatScore</c> (null disables this clause).</summary>
	public double? MinThreatScore { get; init; }

	/// <summary>When true, only rows with <c>IsBlocked</c> set match.</summary>
	public bool OnlyBlocked { get; init; }

	/// <summary>Inclusive UTC lower bound on <c>LastSeenUtc</c>.</summary>
	public DateTime? SinceUtc { get; init; }

	/// <summary>Inclusive UTC upper bound on <c>LastSeenUtc</c>.</summary>
	public DateTime? UntilUtc { get; init; }

	/// <summary>Returns true when none of the clauses restrict the result set.</summary>
	public bool IsEmpty =>
		string.IsNullOrWhiteSpace(IpQuery)
		&& MinThreatScore is null
		&& !OnlyBlocked
		&& SinceUtc is null
		&& UntilUtc is null;

	/// <summary>Tests an entry against the configured clauses (AND semantics).</summary>
	public bool Matches(AttackStatEntryDto? entry)
	{
		if (entry is null)
		{
			return false;
		}

		if (!string.IsNullOrWhiteSpace(IpQuery))
		{
			string needle = IpQuery.Trim();
			if (string.IsNullOrEmpty(entry.Ip)
				|| !entry.Ip.Contains(needle, StringComparison.OrdinalIgnoreCase))
			{
				return false;
			}
		}

		if (MinThreatScore is double min && entry.ThreatScore < min)
		{
			return false;
		}

		if (OnlyBlocked && !entry.IsBlocked)
		{
			return false;
		}

		if (SinceUtc is DateTime since && entry.LastSeenUtc < since)
		{
			return false;
		}

		if (UntilUtc is DateTime until && entry.LastSeenUtc > until)
		{
			return false;
		}

		return true;
	}
}
