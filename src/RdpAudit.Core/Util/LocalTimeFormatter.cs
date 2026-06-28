// File:    src/RdpAudit.Core/Util/LocalTimeFormatter.cs
// Module:  RdpAudit.Core.Util
// Purpose: Single source of truth for converting persisted UTC timestamps into the operator's
//          local time for WinForms display. The database remains UTC internally; every grid /
//          status strip / diagnostic line that surfaces a DateTime to the operator MUST flow
//          through this helper so the visible value matches the host clock the operator is
//          looking at. Raw UTC values can still be emitted in deep diagnostic dumps that are
//          explicitly labelled as such.
// Extends: System.Object
// Author:  Mikhail Deynekin
// Site:    https://Deynekin.com

using System.Globalization;

namespace RdpAudit.Core.Util;

/// <summary>Operator-facing local-time formatting helpers.</summary>
/// <remarks>
/// All public methods accept a UTC-kind <see cref="DateTime"/>. The database, the ingestion
/// pipeline, and IPC payloads always carry UTC; converting at the rendering boundary keeps
/// timezone handling in exactly one place. The header label "Time" — without "(UTC)" — is the
/// expected accompanying column header in any grid that uses these formatters.
/// </remarks>
public static class LocalTimeFormatter
{
	/// <summary>Default invariant grid format. Year-first so the column sorts as plain text.</summary>
	public const string GridFormat = "yyyy-MM-dd HH:mm:ss";

	/// <summary>Format suffixed with the operator's local UTC offset, e.g. "+02:00". Use when the
	/// row is in a diagnostic that may be pasted into a support ticket on a different host.</summary>
	public const string OffsetFormat = "yyyy-MM-dd HH:mm:ss zzz";

	/// <summary>Convert a UTC <see cref="DateTime"/> to the host's local time. Unspecified-kind
	/// inputs are treated as UTC (the DB invariant) before conversion.</summary>
	public static DateTime ToLocal(DateTime utc)
	{
		if (utc.Kind == DateTimeKind.Local)
		{
			return utc;
		}

		DateTime asUtc = utc.Kind == DateTimeKind.Unspecified
			? DateTime.SpecifyKind(utc, DateTimeKind.Utc)
			: utc;
		return asUtc.ToLocalTime();
	}

	/// <summary>Convert and format. Returns <see cref="string.Empty"/> for <see cref="DateTime.MinValue"/>
	/// so empty-fact rows render as a blank cell rather than "0001-01-01 00:00:00".</summary>
	public static string FormatLocal(DateTime utc, string? format = null)
	{
		if (utc == default)
		{
			return string.Empty;
		}

		DateTime local = ToLocal(utc);
		return local.ToString(format ?? GridFormat, CultureInfo.InvariantCulture);
	}

	/// <summary>Nullable form. Returns <paramref name="fallback"/> (default "(never)") when the
	/// input has no value, matching the conventions used by the diagnostics report builder.</summary>
	public static string FormatLocal(DateTime? utc, string fallback = "(never)", string? format = null)
	{
		return utc is { } v ? FormatLocal(v, format) : fallback;
	}

	/// <summary>Diagnostic helper: render both forms ("local | UTC") so deep-diagnostic dumps
	/// can satisfy operators on both sides without ambiguity.</summary>
	public static string FormatBoth(DateTime utc)
	{
		DateTime local = ToLocal(utc);
		return string.Format(
			CultureInfo.InvariantCulture,
			"{0} (local) | {1}Z (UTC)",
			local.ToString(GridFormat, CultureInfo.InvariantCulture),
			utc.Kind == DateTimeKind.Local
				? utc.ToUniversalTime().ToString(GridFormat, CultureInfo.InvariantCulture)
				: utc.ToString(GridFormat, CultureInfo.InvariantCulture));
	}
}
